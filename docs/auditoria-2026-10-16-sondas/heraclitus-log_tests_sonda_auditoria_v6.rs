//! Sondas da auditoria 2026-10-16 (NAO faz parte do repositorio).
//! Um teste "aprovado" aqui significa: comportamento defeituoso observado.

use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::v6::V6Log;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

fn selados(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir.join("segments"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with(".raw.hrkl"))
        .collect();
    v.sort();
    v
}

fn inverter_byte(path: &Path, off: u64) {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut b = [0u8; 1];
    f.seek(SeekFrom::Start(off)).unwrap();
    f.read_exact(&mut b).unwrap();
    b[0] ^= 0x01;
    f.seek(SeekFrom::Start(off)).unwrap();
    f.write_all(&b).unwrap();
    f.sync_all().unwrap();
}

#[test]
fn sonda_bitrot_em_raw_selado_v6_scan_e_read() {
    let dir = tempfile::tempdir().unwrap();
    let log = V6Log::open(dir.path(), 4096, FsyncPolicy::Always).unwrap();
    for i in 0..200 {
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("evento {i} {}", "x".repeat(60)).into_bytes(),
        ))
        .unwrap();
    }
    let head = log.head();
    assert_eq!(log.scan(0, head).unwrap().len() as u64, head);
    let segs = selados(dir.path());
    eprintln!("selados: {}", segs.len());
    assert!(segs.len() >= 3);
    let alvo = segs[segs.len() / 2].clone();
    let len = std::fs::metadata(&alvo).unwrap().len();
    inverter_byte(&alvo, len / 2);

    let r = log.scan(0, head);
    match &r {
        Ok(v) => eprintln!("SCAN Ok com {} de {head} linhas", v.len()),
        Err(e) => eprintln!("SCAN Err: {e}"),
    }
    let mut nones = 0;
    let mut errs = 0;
    for lsn in 0..head {
        match log.read(lsn) {
            Ok(None) => nones += 1,
            Err(_) => errs += 1,
            Ok(Some(_)) => {}
        }
    }
    eprintln!("READ: {nones} Ok(None) e {errs} Err para LSN < head");
    // Defeito: Ok com buraco OU Ok(None) para LSN confirmado.
    let buraco = matches!(&r, Ok(v) if (v.len() as u64) < head);
    assert!(buraco || nones > 0, "nao reproduziu: comportamento correto");
}

fn activo(dir: &Path) -> PathBuf {
    std::fs::read_dir(dir.join("segments"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.to_string_lossy().ends_with(".active.hrkl"))
        .unwrap()
}

/// Bit rot no MEIO da cauda activa (registos fsync'd, Always) e reabertura:
/// o arranque trata o CRC falhado como "cauda rasgada" e trunca tudo o que
/// vem depois — registos confirmados ao cliente.
#[test]
fn sonda_bitrot_no_meio_da_cauda_activa_trunca_confirmados() {
    let dir = tempfile::tempdir().unwrap();
    let head;
    {
        let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        for i in 0..100 {
            log.append(Episode::new(
                "a",
                EventKind::Observation,
                format!("evento {i} {}", "y".repeat(40)).into_bytes(),
            ))
            .unwrap();
        }
        head = log.head();
        // em runtime: corromper e varrer com o log aberto
        let a = activo(dir.path());
        let len = std::fs::metadata(&a).unwrap().len();
        inverter_byte(&a, len / 3);
        let v = log.scan(0, head);
        eprintln!("RUNTIME scan da cauda: {:?}", v.as_ref().map(|v| v.len()).map_err(|e| e.to_string()));
    }
    let r = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always);
    match &r {
        Ok(log) => eprintln!("REABRIU: head {} (antes {head})", log.head()),
        Err(e) => eprintln!("RECUSOU abrir: {e}"),
    }
    let perdeu = matches!(&r, Ok(log) if log.head() < head);
    assert!(perdeu, "nao reproduziu");
}

/// Escrita parcial (SIGKILL a meio de um write grande corta em fronteira de
/// pagina) de um registo cujo payload (conteudo do cliente) contem uma imagem
/// de footer V6 valida exactamente antes do corte: o arranque recusa abrir
/// para sempre ("refusing to truncate a sealed segment").
#[test]
fn sonda_cauda_rasgada_com_imagem_de_footer_no_payload_bloqueia_arranque() {
    use heraclitus_log::v6::FooterV6;
    let dir = tempfile::tempdir().unwrap();
    let footer = FooterV6 {
        record_count: 0,
        min_lsn: 0,
        max_lsn: 0,
        min_hlc: 0,
        max_hlc: 0,
        block_count: 0,
        flags: 0,
        block_directory_offset: 0,
        block_directory_len: 0,
        logical_root: [0u8; 32],
    };
    let imagem = footer.encode();
    {
        let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        log.append(Episode::new("a", EventKind::Observation, b"primeiro".to_vec())).unwrap();
        let mut conteudo = vec![b'x'; 300];
        conteudo.extend_from_slice(&imagem);
        conteudo.extend_from_slice(&vec![b'y'; 5000]);
        log.append(Episode::new("a", EventKind::Observation, conteudo)).unwrap();
    }
    let a = activo(dir.path());
    let bytes = std::fs::read(&a).unwrap();
    let pos = bytes.windows(imagem.len()).position(|w| w == &imagem[..]).expect("imagem no ficheiro");
    // simula o corte do write a meio do 2.o registo, logo a seguir a imagem
    let f = std::fs::OpenOptions::new().write(true).open(&a).unwrap();
    f.set_len((pos + imagem.len()) as u64).unwrap();
    drop(f);
    let r = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always);
    match &r {
        Ok(log) => eprintln!("REABRIU head={}", log.head()),
        Err(e) => eprintln!("ARRANQUE RECUSADO: {e}"),
    }
    assert!(r.is_err(), "nao reproduziu");
}

/// Um RAW selado corrompido trava o packing de TODOS os segmentos seguintes.
#[test]
fn sonda_um_raw_corrompido_trava_a_fila_de_packing() {
    use heraclitus_log::v6::PackingProfile;
    let dir = tempfile::tempdir().unwrap();
    let log = V6Log::open(dir.path(), 4096, FsyncPolicy::Always).unwrap();
    for i in 0..200 {
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("evento {i} {}", "x".repeat(60)).into_bytes(),
        ))
        .unwrap();
    }
    let segs = selados(dir.path());
    let alvo = segs[1].clone();
    let len = std::fs::metadata(&alvo).unwrap().len();
    inverter_byte(&alvo, len / 2);
    for tentativa in 0..2 {
        let r = log.pack_pending(PackingProfile::Balanced);
        eprintln!("pack_pending #{tentativa}: {:?}", r.as_ref().map(|v| v.len()).map_err(|e| e.to_string()));
    }
    let fila = log.manifest().packing_queue();
    eprintln!("fila por empacotar depois de 2 passagens: {} segmentos {:?}", fila.len(), fila);
    assert!(fila.len() > 1, "nao reproduziu");
}
