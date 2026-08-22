//! SPEC-0050 §123, §162 — crash-injection do **HRKL v6 RAW**.
//!
//! O que isto acrescenta ao que já existia
//! ---------------------------------------
//!
//! `v6::raw` já tinha um teste unitário de cauda rasgada
//! (`cauda_rasgada_e_truncada_apenas_no_segmento_activo`): trunca o ficheiro à
//! mão, confirma o `torn_at` e o `repair_active_tail`. Isso prova o
//! **mecanismo**.
//!
//! Não prova a **propriedade**, que é outra coisa: *seja qual for o instante em
//! que o processo morre, o segmento recupera e nenhum registo já durável
//! desaparece*. Um kill real cai em sítios que ninguém escolhe — a meio do
//! `write_all` do header do registo, a meio do payload, entre o `write` e o
//! `sync`, durante a escrita do footer. É a diferença entre testar a função de
//! reparação e testar o formato sob falha.
//!
//! O v5 tem essa suite (`crash_injection.rs`) e ela ganhou o seu lugar: durante
//! o trabalho de 2026-08-19 apanhou um bug real, introduzido ao deixar de
//! calcular leaf hashes — o contador do rodapé passou a comparar contra zero e
//! marcava todo segmento selado como corrompido. Nenhum outro teste o viu.
//!
//! Ligar o writer do motor ao v6 sem o equivalente seria trocar um formato
//! testado sob falha por um testado só em condições normais.
//!
//! `CRASH_ITERS_V6=200` para correr a versão longa.

use heraclitus_core::Episode;
use heraclitus_log::v6::canonical::{canonical_record_hash, CanonicalRecordV1};
use heraclitus_log::v6::merkle::MerkleAccumulatorV1;
use heraclitus_log::v6::raw::{
    encode_raw_record, read_footer, repair_active_tail, scan_raw_segment, RawSegmentWriter,
    SegmentInit,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const MAX_BYTES: u64 = 48 * 1024;

fn crash_writer_v6_bin() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // deps/
    p.pop(); // debug/ | release/
    p.push("examples");
    p.push(format!("crash_writer_v6{}", std::env::consts::EXE_SUFFIX));
    p
}

fn segmentos(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().map(|x| x == "hrkl").unwrap_or(false))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Recalcula a `logical_root` a partir dos registos lidos e compara com a do
/// rodapé. É a verificação que interessa: um segmento selado que sobreviva a um
/// kill tem de continuar a provar a sua própria identidade.
fn raiz_logica_bate(path: &Path) -> Option<bool> {
    let footer = read_footer(path).ok()??;
    let scan = scan_raw_segment(path).ok()?;
    let mut acc = MerkleAccumulatorV1::new();
    for r in &scan.records {
        let ep: Episode = serde_json::from_slice(&r.payload).ok()?;
        let h = canonical_record_hash(&CanonicalRecordV1 {
            lsn: r.lsn,
            record_hlc: r.hlc,
            opaque_meta: ep.id.0.to_bytes(),
            episode: &ep,
        });
        acc.push_record_hash(&h);
    }
    Some(acc.finalize() == footer.logical_root && scan.records.len() as u64 == footer.record_count)
}

/// Estado recuperável do diretório: quantos registos duráveis existem, depois
/// de reparar a cauda do segmento activo — que é o que o motor faria no boot.
fn recuperar(dir: &Path) -> u64 {
    let mut total = 0u64;
    for p in segmentos(dir) {
        if read_footer(&p).ok().flatten().is_some() {
            // Selado: NÃO se repara. Confirma-se a prova.
            assert_eq!(
                raiz_logica_bate(&p),
                Some(true),
                "segmento selado {} deixou de provar a sua raiz logica",
                p.display()
            );
            let scan = scan_raw_segment(&p).expect("scan selado");
            total += scan.records.len() as u64;
        } else {
            // Activo: repara a cauda e conta o que sobrou.
            repair_active_tail(&p).unwrap_or_else(|e| {
                panic!("reparacao falhou em {}: {e}", p.display());
            });
            let scan = scan_raw_segment(&p).expect("scan activo");
            assert!(
                scan.torn_at.is_none(),
                "cauda continua rasgada depois de reparar: {}",
                p.display()
            );
            total += scan.records.len() as u64;
        }
    }
    total
}

#[test]
fn sobrevive_a_kills_repetidos_a_meio_do_append() {
    let iters: u64 = std::env::var("CRASH_ITERS_V6")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);

    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "--example",
            "crash_writer_v6",
            "-p",
            "heraclitus-log",
        ])
        .status()
        .expect("cargo build crash_writer_v6");
    assert!(status.success(), "build do harness falhou");

    let dir = tempfile::tempdir().unwrap();
    let mut ultimo = 0u64;

    for i in 0..iters {
        let mut child = Command::new(crash_writer_v6_bin())
            .arg(dir.path())
            .arg(MAX_BYTES.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn crash_writer_v6");

        // Janela variável: apanha o kill em fases diferentes do ciclo
        // write→sync→seal→roll.
        std::thread::sleep(Duration::from_millis(25 + (i * 11) % 90));
        child.kill().expect("kill");
        let _ = child.wait();

        let agora = recuperar(dir.path());
        assert!(
            agora >= ultimo,
            "iteracao {i}: a contagem de registos ENCOLHEU ({ultimo} -> {agora})"
        );
        ultimo = agora;
    }

    assert!(ultimo > 0, "o escritor nunca chegou a gravar nada");
}

/// A recusa que o nome do teste unitário promete mas não exercita.
///
/// `repair_active_tail` só pode truncar o segmento ACTIVO. Num ficheiro já
/// selado, bytes ilegíveis são bit rot — truncar apagaria história e reescreveria
/// a prova sobre o que sobrasse. Tem de falhar alto.
#[test]
fn reparacao_recusa_segmento_selado() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("selado.hrkl");

    let mut w = RawSegmentWriter::create(
        &path,
        SegmentInit {
            segment_id: 1,
            created_hlc: 1,
            first_lsn: 0,
            writer_epoch: 1,
            storage_namespace_id: [1u8; 16],
        },
    )
    .unwrap();
    for i in 0..4u64 {
        w.append(i, i, b"conteudo-estavel", &[i as u8; 32]).unwrap();
    }
    w.seal().unwrap();

    // Corrompe um byte NO MEIO dos registos, antes do footer.
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.seek(SeekFrom::Start(80)).unwrap();
        let mut b = [0u8; 1];
        f.read_exact(&mut b).unwrap();
        f.seek(SeekFrom::Start(80)).unwrap();
        f.write_all(&[b[0] ^ 0xFF]).unwrap();
    }

    let r = repair_active_tail(&path);
    assert!(
        r.is_err(),
        "reparar um segmento SELADO tem de falhar; devolveu {r:?}"
    );
}

/// Bit rot num registo COMPLETO (o CRC falha, o comprimento não) tem de dar
/// `torn_at` nesse registo — e não ser lido como bom.
#[test]
fn bit_rot_num_registo_completo_e_tratado_como_cauda() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rot.hrkl");

    let mut w = RawSegmentWriter::create(
        &path,
        SegmentInit {
            segment_id: 2,
            created_hlc: 1,
            first_lsn: 0,
            writer_epoch: 1,
            storage_namespace_id: [2u8; 16],
        },
    )
    .unwrap();
    for i in 0..3u64 {
        w.append(i, i, b"payload-de-teste", &[i as u8; 32]).unwrap();
    }
    w.sync().unwrap();
    let tamanho_bom = std::fs::metadata(&path).unwrap().len();
    drop(w);

    // Acrescenta um 4º registo íntegro e depois vira um bit do seu payload.
    let rec = encode_raw_record(3, 3, b"payload-de-teste");
    let inicio_do_quarto = tamanho_bom;
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&rec).unwrap();
    }
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let alvo = inicio_do_quarto + 30; // dentro do payload
        f.seek(SeekFrom::Start(alvo)).unwrap();
        let mut b = [0u8; 1];
        f.read_exact(&mut b).unwrap();
        f.seek(SeekFrom::Start(alvo)).unwrap();
        f.write_all(&[b[0] ^ 0x01]).unwrap();
    }

    let scan = scan_raw_segment(&path).unwrap();
    assert_eq!(scan.records.len(), 3, "o registo corrompido nao pode ser lido");
    assert_eq!(
        scan.torn_at,
        Some(inicio_do_quarto),
        "torn_at tem de apontar para o inicio do registo corrompido"
    );
    assert_eq!(repair_active_tail(&path).unwrap(), Some(inicio_do_quarto));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), tamanho_bom);
}

/// Um footer escrito só até meio (kill durante o `seal`) não pode ser aceite
/// como selagem válida — o segmento continua activo e reparável.
#[test]
fn footer_parcial_nao_conta_como_selado() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("meio-footer.hrkl");

    let mut w = RawSegmentWriter::create(
        &path,
        SegmentInit {
            segment_id: 3,
            created_hlc: 1,
            first_lsn: 0,
            writer_epoch: 1,
            storage_namespace_id: [3u8; 16],
        },
    )
    .unwrap();
    for i in 0..3u64 {
        w.append(i, i, b"abc", &[i as u8; 32]).unwrap();
    }
    w.sync().unwrap();
    let tamanho_bom = std::fs::metadata(&path).unwrap().len();
    drop(w);

    // Metade de um footer: o magic está lá, o resto não.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&heraclitus_log::v6::footer::FOOTER_MAGIC).unwrap();
        f.write_all(&[0u8; 20]).unwrap();
    }

    assert!(
        read_footer(&path).unwrap().is_none(),
        "um footer truncado nao pode passar por selagem valida"
    );
    let scan = scan_raw_segment(&path).unwrap();
    assert!(scan.footer.is_none(), "scan nao pode ver footer valido");
    assert_eq!(scan.records.len(), 3);
    assert_eq!(repair_active_tail(&path).unwrap(), Some(tamanho_bom));
}
