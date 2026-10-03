//! Regressão: um "HFTR" escrito pelo cliente no fim da cauda ativa não pode
//! fazer o arranque saltar os leaf hashes (auditoria recursiva 2026-10-03,
//! iteração 1).

use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;
use std::path::{Path, PathBuf};

const FOOTER_LEN: usize = 60;

fn segmentos(dir: &Path) -> Vec<PathBuf> {
    let mut segs: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "hrkl").unwrap_or(false))
        .collect();
    segs.sort();
    segs
}

/// Escreve UM episódio cujo conteúdo põe `b"HFTR"` exactamente nos últimos
/// `FOOTER_LEN` bytes do segmento ativo. O número de bytes que o bincode
/// escreve DEPOIS do `content` (os campos opcionais vazios) não é fixado
/// aqui: experimenta-se cada desvio até o ficheiro ficar com a forma pedida,
/// e o teste falha se nenhum servir (pré-condição, não o defeito).
fn cauda_com_magic_falso() -> tempfile::TempDir {
    for depois in 0..48usize {
        let dir = tempfile::tempdir().unwrap();
        let mut content = vec![b'z'; 200];
        let pos = content.len() + depois - FOOTER_LEN;
        content[pos..pos + 4].copy_from_slice(b"HFTR");
        {
            let log = Log::open(dir.path(), 4096, FsyncPolicy::Always).unwrap();
            log.append(Episode::new("a", EventKind::Observation, content))
                .unwrap();
        }
        let segs = segmentos(dir.path());
        assert_eq!(segs.len(), 1);
        let bytes = std::fs::read(&segs[0]).unwrap();
        if bytes[bytes.len() - FOOTER_LEN..].starts_with(b"HFTR") {
            return dir;
        }
    }
    panic!("pré-condição: não consegui pôr 'HFTR' nos últimos 60 bytes da cauda");
}

/// `tem_rodape_selado` só confirma o magic dos últimos 60 bytes; um conteúdo
/// do cliente com "HFTR" nessa posição fazia o `Log::open` varrer a cauda SEM
/// leaf hashes e adoptá-la com `record_hashes = []`. No roll seguinte o rodapé
/// gravava a contagem e a raiz Merkle só dos registos novos: o `verify()`
/// acusava adulteração e a abertura seguinte recusava arrancar com
/// "Corruption ... Restaure este segmento".
#[test]
fn magic_falso_na_cauda_nao_corrompe_o_rodape_do_roll() {
    let dir = cauda_com_magic_falso();

    // Reabre (a cauda é adoptada) e acrescenta até o segmento rolar.
    {
        let log = Log::open(dir.path(), 4096, FsyncPolicy::Always).unwrap();
        let mut i = 0;
        while log.sealed_segments().is_empty() {
            log.append(Episode::new(
                "a",
                EventKind::Observation,
                format!("depois {i} {}", "y".repeat(60)).into_bytes(),
            ))
            .unwrap();
            i += 1;
            assert!(i < 1000, "o segmento nunca rolou");
        }
        let r = log
            .verify()
            .expect("verify acusou adulteração num segmento íntegro");
        assert_eq!(r.merkle_ok, r.sealed);
    }

    // A abertura seguinte tem de aceitar o segmento selado.
    let log = Log::open(dir.path(), 4096, FsyncPolicy::Always)
        .expect("a base deixou de abrir depois do roll");
    let r = log.verify().unwrap();
    assert_eq!(r.merkle_ok, r.sealed);
    assert!(r.sealed >= 1);
}
