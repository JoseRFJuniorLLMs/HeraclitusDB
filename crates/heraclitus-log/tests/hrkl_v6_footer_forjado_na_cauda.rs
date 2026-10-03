//! Regressão: os últimos 128 bytes de uma cauda `.active` do v6 são, sem
//! footer, o fim do payload do último evento — conteúdo do cliente. Nem um
//! `"HFTR"` em EOF-128 nem uma imagem completa de footer (o CRC do footer não
//! tem chave) podem fazer o arranque tratar a cauda como selada (auditoria
//! recursiva 2026-10-03, iteração 1).
//!
//! Antes da correcção: com só o magic, `repair_active_tail` recusava a cauda
//! ("refusing to truncate a sealed segment") em TODOS os arranques; com a
//! imagem inteira, o boot renomeava a cauda para `.g0000.raw.hrkl` e o
//! `reconcile_raw` falhava ("final RAW generation has no valid footer"), de
//! novo em todos os arranques.

use heraclitus_core::config::FsyncPolicy;
use heraclitus_core::{Episode, EventKind};
use heraclitus_log::v6::footer::{FooterV6, FOOTER_LEN, FOOTER_MAGIC};
use heraclitus_log::v6::V6Log;
use std::path::{Path, PathBuf};

fn caudas_activas(dir: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    let mut pilha = vec![dir.to_path_buf()];
    while let Some(d) = pilha.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                pilha.push(p);
            } else if p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".active.hrkl"))
            {
                v.push(p);
            }
        }
    }
    v
}

fn imagem_de_footer() -> [u8; FOOTER_LEN] {
    FooterV6 {
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
    }
    .encode()
}

/// Escreve UM evento cujo conteúdo termina com o início de `alvo`, de modo
/// que os últimos `alvo.len()` bytes da cauda sejam `alvo` — contando com os
/// `depois` bytes que o bincode escreve a seguir ao `content` (campos
/// opcionais vazios). Esse número não é fixado
/// aqui: experimenta-se cada desvio até `aceita` confirmar a forma do
/// ficheiro, e o teste falha se nenhum servir (pré-condição, não o defeito).
fn cauda_forjada(alvo: &[u8], aceita: impl Fn(&[u8]) -> bool) -> (tempfile::TempDir, Vec<u8>, u64) {
    for depois in 0..20usize {
        let dir = tempfile::tempdir().unwrap();
        let mut content = vec![b'z'; 400];
        let usado = alvo.len() - depois;
        let inicio = content.len() - usado;
        content[inicio..].copy_from_slice(&alvo[..usado]);
        let lsn = {
            let log = V6Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
            log.append(Episode::new("a", EventKind::Observation, b"antes".to_vec()))
                .unwrap();
            log.append(Episode::new("a", EventKind::Observation, content.clone()))
                .unwrap()
        };
        let caudas = caudas_activas(dir.path());
        assert_eq!(caudas.len(), 1);
        let bytes = std::fs::read(&caudas[0]).unwrap();
        if aceita(&bytes[bytes.len() - FOOTER_LEN..]) {
            return (dir, content, lsn);
        }
    }
    panic!("pré-condição: não consegui pôr a forma pedida nos últimos 128 bytes da cauda");
}

fn reabre_e_le(dir: &Path, content: &[u8], lsn: u64) {
    for volta in 0..2 {
        let log = V6Log::open(dir, 1 << 20, FsyncPolicy::Always)
            .unwrap_or_else(|e| panic!("arranque {volta} recusou uma cauda íntegra: {e}"));
        let (lido, ep) = log.read(lsn).unwrap().expect("evento perdido");
        assert_eq!(lido, lsn);
        assert_eq!(ep.content, content);
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("depois {volta}").into_bytes(),
        ))
        .unwrap();
    }
}

#[test]
fn magic_hftr_em_eof_menos_128_nao_bloqueia_o_arranque() {
    let mut alvo = vec![b'z'; FOOTER_LEN];
    alvo[..4].copy_from_slice(&FOOTER_MAGIC);
    let (dir, content, lsn) = cauda_forjada(&alvo, |fim| fim.starts_with(&FOOTER_MAGIC));
    reabre_e_le(dir.path(), &content, lsn);
}

#[test]
fn imagem_de_footer_valida_no_payload_nao_e_promovida_a_raw() {
    let imagem = imagem_de_footer();
    let (dir, content, lsn) = cauda_forjada(&imagem, |fim| FooterV6::decode(fim).is_ok());
    reabre_e_le(dir.path(), &content, lsn);
    // A cauda continua a ser a activa: nada foi renomeado para RAW.
    assert_eq!(caudas_activas(dir.path()).len(), 1);
}
