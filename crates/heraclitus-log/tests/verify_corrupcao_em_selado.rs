//! Regressão: `Log::verify` não pode dar `Ok` com um segmento SELADO corrompido
//! depois do arranque (auditoria recursiva 2026-10-03, iteração 1).
//!
//! O servidor abre o log uma vez e fica a correr; o `/verify` chama
//! `verify_durable` → `verify` SEM reabrir. Antes, um registo com CRC violado
//! (ou o magic do rodapé sobrescrito) num selado fazia a re-varredura parar
//! antes do rodapé: `scan.sealed` ficava falso e o segmento saía em silêncio de
//! `sealed` e de `merkle_ok` — `verify` devolvia `Ok` e o servidor respondia
//! `"ok": true, "sem_raiz": 0`.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use heraclitus_core::{Episode, EventKind, FsyncPolicy, HeraclitusError};
use heraclitus_log::format::{FOOTER_LEN, FOOTER_MAGIC};
use heraclitus_log::Log;

fn log_com_selados(dir: &Path) -> Log {
    let log = Log::open(dir, 4096, FsyncPolicy::Always).unwrap();
    for i in 0..120 {
        log.append(Episode::new(
            "a",
            EventKind::Observation,
            format!("evento {i} {}", "x".repeat(60)).into_bytes(),
        ))
        .unwrap();
    }
    assert!(
        log.sealed_segments().len() >= 2,
        "o teste precisa de segmentos selados"
    );
    log.verify_durable()
        .expect("log são tem de verificar antes da corrupção");
    log
}

/// Um selado do meio (nunca o ativo, que é o último).
fn segmento_selado(dir: &Path) -> PathBuf {
    let mut segs: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "hrkl").unwrap_or(false))
        .collect();
    segs.sort();
    assert!(segs.len() >= 3, "esperava vários segmentos");
    segs[segs.len() / 2].clone()
}

/// Altera bytes NO SÍTIO (sem truncar) com o log aberto, como bit rot ou uma
/// adulteração em runtime.
fn sobrescrever(path: &Path, offset: u64, f: impl FnOnce(&mut [u8])) {
    let mut fh = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut buf = [0u8; 4];
    fh.seek(SeekFrom::Start(offset)).unwrap();
    fh.read_exact(&mut buf).unwrap();
    f(&mut buf);
    fh.seek(SeekFrom::Start(offset)).unwrap();
    fh.write_all(&buf).unwrap();
    fh.sync_all().unwrap();
}

fn assert_corrupcao(r: Result<heraclitus_log::VerifyReport, HeraclitusError>) {
    match r {
        Err(HeraclitusError::Corruption { .. }) => {}
        Err(e) => panic!("esperava Corruption, veio outro erro: {e:?}"),
        Ok(rep) => panic!(
            "verify devolveu Ok com um selado corrompido (sealed={}, merkle_ok={})",
            rep.sealed, rep.merkle_ok
        ),
    }
}

#[test]
fn bit_invertido_num_selado_falha_o_verify_em_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let log = log_com_selados(dir.path());
    let alvo = segmento_selado(dir.path());
    let meio = std::fs::metadata(&alvo).unwrap().len() / 2;
    sobrescrever(&alvo, meio, |b| b[0] ^= 0x01);

    assert_corrupcao(log.verify_durable());
}

#[test]
fn magic_do_rodape_sobrescrito_num_selado_falha_o_verify_em_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let log = log_com_selados(dir.path());
    let alvo = segmento_selado(dir.path());
    let len = std::fs::metadata(&alvo).unwrap().len();
    // O rodapé ocupa os últimos FOOTER_LEN bytes e começa pelo magic; destrói-o.
    let off = len - FOOTER_LEN as u64;
    sobrescrever(&alvo, off, |b| {
        assert_eq!(*b, FOOTER_MAGIC, "o selado tem de terminar num rodapé");
        b.copy_from_slice(&[0xFF; 4]);
    });

    assert_corrupcao(log.verify_durable());
}
