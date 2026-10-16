//! A regra única de **cauda rasgada**, partilhada pelo HRKL v6 e pelo legado.
//!
//! Auditoria 2026-10-16, B1 e B5. As duas recuperações de arranque
//! (`v6::raw::repair_active_tail` e o ramo do segmento activo de `Log::open`)
//! cortavam o ficheiro no primeiro registo ilegível sem perguntar porque é que
//! ele era ilegível:
//!
//! * **B1** — um bit trocado a meio da cauda activa (registos confirmados com
//!   `fsync = Always`) era tratado como escrita interrompida: o arranque
//!   apagava todos os registos a seguir e os LSN voltavam a ser atribuídos.
//! * **B5** — no sentido contrário, uma escrita realmente interrompida cujo
//!   payload trazia uma imagem de footer (o CRC do footer não tem chave)
//!   parecia selada e o arranque recusava abrir para sempre.
//!
//! Uma escrita interrompida só pode deixar **um** frame incompleto, o último, e
//! esse frame estende-se para lá do EOF: o `write` foi cortado antes de o
//! acabar. Daí a regra:
//!
//! 1. o frame que começa no rasgo tem de declarar um fim **além do EOF** (ou
//!    não ter sequer cabeçalho completo); um frame que cabe no ficheiro e falha
//!    o CRC foi escrito por inteiro e estragou-se depois;
//! 2. depois do rasgo não pode existir nenhum registo íntegro com o LSN que
//!    viria a seguir (`esperado + k`) — se existir, o comprimento do frame
//!    rasgado é que se estragou e há história confirmada depois dele;
//!
//! Tudo o resto é corrupção: preservar o ficheiro e recusar arrancar, a mesma
//! política dos segmentos não-últimos do legado e do WAL do Raft.
//!
//! Nota sobre o footer: ele **nunca sela** a partir daqui. Só sela um footer
//! que a varredura alcança numa fronteira de registo (isto é, que começa no
//! próprio rasgo), e esse caso já não chega a este módulo — a varredura
//! devolveu-o como footer, ou recusou-o como footer completo malformado.

use heraclitus_core::Lsn;

/// `payload_len u32 | crc u32 | lsn u64 | hlc u64` — o mesmo cabeçalho de
/// registo nos dois formatos.
pub(crate) const CABECALHO_REGISTO: usize = 24;

/// O que distingue os dois formatos para esta regra.
pub(crate) struct Formato<'a> {
    pub footer_magic: [u8; 4],
    pub footer_len: usize,
    /// `Some(lsn)` se `buf` começa por um registo completo cujo CRC confere.
    pub registo_integro: &'a dyn Fn(&[u8]) -> Option<Lsn>,
}

/// Veredicto sobre os bytes que vão do rasgo até ao EOF.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Rasgo {
    /// Escrita interrompida: truncar no rasgo não apaga nada confirmado.
    Cauda,
    /// Corrupção: o motivo, para a mensagem de erro.
    Corrupcao(String),
}

/// Classifica `resto` — os bytes do ficheiro a partir do offset onde a
/// varredura parou — sabendo que o registo nesse offset devia ter o LSN
/// `esperado`.
pub(crate) fn classificar(resto: &[u8], esperado: Lsn, fmt: &Formato<'_>) -> Rasgo {
    let alem_do_eof = if resto.starts_with(&fmt.footer_magic) {
        resto.len() < fmt.footer_len
    } else if resto.len() < CABECALHO_REGISTO {
        true
    } else {
        let len = u32::from_le_bytes(resto[..4].try_into().unwrap()) as u64;
        CABECALHO_REGISTO as u64 + len > resto.len() as u64
    };
    if !alem_do_eof {
        return Rasgo::Corrupcao(if resto.starts_with(&fmt.footer_magic) {
            "a complete footer at the reached record boundary is malformed".into()
        } else {
            "the record there fits inside the file but fails its CRC: it was written \
             whole and damaged afterwards (bit rot), not cut short by a crash"
                .into()
        });
    }

    // Ressincronização: um registo íntegro com o LSN de um dos registos que
    // viriam a seguir. `resto.len() / 24` é o máximo de registos que cabem.
    let teto = (resto.len() / CABECALHO_REGISTO) as u64;
    for p in 1..=resto.len().saturating_sub(CABECALHO_REGISTO) {
        let lsn = u64::from_le_bytes(resto[p + 8..p + 16].try_into().unwrap());
        if lsn.checked_sub(esperado).is_none_or(|k| k > teto) {
            continue;
        }
        if (fmt.registo_integro)(&resto[p..]) == Some(lsn) {
            return Rasgo::Corrupcao(format!(
                "an intact record with LSN {lsn} follows {p} bytes after it, so the \
                 damaged frame is mid-file history, not a torn write"
            ));
        }
    }

    Rasgo::Cauda
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Formato de brinquedo: CRC "válido" quando o byte 4 é `0xC0`, footer de
    /// 8 bytes `FFFF` + min (u16) + max (u16).
    fn com_formato<R>(f: impl FnOnce(&Formato<'_>) -> R) -> R {
        let registo = |b: &[u8]| -> Option<Lsn> {
            if b.len() < CABECALHO_REGISTO {
                return None;
            }
            let len = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
            (b.len() >= CABECALHO_REGISTO + len && b[4] == 0xC0)
                .then(|| u64::from_le_bytes(b[8..16].try_into().unwrap()))
        };
        f(&Formato {
            footer_magic: *b"FFFF",
            footer_len: 8,
            registo_integro: &registo,
        })
    }

    fn frame(lsn: Lsn, payload: &[u8], crc_bom: bool) -> Vec<u8> {
        let mut v = (payload.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(&[if crc_bom { 0xC0 } else { 0x00 }, 0, 0, 1]);
        v.extend_from_slice(&lsn.to_le_bytes());
        v.extend_from_slice(&7u64.to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn frame_cortado_sem_nada_depois_e_cauda() {
        com_formato(|fmt| {
            let f = frame(5, &[b'x'; 100], true);
            assert_eq!(classificar(&f[..60], 5, fmt), Rasgo::Cauda);
            assert_eq!(classificar(&f[..10], 5, fmt), Rasgo::Cauda);
            assert_eq!(classificar(b"FFFF\x01", 5, fmt), Rasgo::Cauda); // footer a meio
            assert!(matches!(
                classificar(&[0u8; 300], 5, fmt),
                Rasgo::Corrupcao(_)
            ));
        });
    }

    #[test]
    fn frame_que_cabe_e_corrupcao() {
        com_formato(|fmt| {
            let mut v = frame(5, b"abc", false);
            v.extend(frame(6, b"def", true));
            assert!(matches!(classificar(&v, 5, fmt), Rasgo::Corrupcao(_)));
            // Mesmo sendo o último frame do ficheiro.
            assert!(matches!(
                classificar(&frame(5, b"abc", false), 5, fmt),
                Rasgo::Corrupcao(_)
            ));
        });
    }

    #[test]
    fn comprimento_estragado_com_registos_depois_e_corrupcao() {
        com_formato(|fmt| {
            let mut v = frame(5, b"abc", true);
            v[..4].copy_from_slice(&10_000u32.to_le_bytes());
            v.extend(frame(6, b"def", true));
            v.extend(frame(7, b"ghi", true));
            assert!(matches!(classificar(&v, 5, fmt), Rasgo::Corrupcao(m) if m.contains("LSN 6")));
            // Um registo íntegro com LSN de outra história não conta.
            let mut w = frame(5, b"abc", true);
            w[..4].copy_from_slice(&10_000u32.to_le_bytes());
            w.extend(frame(900, b"def", true));
            assert_eq!(classificar(&w, 5, fmt), Rasgo::Cauda);
        });
    }

    #[test]
    fn footer_dentro_do_frame_rasgado_nao_sela_mesmo_declarando_o_lsn() {
        com_formato(|fmt| {
            let mut v = frame(5, &[b'x'; 40], true);
            v[..4].copy_from_slice(&10_000u32.to_le_bytes());
            let mut que_cobre = v.clone();
            que_cobre.extend_from_slice(b"FFFF\x00\x00\x05\x00");
            assert_eq!(classificar(&que_cobre, 5, fmt), Rasgo::Cauda);
            let mut imagem_vazia = v;
            imagem_vazia.extend_from_slice(b"FFFF\x00\x00\x00\x00");
            assert_eq!(classificar(&imagem_vazia, 5, fmt), Rasgo::Cauda);
        });
    }
}
