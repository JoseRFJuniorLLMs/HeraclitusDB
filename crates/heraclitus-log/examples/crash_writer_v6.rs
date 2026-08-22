//! Harness de processo-filho para a crash-injection do HRKL **v6 RAW**.
//!
//! Equivalente ao `crash_writer.rs` do v5, mas contra
//! [`heraclitus_log::v6::raw::RawSegmentWriter`]: acrescenta registos com
//! `sync()` a cada um até ser morto a frio.
//!
//! Porque é que existe: a SPEC-0050 §123 define a recuperação da cauda rasgada,
//! e há um teste unitário que a exercita truncando o ficheiro à mão. Isso prova
//! o *mecanismo*, não a *propriedade* — que é "seja qual for o instante em que o
//! processo morre, o segmento recupera". A única forma honesta de a testar é
//! matar um processo real a meio de uma escrita real, que é o que este binário
//! existe para permitir.
//!
//! Uso: `crash_writer_v6 <dir> [segmento_max_bytes]`
//!
//! Escreve um segmento de cada vez; ao ultrapassar o tamanho máximo, **sela** e
//! roda para o seguinte. Isso é deliberado: sem selagem, a suite só testaria a
//! recuperação de um ficheiro; com ela, testa também que um segmento já selado
//! sobrevive intacto a um kill que apanhe o segmento SEGUINTE.

use heraclitus_core::{Episode, EventKind};
use heraclitus_log::v6::canonical::{canonical_record_hash, CanonicalRecordV1};
use heraclitus_log::v6::raw::{read_footer, scan_raw_segment, RawSegmentWriter, SegmentInit};
use std::path::{Path, PathBuf};

fn caminho(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("{id:020}.hrkl"))
}

/// Descobre onde retomar: o maior segmento existente e o LSN a seguir ao
/// último registo legível. Um segmento com cauda rasgada é reparado antes de
/// ser continuado — é exatamente o que o motor faria no arranque.
fn retomar(dir: &Path) -> (u64, u64) {
    let mut ids: Vec<u64> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| {
                    e.file_name()
                        .into_string()
                        .ok()?
                        .strip_suffix(".hrkl")?
                        .parse::<u64>()
                        .ok()
                })
                .collect()
        })
        .unwrap_or_default();
    ids.sort_unstable();

    let Some(&ultimo) = ids.last() else {
        return (0, 0);
    };
    let p = caminho(dir, ultimo);

    // Selado? Continua no segmento seguinte, a partir de max_lsn + 1.
    if let Ok(Some(f)) = read_footer(&p) {
        return (ultimo + 1, f.max_lsn + 1);
    }
    // Activo: repara a cauda e continua NESTE segmento.
    let _ = heraclitus_log::v6::raw::repair_active_tail(&p);
    match scan_raw_segment(&p) {
        Ok(s) => {
            let proximo = s.records.last().map(|r| r.lsn + 1).unwrap_or(s.header.first_lsn);
            (ultimo, proximo)
        }
        Err(_) => (ultimo + 1, 0),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().expect("uso: crash_writer_v6 <dir> [max_bytes]"));
    let max_bytes: u64 = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64 * 1024);
    std::fs::create_dir_all(&dir).expect("criar dir");

    let (mut seg_id, mut lsn) = retomar(&dir);

    loop {
        let p = caminho(&dir, seg_id);
        // Um segmento activo pré-existente é continuado abrindo um novo id: o
        // `RawSegmentWriter::create` usa `create_new`, e reabrir para acrescentar
        // não faz parte da sua superfície. Para a suite isso é indiferente — o
        // que interessa é que nenhum registo já selado desapareça.
        let mut id_livre = seg_id;
        while caminho(&dir, id_livre).exists() {
            id_livre += 1;
        }
        seg_id = id_livre;

        let init = SegmentInit {
            segment_id: seg_id,
            created_hlc: lsn,
            first_lsn: lsn,
            writer_epoch: 1,
            storage_namespace_id: [7u8; 16],
        };
        let mut w = match RawSegmentWriter::create(&caminho(&dir, seg_id), init) {
            Ok(w) => w,
            Err(_) => return,
        };

        while w.bytes_written() < max_bytes {
            let ep = Episode::new(
                "crash-agent-v6",
                EventKind::Observation,
                format!("payload-{lsn}-{}", "x".repeat((lsn % 200) as usize)).into_bytes(),
            );
            let opaque = ep.id.0.to_bytes();
            let hash = canonical_record_hash(&CanonicalRecordV1 {
                lsn,
                record_hlc: lsn,
                opaque_meta: opaque,
                episode: &ep,
            });
            // O payload é o mesmo bincode que o v5 grava (Fase 2 da SPEC manda
            // manter compatibilidade de payload nesta etapa).
            let payload = serde_json::to_vec(&ep).expect("payload");
            if w.append(lsn, lsn, &payload, &hash).is_err() {
                return;
            }
            // `sync` por registo: é o que torna a janela de kill interessante —
            // sem ele, quase tudo estaria em buffers do SO e o teste mediria o
            // cache, não o formato.
            if w.sync().is_err() {
                return;
            }
            lsn += 1;
        }

        if w.seal().is_err() {
            return;
        }
        seg_id += 1;
        let _ = p;
    }
}
