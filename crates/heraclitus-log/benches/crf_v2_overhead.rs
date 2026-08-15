//! Custo do cutover para o CRF v2 (`cpm.rs`) no log real.
//!
//! O `cpm.rs` implementa o Canonical Record Format v2 e não tem consumidor. A
//! pergunta antes de qualquer cutover não é "o formato é melhor?" — é
//! **"quanto custa por registo, e o que é que esse custo compra neste modelo de
//! dados?"**.
//!
//! O CRC-32C do CPM-200 **já fez cutover**: está no v5 do `format.rs`. O que
//! falta é só o *layout* do registo.
//!
//! ```text
//! v5 atual : 24 B  [len | crc | lsn | hlc]
//! CRF v2   : 64 B  [crc | record_size | lsn | hlc | header_len | flags
//!                  | var_meta_len | payload_len | event_id[16]
//!                  | knowledge_ver | ontology_ver | confidence_raw | pad]
//! ```
//!
//! ```bash
//! cargo bench -p heraclitus-log --bench crf_v2_overhead
//! ```
//!
//! Aponta `HERACLITUS_DATA_DIR` ao data dir para medir o log **real** em vez de
//! um tamanho médio inventado.

use heraclitus_log::{cpm, format};

fn main() {
    let v5 = format::RECORD_HEADER_LEN;
    let crf = cpm::FIXED_PREFIX_LEN;
    let delta = crf - v5;

    println!("\nCusto do cutover para o CRF v2\n");
    println!("  cabecalho v5 atual : {v5} B");
    println!("  prefixo fixo CRF v2: {crf} B");
    println!("  custo por registo  : +{delta} B\n");

    // Tamanho medio real do registo, se o log estiver acessivel.
    let mut medio: Option<f64> = None;
    if let Ok(data) = std::env::var("HERACLITUS_DATA_DIR") {
        let dir = std::path::Path::new(&data).join("log");
        if let Ok(rd) = std::fs::read_dir(&dir) {
            let (mut bytes, mut n) = (0u64, 0u64);
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|s| s.to_str()) != Some("hrkl") {
                    continue;
                }
                let Ok(seg) = heraclitus_log::mmap::MappedSegment::open(&p) else {
                    continue;
                };
                for (_lsn, _hlc, payload) in seg.records() {
                    bytes += (payload.len() + v5) as u64;
                    n += 1;
                }
            }
            if n > 0 {
                medio = Some(bytes as f64 / n as f64);
                println!("  LOG REAL: {n} registos, media {:.0} B/registo", medio.unwrap());
            }
        }
    }
    let medio = medio.unwrap_or_else(|| {
        println!("  (sem HERACLITUS_DATA_DIR; a assumir 256 B/registo)");
        256.0
    });

    println!("\n  {:>14}  {:>14}  {:>10}", "registos", "custo extra", "inchaco");
    for n in [1_000_000u64, 10_000_000, 136_000_000] {
        let extra = n * delta as u64;
        let pct = delta as f64 / medio * 100.0;
        println!(
            "  {n:>14}  {:>11.2} GB  {pct:>9.1}%",
            extra as f64 / 1e9
        );
    }

    println!();
    println!("  O que os {delta} B compram, NESTE modelo de dados:");
    println!();
    println!("    event_id[16]      hoje vive no payload bincode  -> ganho real");
    println!("    lsn, hlc          JA estao no cabecalho v5      -> ganho zero");
    println!("    knowledge_ver     conceito do Fato Operacional  -> SEM FONTE");
    println!("    ontology_ver      conceito do Fato Operacional  -> SEM FONTE");
    println!("    confidence_raw    conceito do Fato Operacional  -> SEM FONTE");
    println!("    flags, TLV        extensibilidade futura        -> por usar");
    println!();
    println!("  Os campos por que o HeraclitusDB REALMENTE filtra -- agent_id, kind,");
    println!("  attrs -- nao estao no prefixo fixo: continuariam no payload. O ganho");
    println!("  de varrer-sem-descodificar nao se aplica ao que este banco consulta.");
    println!();
}
