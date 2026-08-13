//! Extrator offline (one-shot) de memória do Claude a partir de segmentos
//! `.hrkl` FORMAT v2 (pré-M30: payload = `Episode` em bincode).
//!
//! Uso: extract_memory <dir-ou-ficheiro> [<dir-ou-ficheiro>...] <saida.jsonl>
//!
//! Varre cada segmento sequencialmente (read-only, nunca abre o Log nem
//! escreve nos dados) e despeja em JSONL os eventos de memória:
//! `attrs.generated_by ∈ {claude_mem, claude_transcript}` OU
//! `agent_id == "claude-code"`. Pensado para recuperar a memória antes de
//! limpar uma carga massiva que impede o boot do serviço.

use heraclitus_core::Episode;
use heraclitus_log::format::{self, Decoded, SegmentHeader, HEADER_LEN};
use std::io::Write;

fn collect_segments(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    if path.is_file() {
        out.push(path.to_path_buf());
        return;
    }
    if let Ok(rd) = std::fs::read_dir(path) {
        let mut files: Vec<_> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().map(|x| x == "hrkl").unwrap_or(false))
            .collect();
        files.sort();
        out.extend(files);
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("uso: extract_memory <dir-ou-.hrkl>... <saida.jsonl>");
        std::process::exit(2);
    }
    let out_path = args.last().unwrap();
    let mut segments = Vec::new();
    for a in &args[..args.len() - 1] {
        collect_segments(std::path::Path::new(a), &mut segments);
    }

    let mut out = std::io::BufWriter::new(std::fs::File::create(out_path)?);
    let cfg = bincode::config::standard();
    let (mut total, mut kept, mut undecodable) = (0u64, 0u64, 0u64);
    let n_segs = segments.len();

    for (i, seg) in segments.iter().enumerate() {
        let bytes = match std::fs::read(seg) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("SKIP {}: {e}", seg.display());
                continue;
            }
        };
        if bytes.len() < HEADER_LEN {
            continue;
        }
        let version = match SegmentHeader::decode(&bytes) {
            Ok(h) => h.version,
            Err(_) => {
                eprintln!("SKIP {}: header inválido", seg.display());
                continue;
            }
        };
        let mut off = HEADER_LEN;
        while off < bytes.len() {
            match format::decode_record(version, &bytes[off..]) {
                Decoded::Record(lsn, hlc, payload, consumed) => {
                    total += 1;
                    // v2: payload = Episode; v3: StoragePayload (não esperado aqui).
                    match bincode::serde::decode_from_slice::<Episode, _>(payload, cfg) {
                        Ok((ep, _)) => {
                            let gen = ep
                                .attrs
                                .get("generated_by")
                                .map(|s| s.as_str())
                                .unwrap_or("");
                            if gen == "claude_mem"
                                || gen == "claude_transcript"
                                || ep.agent_id == "claude-code"
                            {
                                kept += 1;
                                let j = serde_json::json!({
                                    "lsn": lsn,
                                    "hlc": hlc,
                                    "id": ep.id.to_string(),
                                    "agent_id": ep.agent_id,
                                    "session_id": ep.session_id,
                                    "ts_hlc": ep.ts_hlc,
                                    "kind": ep.kind,
                                    "content": String::from_utf8_lossy(&ep.content),
                                    "attrs": ep.attrs,
                                    "hyp": ep.embedding.as_ref().map(|e| e.hyp.clone()),
                                    "sph": ep.embedding.as_ref().map(|e| e.sph.clone()),
                                    "euc": ep.embedding.as_ref().map(|e| e.euc.clone()),
                                    "parents": ep.parents.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                                });
                                writeln!(out, "{j}")?;
                            }
                        }
                        Err(_) => undecodable += 1,
                    }
                    off += consumed;
                }
                Decoded::Footer(_) | Decoded::Torn => break,
            }
        }
        eprintln!(
            "[{}/{}] {} — total={} kept={} undec={}",
            i + 1,
            n_segs,
            seg.file_name().unwrap_or_default().to_string_lossy(),
            total,
            kept,
            undecodable
        );
    }
    out.flush()?;
    println!("TOTAL={total} KEPT={kept} UNDECODABLE={undecodable}");
    Ok(())
}
