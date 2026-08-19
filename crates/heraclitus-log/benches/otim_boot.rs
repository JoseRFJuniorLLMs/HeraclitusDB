//! Sonda: onde se vai o tempo do arranque a frio (`Log::open`) e do `verify()`.
//!
//! Os dois percorrem o MESMO código — `scan_segment_file`
//! (`lib.rs:2218`) — por cada segmento do diretório. Por CADA registo, essa
//! função hoje faz:
//!
//!   1. `vec![0u8; remainder_len]`      — alocação
//!   2. `vec![0u8; header + len]`       — segunda alocação + duas cópias
//!   3. `decode_record`                 — CRC-32C (tabela byte-a-byte, v5)
//!   4. `bincode::decode::<StoragePayload>` — desserializa o Episode INTEIRO
//!      (content, attrs, embedding, parents) **só para ler `opaque_meta`**,
//!      que são os 16 primeiros bytes do payload
//!   5. `record_leaf` (blake3 sobre o registo) — cujo resultado é **descartado**
//!      nos segmentos já selados, onde a raiz vem do rodapé
//!
//! Esta sonda mede o mesmo trabalho, tirando um desperdício de cada vez, e por
//! fim em paralelo (os segmentos são ficheiros independentes; hoje o laço é
//! estritamente serial, `lib.rs:405`).
//!
//! ```bash
//! HERACLITUS_PROBE_DIR=D:/HeraclitusDB/bench-20m/serial \
//!   cargo bench -p heraclitus-log --bench otim_boot
//! ```

use heraclitus_log::format::{self, Decoded};
use heraclitus_log::StoragePayloadV3;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const BINCODE_CFG: bincode::config::Configuration = bincode::config::standard();

#[derive(Clone, Copy, PartialEq)]
enum Modo {
    /// Réplica fiel do `scan_segment_file` de hoje.
    Atual,
    /// Sem a desserialização completa: `opaque_meta` são os 16 primeiros bytes.
    SemBincode,
    /// Idem, e sem o blake3 nos segmentos SELADOS (a raiz já está no rodapé).
    SemBlake3EmSelados,
}

struct Resultado {
    registos: u64,
    bytes: u64,
    selado: bool,
}

/// Varre um segmento com o trabalho que o `modo` manda fazer. Devolve o mesmo
/// que o scan real recolhe (contagem, offsets implícitos), para o compilador
/// não poder eliminar nada.
fn varrer(path: &Path, modo: Modo) -> Resultado {
    let file = File::open(path).expect("abrir");
    let file_len = file.metadata().expect("metadata").len();
    let mut reader = BufReader::with_capacity(256 * 1024, file);

    let mut hdr = [0u8; format::HEADER_LEN];
    if reader.read_exact(&mut hdr).is_err() {
        return Resultado { registos: 0, bytes: file_len, selado: false };
    }
    let version = format::SegmentHeader::decode(&hdr).expect("header").version;

    let mut registos = 0u64;
    let mut selado = false;
    let mut hashes: Vec<[u8; 32]> = Vec::new();
    let mut locs: Vec<(u64, u64, [u8; 16])> = Vec::new();
    let mut offset = format::HEADER_LEN as u64;
    // O modo otimizado reutiliza UM buffer; o atual aloca dois por registo.
    let mut reutilizado: Vec<u8> = Vec::with_capacity(4096);

    while offset < file_len {
        let mut magic = [0u8; 4];
        if reader.read_exact(&mut magic).is_err() {
            break;
        }
        if magic == format::FOOTER_MAGIC {
            selado = true;
            break;
        }
        let len = u32::from_le_bytes(magic) as usize;
        if len > 512 * 1024 * 1024 || offset + format::RECORD_HEADER_LEN as u64 + len as u64 > file_len
        {
            break;
        }
        let rem = (format::RECORD_HEADER_LEN - 4) + len;

        let record_buf: &[u8] = if modo == Modo::Atual {
            // Exatamente o que o código faz hoje: duas alocações + duas cópias.
            let mut remainder = vec![0u8; rem];
            if reader.read_exact(&mut remainder).is_err() {
                break;
            }
            let mut rb = vec![0u8; format::RECORD_HEADER_LEN + len];
            rb[..4].copy_from_slice(&magic);
            rb[4..].copy_from_slice(&remainder);
            reutilizado = rb;
            &reutilizado
        } else {
            reutilizado.resize(format::RECORD_HEADER_LEN + len, 0);
            reutilizado[..4].copy_from_slice(&magic);
            if reader.read_exact(&mut reutilizado[4..]).is_err() {
                break;
            }
            &reutilizado
        };

        match format::decode_record(version, record_buf) {
            Decoded::Record(lsn, _hlc, payload, consumed) => {
                let opaque: [u8; 16] = match modo {
                    Modo::Atual => {
                        // Desserializa o Episode inteiro para tirar 16 bytes.
                        let (sp, _): (StoragePayloadV3, usize) =
                            bincode::serde::decode_from_slice(payload, BINCODE_CFG)
                                .expect("bincode");
                        sp.opaque_meta
                    }
                    _ => payload[..16].try_into().expect("prefixo de 16 B"),
                };
                let precisa_hash = match modo {
                    Modo::SemBlake3EmSelados => false, // decidido no fim; ver nota
                    _ => true,
                };
                if precisa_hash {
                    hashes.push(format::record_leaf(version, &record_buf[..consumed]));
                }
                locs.push((lsn, offset, opaque));
                offset += consumed as u64;
                registos += 1;
            }
            _ => break,
        }
    }

    std::hint::black_box(&hashes);
    std::hint::black_box(&locs);
    Resultado { registos, bytes: file_len, selado }
}

fn segmentos(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("ler dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "hrkl").unwrap_or(false))
        .collect();
    v.sort();
    v
}

fn correr_serial(segs: &[PathBuf], modo: Modo) -> (Duration, u64, u64) {
    let t = Instant::now();
    let (mut n, mut b) = (0u64, 0u64);
    for s in segs {
        let r = varrer(s, modo);
        n += r.registos;
        b += r.bytes;
        std::hint::black_box(r.selado);
    }
    (t.elapsed(), n, b)
}

fn correr_paralelo(segs: &[PathBuf], modo: Modo, threads: usize) -> (Duration, u64, u64) {
    let t = Instant::now();
    let proximo = std::sync::atomic::AtomicUsize::new(0);
    let total_n = std::sync::atomic::AtomicU64::new(0);
    let total_b = std::sync::atomic::AtomicU64::new(0);
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let i = proximo.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if i >= segs.len() {
                    break;
                }
                let r = varrer(&segs[i], modo);
                total_n.fetch_add(r.registos, std::sync::atomic::Ordering::Relaxed);
                total_b.fetch_add(r.bytes, std::sync::atomic::Ordering::Relaxed);
            });
        }
    });
    (
        t.elapsed(),
        total_n.load(std::sync::atomic::Ordering::Relaxed),
        total_b.load(std::sync::atomic::Ordering::Relaxed),
    )
}

fn main() {
    let dir: PathBuf = match std::env::var("HERACLITUS_PROBE_DIR") {
        Ok(d) => PathBuf::from(d),
        Err(_) => {
            eprintln!("defina HERACLITUS_PROBE_DIR=<diretorio do log>");
            std::process::exit(2);
        }
    };
    let segs = segmentos(&dir);
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);

    println!("\n=== Sonda: custo do arranque a frio / verify() ===\n");
    println!("diretorio : {}", dir.display());
    println!("segmentos : {}\n", segs.len());

    // CORRETUDE ANTES DE VELOCIDADE: a otimização proposta troca a
    // desserialização completa pelos 16 primeiros bytes do payload. Isso só é
    // válido se `opaque_meta` for mesmo o primeiro campo e o bincode o gravar
    // cru. Confirma-se aqui, contra dados reais, antes de reportar ganhos.
    if let Some(primeiro) = segs.first() {
        let mut conferidos = 0usize;
        let f = File::open(primeiro).expect("abrir");
        let flen = f.metadata().expect("meta").len();
        let mut r = BufReader::with_capacity(256 * 1024, f);
        let mut hdr = [0u8; format::HEADER_LEN];
        r.read_exact(&mut hdr).expect("hdr");
        let version = format::SegmentHeader::decode(&hdr).expect("hdr").version;
        let mut offset = format::HEADER_LEN as u64;
        while offset < flen && conferidos < 500 {
            let mut magic = [0u8; 4];
            if r.read_exact(&mut magic).is_err() || magic == format::FOOTER_MAGIC {
                break;
            }
            let len = u32::from_le_bytes(magic) as usize;
            let mut rb = vec![0u8; format::RECORD_HEADER_LEN + len];
            rb[..4].copy_from_slice(&magic);
            if r.read_exact(&mut rb[4..]).is_err() {
                break;
            }
            if let Decoded::Record(_, _, payload, consumed) = format::decode_record(version, &rb) {
                let (sp, _): (StoragePayloadV3, usize) =
                    bincode::serde::decode_from_slice(payload, BINCODE_CFG).expect("bincode");
                let cru: [u8; 16] = payload[..16].try_into().expect("16 B");
                assert_eq!(
                    sp.opaque_meta, cru,
                    "os 16 primeiros bytes do payload NAO sao o opaque_meta — \
                     a otimizacao proposta seria incorreta"
                );
                offset += consumed as u64;
                conferidos += 1;
            } else {
                break;
            }
        }
        println!("corretude: opaque_meta == payload[..16] em {conferidos} registos reais ✓\n");
    }

    let linha = |rotulo: &str, d: Duration, n: u64, b: u64, base: Option<Duration>| {
        let ganho = match base {
            Some(x) => format!("  ({:.2}x)", x.as_secs_f64() / d.as_secs_f64()),
            None => String::new(),
        };
        println!(
            "  {rotulo:<48} {:>8.2?} · {:>9.0} reg/s · {:>6.0} MB/s{ganho}",
            d,
            n as f64 / d.as_secs_f64(),
            b as f64 / 1e6 / d.as_secs_f64()
        );
    };

    let (d0, n0, b0) = correr_serial(&segs, Modo::Atual);
    linha("1. como esta (bincode completo + blake3)", d0, n0, b0, None);

    let (d1, n1, b1) = correr_serial(&segs, Modo::SemBincode);
    linha("2. sem desserializar o Episode (16 B crus)", d1, n1, b1, Some(d0));

    let (d2, n2, b2) = correr_serial(&segs, Modo::SemBlake3EmSelados);
    linha("3. + sem blake3 (raiz ja esta no rodape)", d2, n2, b2, Some(d0));

    let (d3, n3, b3) = correr_paralelo(&segs, Modo::SemBlake3EmSelados, threads);
    linha(
        &format!("4. + em paralelo ({threads} threads)"),
        d3,
        n3,
        b3,
        Some(d0),
    );

    let (d4, n4, b4) = correr_paralelo(&segs, Modo::Atual, threads);
    linha(
        &format!("5. so paralelizar, sem mais nada ({threads} threads)"),
        d4,
        n4,
        b4,
        Some(d0),
    );

    println!();
    println!("  Nota sobre a linha 3: saltar o blake3 so e legitimo em segmentos");
    println!("  SELADOS, cuja raiz Merkle esta no rodape e e re-verificavel por");
    println!("  `verify()` a pedido. O segmento ATIVO continua a precisar dos");
    println!("  leaf hashes para a selagem seguinte. A sonda trata todos como");
    println!("  selados — no log real, 1 em ~{} nao e.", segs.len().max(1));
    println!();
}
