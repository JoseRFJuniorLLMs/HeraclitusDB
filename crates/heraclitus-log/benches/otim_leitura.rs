//! Sonda de otimização do caminho de LEITURA, sobre um segmento REAL selado.
//!
//! O relatório de otimização precisa de números, não de leitura de código. Cada
//! variante aqui reproduz exatamente o trabalho que o código atual faz, e a
//! seguir a mesma leitura sem o desperdício identificado. A diferença é o
//! ganho disponível, medido no formato e nos dados reais.
//!
//! 1. **`read_at` como está** (`lib.rs:1165`): por CADA leitura pontual abre o
//!    ficheiro, faz seek+read do registo, faz `seek(0)` e RELÊ o cabeçalho de
//!    22 B do segmento só para descobrir o `format_version` — que já está em
//!    `SegmentMeta.version`, no catálogo em memória.
//! 2. **`read_at` sem o re-seek do cabeçalho** — versão do segmento vinda do
//!    catálogo. Isola o custo do seek+read redundante.
//! 3. **`read_at` com handle reutilizado** — sem `File::open` por leitura.
//! 4. **scan como está** (`lib.rs:1236`): `File` cru, dois `read_exact` por
//!    registo (cabeçalho, depois corpo). Sem `BufReader`.
//! 5. **scan com `BufReader`** de 1 MiB.
//! 6. **scan por `mmap`** — o `mmap.rs` existe e está desligado; a sua própria
//!    doc diz que a medição de 2026-08-15 foi contra um leitor com `BufReader`,
//!    não contra o `scan_capped` real (que não tem buffer nenhum).
//!
//! ```bash
//! HERACLITUS_PROBE_SEG=D:/HeraclitusDB/bench-20m/serial/00000000000000000100.hrkl \
//!   cargo bench -p heraclitus-log --bench otim_leitura
//! ```

use heraclitus_log::format::{self, Decoded};
use heraclitus_log::mmap::MappedSegment;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn pct(v: &mut Vec<Duration>, p: f64) -> Duration {
    if v.is_empty() {
        return Duration::ZERO;
    }
    v.sort_unstable();
    v[(((v.len() - 1) as f64) * p).round() as usize]
}

/// Varre um segmento uma vez para recolher (offset, len) de cada registo — a
/// informação que o catálogo do log tem em memória (`LsnEntry.offset`).
fn offsets(path: &std::path::Path) -> (u16, Vec<u64>) {
    let mut f = BufReader::with_capacity(1 << 20, File::open(path).expect("abrir segmento"));
    let mut hdr = [0u8; format::HEADER_LEN];
    f.read_exact(&mut hdr).expect("cabecalho");
    let version = format::SegmentHeader::decode(&hdr).expect("decode header").version;

    let mut offs = Vec::new();
    let mut pos = format::HEADER_LEN as u64;
    let mut rh = [0u8; format::RECORD_HEADER_LEN];
    loop {
        if f.read_exact(&mut rh).is_err() {
            break;
        }
        if rh[..4] == format::FOOTER_MAGIC {
            break;
        }
        let len = u32::from_le_bytes(rh[..4].try_into().unwrap()) as usize;
        let mut corpo = vec![0u8; len];
        if f.read_exact(&mut corpo).is_err() {
            break;
        }
        offs.push(pos);
        pos += (format::RECORD_HEADER_LEN + len) as u64;
    }
    (version, offs)
}

/// Réplica fiel do que `Log::read_at` faz hoje, incluindo o `seek(0)` + releitura
/// do cabeçalho do segmento para descobrir a versão.
fn leitura_atual(path: &std::path::Path, off: u64) -> usize {
    let mut f = File::open(path).expect("open");
    f.seek(SeekFrom::Start(off)).expect("seek");
    let mut rh = [0u8; format::RECORD_HEADER_LEN];
    f.read_exact(&mut rh).expect("read hdr");
    let len = u32::from_le_bytes(rh[..4].try_into().unwrap()) as usize;
    let mut buf = vec![0u8; format::RECORD_HEADER_LEN + len];
    buf[..format::RECORD_HEADER_LEN].copy_from_slice(&rh);
    f.read_exact(&mut buf[format::RECORD_HEADER_LEN..]).expect("read body");
    // O desperdício: volta ao início do ficheiro só para ler 22 bytes.
    let mut sh = [0u8; format::HEADER_LEN];
    f.seek(SeekFrom::Start(0)).expect("seek 0");
    f.read_exact(&mut sh).expect("read seg hdr");
    let version = format::SegmentHeader::decode(&sh).expect("hdr").version;
    match format::decode_record(version, &buf) {
        Decoded::Record(_, _, p, _) => p.len(),
        _ => 0,
    }
}

/// Sem o `seek(0)` + releitura: a versão vem do catálogo (`SegmentMeta.version`).
fn leitura_sem_reler_header(path: &std::path::Path, off: u64, version: u16) -> usize {
    let mut f = File::open(path).expect("open");
    f.seek(SeekFrom::Start(off)).expect("seek");
    let mut rh = [0u8; format::RECORD_HEADER_LEN];
    f.read_exact(&mut rh).expect("read hdr");
    let len = u32::from_le_bytes(rh[..4].try_into().unwrap()) as usize;
    let mut buf = vec![0u8; format::RECORD_HEADER_LEN + len];
    buf[..format::RECORD_HEADER_LEN].copy_from_slice(&rh);
    f.read_exact(&mut buf[format::RECORD_HEADER_LEN..]).expect("read body");
    match format::decode_record(version, &buf) {
        Decoded::Record(_, _, p, _) => p.len(),
        _ => 0,
    }
}

/// Handle já aberto (um cache de descritores por segmento) + versão do catálogo.
fn leitura_handle_quente(f: &mut File, off: u64, version: u16, buf: &mut Vec<u8>) -> usize {
    f.seek(SeekFrom::Start(off)).expect("seek");
    let mut rh = [0u8; format::RECORD_HEADER_LEN];
    f.read_exact(&mut rh).expect("read hdr");
    let len = u32::from_le_bytes(rh[..4].try_into().unwrap()) as usize;
    buf.resize(format::RECORD_HEADER_LEN + len, 0);
    buf[..format::RECORD_HEADER_LEN].copy_from_slice(&rh);
    f.read_exact(&mut buf[format::RECORD_HEADER_LEN..]).expect("read body");
    match format::decode_record(version, buf) {
        Decoded::Record(_, _, p, _) => p.len(),
        _ => 0,
    }
}

fn main() {
    let path: PathBuf = match std::env::var("HERACLITUS_PROBE_SEG") {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            eprintln!("defina HERACLITUS_PROBE_SEG=<caminho de um .hrkl selado>");
            std::process::exit(2);
        }
    };
    let tam = std::fs::metadata(&path).expect("metadata").len();
    let (version, offs) = offsets(&path);
    println!("\n=== Sonda de otimizacao da LEITURA ===\n");
    println!("segmento : {}", path.display());
    println!("tamanho  : {:.1} MB · {} registos · FORMAT v{version}\n", tam as f64 / 1e6, offs.len());

    // ── LEITURA PONTUAL ─────────────────────────────────────────────────────
    let amostras = 20_000usize.min(offs.len());
    let passo = (offs.len() / amostras).max(1);
    let alvos: Vec<u64> = (0..amostras).map(|i| offs[(i * passo) % offs.len()]).collect();

    println!("-- LEITURA PONTUAL · {amostras} registos do MESMO segmento -------");

    let mut l1 = Vec::with_capacity(amostras);
    let t = Instant::now();
    for &o in &alvos {
        let t0 = Instant::now();
        std::hint::black_box(leitura_atual(&path, o));
        l1.push(t0.elapsed());
    }
    let d1 = t.elapsed();

    let mut l2 = Vec::with_capacity(amostras);
    let t = Instant::now();
    for &o in &alvos {
        let t0 = Instant::now();
        std::hint::black_box(leitura_sem_reler_header(&path, o, version));
        l2.push(t0.elapsed());
    }
    let d2 = t.elapsed();

    let mut l3 = Vec::with_capacity(amostras);
    let mut fq = File::open(&path).expect("open quente");
    let mut buf = Vec::with_capacity(4096);
    let t = Instant::now();
    for &o in &alvos {
        let t0 = Instant::now();
        std::hint::black_box(leitura_handle_quente(&mut fq, o, version, &mut buf));
        l3.push(t0.elapsed());
    }
    let d3 = t.elapsed();

    println!(
        "  1. como esta (open + seek + re-le cabecalho) : p50 {:>8.2?} · {:>8.0} leituras/s",
        pct(&mut l1, 0.50),
        amostras as f64 / d1.as_secs_f64()
    );
    println!(
        "  2. sem reler o cabecalho do segmento         : p50 {:>8.2?} · {:>8.0} leituras/s  ({:.2}x)",
        pct(&mut l2, 0.50),
        amostras as f64 / d2.as_secs_f64(),
        d1.as_secs_f64() / d2.as_secs_f64()
    );
    println!(
        "  3. + handle reutilizado (cache de fd)        : p50 {:>8.2?} · {:>8.0} leituras/s  ({:.2}x)",
        pct(&mut l3, 0.50),
        amostras as f64 / d3.as_secs_f64(),
        d1.as_secs_f64() / d3.as_secs_f64()
    );
    println!();

    // ── VARRIMENTO ──────────────────────────────────────────────────────────
    println!("-- VARRIMENTO SEQUENCIAL · segmento inteiro ---------------------");

    // 4. como o `scan_capped` faz: File cru, 2 read_exact por registo.
    let t = Instant::now();
    let mut n4 = 0usize;
    let mut bytes4 = 0usize;
    {
        let mut f = File::open(&path).expect("open");
        f.seek(SeekFrom::Start(format::HEADER_LEN as u64)).expect("seek");
        let mut rh = [0u8; format::RECORD_HEADER_LEN];
        let mut rb = Vec::with_capacity(65536);
        loop {
            if f.read_exact(&mut rh).is_err() || rh[..4] == format::FOOTER_MAGIC {
                break;
            }
            let len = u32::from_le_bytes(rh[..4].try_into().unwrap()) as usize;
            rb.resize(format::RECORD_HEADER_LEN + len, 0);
            rb[..format::RECORD_HEADER_LEN].copy_from_slice(&rh);
            if f.read_exact(&mut rb[format::RECORD_HEADER_LEN..]).is_err() {
                break;
            }
            if let Decoded::Record(_, _, p, _) = format::decode_record(version, &rb) {
                bytes4 += p.len();
                n4 += 1;
            }
        }
    }
    let d4 = t.elapsed();

    // 5. o mesmo trabalho, com BufReader de 1 MiB.
    let t = Instant::now();
    let mut n5 = 0usize;
    let mut bytes5 = 0usize;
    {
        let mut f = BufReader::with_capacity(1 << 20, File::open(&path).expect("open"));
        let mut skip = [0u8; format::HEADER_LEN];
        f.read_exact(&mut skip).expect("hdr");
        let mut rh = [0u8; format::RECORD_HEADER_LEN];
        let mut rb = Vec::with_capacity(65536);
        loop {
            if f.read_exact(&mut rh).is_err() || rh[..4] == format::FOOTER_MAGIC {
                break;
            }
            let len = u32::from_le_bytes(rh[..4].try_into().unwrap()) as usize;
            rb.resize(format::RECORD_HEADER_LEN + len, 0);
            rb[..format::RECORD_HEADER_LEN].copy_from_slice(&rh);
            if f.read_exact(&mut rb[format::RECORD_HEADER_LEN..]).is_err() {
                break;
            }
            if let Decoded::Record(_, _, p, _) = format::decode_record(version, &rb) {
                bytes5 += p.len();
                n5 += 1;
            }
        }
    }
    let d5 = t.elapsed();

    // 6. mmap (zero-copy) — o modulo que existe e esta desligado.
    let t = Instant::now();
    let mut n6 = 0usize;
    let mut bytes6 = 0usize;
    {
        let seg = MappedSegment::open(&path).expect("mmap");
        for (_lsn, _hlc, p) in seg.records() {
            bytes6 += p.len();
            n6 += 1;
        }
    }
    let d6 = t.elapsed();

    let mbps = |bytes: usize, d: Duration| bytes as f64 / 1e6 / d.as_secs_f64();
    println!(
        "  4. como esta (File cru, 2 read_exact/registo) : {n4:>7} reg · {d4:>9.2?} · {:>8.0} reg/s · {:>6.0} MB/s",
        n4 as f64 / d4.as_secs_f64(),
        mbps(bytes4, d4)
    );
    println!(
        "  5. com BufReader de 1 MiB                     : {n5:>7} reg · {d5:>9.2?} · {:>8.0} reg/s · {:>6.0} MB/s  ({:.2}x)",
        n5 as f64 / d5.as_secs_f64(),
        mbps(bytes5, d5),
        d4.as_secs_f64() / d5.as_secs_f64()
    );
    println!(
        "  6. por mmap (zero-copy, hoje desligado)       : {n6:>7} reg · {d6:>9.2?} · {:>8.0} reg/s · {:>6.0} MB/s  ({:.2}x)",
        n6 as f64 / d6.as_secs_f64(),
        mbps(bytes6, d6),
        d4.as_secs_f64() / d6.as_secs_f64()
    );
    println!();
    println!("  Nota: 4/5/6 nao desserializam o Episode (bincode) — isolam o custo");
    println!("  de I/O + CRC, que e o que as opcoes 5 e 6 mudam.\n");
}
