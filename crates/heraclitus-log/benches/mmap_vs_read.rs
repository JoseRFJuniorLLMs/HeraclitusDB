//! A/B: varredura de um segmento SELADO — `read_exact` (caminho atual) vs
//! `mmap` zero-copy (`mmap.rs`, CPM-600).
//!
//! Porque é que este benchmark existe antes de qualquer wiring
//! ----------------------------------------------------------
//! O `mmap.rs` está implementado, testado e sem consumidor. A tentação é ligá-lo
//! ao scan e assumir o ganho. A ronda da compressão ensinou o contrário: o
//! codec parecia excelente em teoria, deu **83% em laboratório e 0,3% nos
//! ficheiros reais**. Não foi um fracasso — foi um filtro. O mesmo critério
//! aplica-se aqui.
//!
//! `mmap` **não é magicamente mais rápido**. Numa varredura sequencial pura, o
//! `BufReader` com read-ahead do kernel é muito competitivo; o ganho forte
//! aparece quando o zero-copy e a reutilização do page cache compensam o custo
//! das page faults. Este benchmark mede, em vez de presumir.
//!
//! Isola exatamente o que o mmap muda — a **cópia por registo** e as syscalls —
//! comparando os dois caminhos ao MESMO nível (extração do payload cru), não um
//! contra o decode completo de `Episode`.
//!
//! ```bash
//! cargo bench -p heraclitus-log --bench mmap_vs_read
//! ```
//!
//! Limitação assumida: mede **cache quente**. Esvaziar o page cache de forma
//! fiável exige privilégios/ferramentas específicas do SO; a primeira passagem
//! de cada configuração é feita e descartada de propósito, para que os números
//! comparem o regime quente nos dois lados em vez de comparar um frio com um
//! quente.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use heraclitus_log::format::{self, encode_record, SegmentFooter, SegmentHeader};
use heraclitus_log::mmap::MappedSegment;

/// Escreve um segmento selado com `n` registos de `tamanho` bytes de payload.
fn segmento_selado(dir: &Path, n: u64, tamanho: usize) -> PathBuf {
    let path = dir.join(format!("{:020}.hrkl", 1));
    let payload = vec![0xABu8; tamanho];
    let mut f = File::create(&path).unwrap();
    f.write_all(
        &SegmentHeader {
            version: format::FORMAT_VERSION,
            segment_id: 1,
            created_hlc: 1,
        }
        .encode(),
    )
    .unwrap();
    for lsn in 0..n {
        let rec = encode_record(format::FORMAT_VERSION, lsn, lsn, &payload);
        f.write_all(&rec).unwrap();
    }
    f.write_all(
        &SegmentFooter {
            record_count: n,
            min_lsn: 0,
            max_lsn: n.saturating_sub(1),
            blake3_root: [0u8; 32],
        }
        .encode(),
    )
    .unwrap();
    f.sync_all().unwrap();
    path
}

/// Caminho ATUAL: `BufReader` + `read_exact`, uma cópia do payload por registo.
/// Devolve `(registos, bytes)` — somados para o otimizador não apagar o corpo.
fn varrer_read(path: &Path) -> (u64, u64) {
    let f = File::open(path).unwrap();
    let mut r = BufReader::new(f);
    let mut cabecalho = vec![0u8; format::HEADER_LEN];
    r.read_exact(&mut cabecalho).unwrap();

    let (mut registos, mut bytes) = (0u64, 0u64);
    let mut rh = vec![0u8; format::RECORD_HEADER_LEN];
    loop {
        if r.read_exact(&mut rh).is_err() {
            break;
        }
        // O footer começa pelo seu magic; ao chegar lá, acabou o fluxo de
        // registos. Mesma deteção que o `scan` faz.
        if rh[..4] == format::FOOTER_MAGIC {
            break;
        }
        // `len` nos primeiros 4 bytes, tal como o `scan` real lê (lib.rs).
        let len = u32::from_le_bytes(rh[..4].try_into().unwrap()) as usize;
        let mut rec = rh.clone();
        rec.resize(format::RECORD_HEADER_LEN + len, 0);
        if r.read_exact(&mut rec[format::RECORD_HEADER_LEN..]).is_err() {
            break;
        }
        registos += 1;
        // Mesmo trabalho que o lado mmap faz sobre o payload, para a comparação
        // ser de igual para igual.
        let p = &rec[format::RECORD_HEADER_LEN..];
        bytes += p.iter().fold(0u64, |a, b| a + *b as u64) % 7 + p.len() as u64;
    }
    (registos, bytes)
}

/// Caminho MMAP, **mapeando a cada varredura**. É o custo de quem abre o
/// segmento, lê e fecha.
fn varrer_mmap(path: &Path) -> (u64, u64) {
    let seg = MappedSegment::open(path).unwrap();
    varrer_mapeado(&seg)
}

/// Caminho MMAP com o mapa **já aberto** — o uso realista para um segmento
/// SELADO, que é imutável e pode ficar mapeado entre queries. Separar isto do
/// custo do `open` é a diferença entre medir o mmap e medir o `mmap()`.
fn varrer_mapeado(seg: &MappedSegment) -> (u64, u64) {
    let (mut registos, mut bytes) = (0u64, 0u64);
    for (_lsn, _hlc, payload) in seg.records() {
        registos += 1;
        // TOCAR nos bytes, não só no comprimento: senão as páginas do payload
        // nunca são faltadas e o mmap parece rápido por não fazer o trabalho
        // que o read faz. `fold` impede o otimizador de apagar o acesso.
        bytes += payload.iter().fold(0u64, |a, b| a + *b as u64) % 7 + payload.len() as u64;
    }
    (registos, bytes)
}

fn medir(rotulo: &str, n: u64, tamanho: usize) {
    let dir = tempfile::tempdir().unwrap();
    let path = segmento_selado(dir.path(), n, tamanho);
    let bytes_ficheiro = std::fs::metadata(&path).unwrap().len();

    // Passagem descartada: aquece o page cache dos DOIS lados igualmente.
    let _ = varrer_read(&path);
    let _ = varrer_mmap(&path);

    const REPS: u32 = 5;
    let t0 = Instant::now();
    let mut chk_r = 0u64;
    for _ in 0..REPS {
        chk_r += varrer_read(&path).0;
    }
    let t_read = t0.elapsed() / REPS;

    let t0 = Instant::now();
    let mut chk_m = 0u64;
    for _ in 0..REPS {
        chk_m += varrer_mmap(&path).0;
    }
    let t_mmap = t0.elapsed() / REPS;

    // Mapa reutilizado: o caso realista de um segmento selado.
    let seg = MappedSegment::open(&path).unwrap();
    let _ = varrer_mapeado(&seg);
    let t0 = Instant::now();
    let mut chk_q = 0u64;
    for _ in 0..REPS {
        chk_q += varrer_mapeado(&seg).0;
    }
    let t_quente = t0.elapsed() / REPS;

    assert_eq!(chk_r, chk_m, "os dois caminhos têm de ler os mesmos registos");
    assert_eq!(chk_m, chk_q);
    let mbs = |d: std::time::Duration| bytes_ficheiro as f64 / d.as_secs_f64() / 1e6;

    println!(
        "  {rotulo:<20} {:>7}x{:>6}B | read {:>9.2?} ({:>6.0} MB/s) | mmap+open {:>9.2?} ({:.2}x) \
         | mmap reutilizado {:>9.2?} ({:.2}x)",
        n,
        tamanho,
        t_read,
        mbs(t_read),
        t_mmap,
        t_read.as_secs_f64() / t_mmap.as_secs_f64(),
        t_quente,
        t_read.as_secs_f64() / t_quente.as_secs_f64(),
    );
}

fn main() {
    println!("\nA/B varredura de segmento selado — cache quente, {} repetições\n", 5);
    medir("registos pequenos", 200_000, 64);
    medir("registos medios", 50_000, 1_024);
    medir("registos grandes", 5_000, 16_384);
    medir("segmento pequeno", 1_000, 256);
    println!(
        "\n  ganho > 1.0 = mmap mais rapido. Cache FRIO nao e medido aqui:\n  \
         esvazia-lo de forma fiavel exige privilegios do SO.\n"
    );
}
