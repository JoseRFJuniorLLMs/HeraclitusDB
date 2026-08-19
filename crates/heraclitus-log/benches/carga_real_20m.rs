//! Carga realista de 20 000 000 de registos — escrita, leitura, integridade.
//!
//! Sucessor de `carga_real_1m.rs` (que já correu a 1M e a 10M). O que este
//! acrescenta, e porquê:
//!
//!  1. **escrita 1 escritor** @ 8 MiB — a curva de referência, comparável às
//!     corridas de 1M e 10M já arquivadas em `docs/md/auditorias/`;
//!  2. **escrita 8 escritores** @ 8 MiB no MESMO volume — a segunda mitigação
//!     da auditoria (lotes do worker até 128) nunca foi medida acima de 200k;
//!  3. leitura pontual, varrimento, leitura sob escrita — como no 1M;
//!  4. **arranque a frio** a 20M — extrapolava-se; agora mede-se;
//!  5. **`verify()` integral** — o custo forense (crc de cada registo + raiz
//!     Merkle de cada segmento selado) nunca foi medido a esta escala. É o
//!     número que decide se a auditoria é praticável em produção;
//!  6. **`resolve_lsn_from_consensus_index`** — a auditoria marcou-o como O(n)
//!     por inspeção e deixou-o por medir (secção 7).
//!
//! A fase do segmento de 256 MiB do bench de 1M NÃO existe aqui: a 10M levou
//! 28 494 s (7,9 h) e a 20M passaria de 30 h. O ponto já está provado.
//!
//! ```bash
//! HERACLITUS_BENCH_N=20000000 HERACLITUS_BENCH_DIR=D:/HeraclitusDB/bench-20m \
//!   cargo bench -p heraclitus-log --bench carga_real_20m
//! ```

use heraclitus_core::{Episode, EventKind, FsyncPolicy, Lsn};
use heraclitus_log::Log;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const SEG_RECOMENDADO: u64 = 8 << 20;

struct Rng(u64);

impl Rng {
    fn proximo(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn ate(&mut self, n: u64) -> u64 {
        self.proximo() % n.max(1)
    }
}

const SERVICOS: [&str; 8] = [
    "api-gateway",
    "auth-svc",
    "billing",
    "nginx-edge",
    "worker-etl",
    "db-proxy",
    "cron",
    "search",
];
const NIVEIS: [&str; 5] = ["INFO", "WARN", "ERROR", "DEBUG", "AUDIT"];
const ROTAS: [&str; 6] = [
    "/v1/consulta",
    "/v1/protocolo",
    "/health",
    "/v1/documento/upload",
    "/login",
    "/v1/relatorio",
];

/// Mesma forma de evento do bench de 1M/10M — trocar o gerador tornava as
/// corridas incomparáveis, que é precisamente o que este bench existe para
/// permitir.
fn evento(rng: &mut Rng, i: u64) -> Episode {
    let svc = SERVICOS[(i % SERVICOS.len() as u64) as usize];
    let nivel = NIVEIS[(rng.ate(100) % NIVEIS.len() as u64) as usize];
    let rota = ROTAS[(rng.ate(100) % ROTAS.len() as u64) as usize];
    let status = [200u32, 200, 200, 201, 304, 400, 404, 500][rng.ate(8) as usize];
    let latencia = rng.ate(2000);
    let extra = (rng.ate(280) + 120) as usize;
    let msg = format!(
        "{nivel} {svc} {rota} status={status} lat={latencia}ms req={:016x} {}",
        rng.proximo(),
        "-".repeat(extra)
    );
    let mut e = Episode::new(svc, EventKind::Custom(nivel.into()), msg.into_bytes());
    e.session_id = format!("sess-{:08x}", i / 1000);
    e.attrs.insert("rota".into(), rota.into());
    e.attrs.insert("status".into(), status.to_string());
    e.attrs.insert("latencia_ms".into(), latencia.to_string());
    e
}

fn pct(v: &mut Vec<Duration>, p: f64) -> Duration {
    if v.is_empty() {
        return Duration::ZERO;
    }
    v.sort_unstable();
    v[(((v.len() - 1) as f64) * p).round() as usize]
}

fn tamanho_em_disco(dir: &std::path::Path) -> (u64, usize) {
    match std::fs::read_dir(dir) {
        Ok(rd) => {
            let v: Vec<u64> = rd
                .flatten()
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .collect();
            (v.iter().sum::<u64>(), v.len())
        }
        Err(_) => (0, 0),
    }
}

fn escrever_serial(log: &Log, n: u64, janela: u64, rotulo: &str) -> f64 {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut debitos = Vec::new();
    let t_total = Instant::now();
    let mut t = Instant::now();
    for i in 0..n {
        log.append(evento(&mut rng, i)).expect("append");
        if (i + 1) % janela == 0 {
            let d = janela as f64 / t.elapsed().as_secs_f64();
            debitos.push(d);
            print!(" {d:.0}");
            let _ = std::io::stdout().flush();
            t = Instant::now();
        }
    }
    println!();
    let total = n as f64 / t_total.elapsed().as_secs_f64();
    if debitos.len() >= 2 {
        println!(
            "    {rotulo}: {total:.0} app/s no total ({:.1?}); 1a janela {:.0} -> ultima {:.0} = {:.1}x",
            t_total.elapsed(),
            debitos[0],
            debitos[debitos.len() - 1],
            debitos[0] / debitos[debitos.len() - 1]
        );
    } else {
        println!(
            "    {rotulo}: {total:.0} app/s no total ({:.1?})",
            t_total.elapsed()
        );
    }
    total
}

/// Escrita com `escritores` threads. O débito é medido por janela GLOBAL (um
/// contador atómico), não por thread: o que interessa é o débito agregado que
/// o worker consegue absorver, e é ele que a curva tem de mostrar.
fn escrever_concorrente(log: &Log, n: u64, janela: u64, escritores: u64, rotulo: &str) -> f64 {
    let feitos = AtomicU64::new(0);
    let debitos;
    let t_total = Instant::now();

    let relatorio = std::thread::scope(|s| {
        let h = s.spawn(|| {
            let mut marca = janela;
            let mut t = Instant::now();
            let mut saida = Vec::new();
            loop {
                let f = feitos.load(Ordering::Relaxed);
                if f >= n {
                    break;
                }
                if f >= marca {
                    let d = janela as f64 / t.elapsed().as_secs_f64();
                    saida.push(d);
                    print!(" {d:.0}");
                    let _ = std::io::stdout().flush();
                    t = Instant::now();
                    marca += janela;
                } else {
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            saida
        });

        for w in 0..escritores {
            let feitos = &feitos;
            s.spawn(move || {
                let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ (w.wrapping_mul(0x1234_5678_9ABC_DEF1)));
                let quota = n / escritores + u64::from(w < n % escritores);
                for i in 0..quota {
                    log.append(evento(&mut rng, i)).expect("append");
                    feitos.fetch_add(1, Ordering::Relaxed);
                }
            });
        }

        h.join().expect("relatorio")
    });
    debitos = relatorio;

    println!();
    let total = n as f64 / t_total.elapsed().as_secs_f64();
    if debitos.len() >= 2 {
        println!(
            "    {rotulo}: {total:.0} app/s no total ({:.1?}); 1a janela {:.0} -> ultima {:.0} = {:.1}x",
            t_total.elapsed(),
            debitos[0],
            debitos[debitos.len() - 1],
            debitos[0] / debitos[debitos.len() - 1]
        );
    } else {
        println!(
            "    {rotulo}: {total:.0} app/s no total ({:.1?})",
            t_total.elapsed()
        );
    }
    total
}

struct Trabalho {
    leitor: bool,
    operacoes: u64,
    latencias: Vec<Duration>,
}

fn main() {
    let n: u64 = std::env::var("HERACLITUS_BENCH_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000_000);
    let janela = (n / 40).clamp(1_000, 500_000).min(n.max(1));

    let raiz: PathBuf = std::env::var("HERACLITUS_BENCH_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("heraclitus-bench-20m"));
    let dir_serial = raiz.join("serial");
    let dir_conc = raiz.join("concorrente");
    for d in [&dir_serial, &dir_conc] {
        let _ = std::fs::remove_dir_all(d);
        std::fs::create_dir_all(d).expect("criar dir do bench");
    }

    println!("\n=== Carga realista: {n} registos, escrita + leitura + integridade ===\n");
    println!("Eventos com forma de log de servidor: 8 servicos, 5 niveis, 6 rotas,");
    println!("mensagem de 120-400 B e 3 atributos por registo (bincode real).");
    println!("Dados em: {}\n", raiz.display());

    // ── 1. ESCRITA · 1 escritor ─────────────────────────────────────────────
    println!("-- 1. ESCRITA · 1 escritor · segmento 8 MiB ---------------------");
    print!("    debito por janela de {janela}:");
    let _ = std::io::stdout().flush();
    let log = Log::open(
        &dir_serial,
        SEG_RECOMENDADO,
        FsyncPolicy::GroupCommit { interval_ms: 1000 },
    )
    .expect("log");
    let escrita_serial = escrever_serial(&log, n, janela, "1 escritor");
    let head = log.head();
    let (bytes, segs) = tamanho_em_disco(&dir_serial);
    println!(
        "    log em disco: {:.1} MB em {segs} ficheiros, media {:.0} B/registo\n",
        bytes as f64 / 1e6,
        bytes as f64 / n as f64
    );

    // ── 2. LEITURA PONTUAL ──────────────────────────────────────────────────
    println!("-- 2. LEITURA PONTUAL · read(lsn) aleatorio ---------------------");
    let amostras = 20_000usize;
    let mut rng = Rng(0xDEAD_BEEF_CAFE_1234);
    let mut lat = Vec::with_capacity(amostras);
    let mut achados = 0usize;
    let t_leituras = Instant::now();
    for _ in 0..amostras {
        let alvo = rng.ate(head) as Lsn;
        let t = Instant::now();
        let r = log.read(alvo).expect("read");
        lat.push(t.elapsed());
        if r.is_some() {
            achados += 1;
        }
    }
    let vazao = amostras as f64 / t_leituras.elapsed().as_secs_f64();
    println!(
        "    {amostras} leituras aleatorias, {achados} encontradas ({:.1}%)",
        achados as f64 / amostras as f64 * 100.0
    );
    println!(
        "    p50 {:>9.2?} · p95 {:>9.2?} · p99 {:>9.2?} · max {:>9.2?} · {vazao:.0} leituras/s\n",
        pct(&mut lat, 0.50),
        pct(&mut lat, 0.95),
        pct(&mut lat, 0.99),
        pct(&mut lat, 1.0)
    );
    let p50_calma = pct(&mut lat, 0.50);

    // ── 3. VARRIMENTO ───────────────────────────────────────────────────────
    println!("-- 3. VARRIMENTO · scan / scan_capped --------------------------");
    for tam in [10_000u64, 100_000] {
        let inicio = head / 2;
        let t = Instant::now();
        let v = log.scan(inicio, (inicio + tam).min(head)).expect("scan");
        let dt = t.elapsed();
        let obtidos = v.len();
        println!(
            "    scan de {obtidos:>8} registos (pedidos {tam:>8}): {dt:>9.2?}  =  {:.0} registos/s",
            obtidos as f64 / dt.as_secs_f64()
        );
    }
    let t = Instant::now();
    let mut cur = 0u64;
    let mut lidos = 0usize;
    while cur < head {
        let lote = log.scan_capped(cur, head, 50_000).expect("scan_capped");
        match lote.last() {
            Some(&(ultimo, _)) => {
                lidos += lote.len();
                cur = ultimo + 1;
            }
            None => break,
        }
    }
    let dt = t.elapsed();
    println!(
        "    scan_capped do log INTEIRO ({lidos} registos): {dt:.2?}  =  {:.0} registos/s\n",
        lidos as f64 / dt.as_secs_f64()
    );

    // ── 4. CONSENSO · resolve_lsn_from_consensus_index ──────────────────────
    // A auditoria (secção 7) marcou-o O(n) por inspeção e deixou-o por medir.
    println!("-- 4. CONSENSO · resolve_lsn_from_consensus_index ---------------");
    let mut lat_cons = Vec::with_capacity(200);
    for k in 0..200u64 {
        let t = Instant::now();
        let _ = log.resolve_lsn_from_consensus_index(k * 7 + 1);
        lat_cons.push(t.elapsed());
    }
    println!(
        "    200 chamadas: p50 {:.2?} · p95 {:.2?} · max {:.2?}\n",
        pct(&mut lat_cons, 0.50),
        pct(&mut lat_cons, 0.95),
        pct(&mut lat_cons, 1.0)
    );

    // ── 5. LEITURA SOB ESCRITA ──────────────────────────────────────────────
    println!("-- 5. LEITURA SOB ESCRITA · 4 leitores + 4 escritores -----------");
    let dur = Duration::from_secs(10);
    let (mut lat_mistas, mut escritas, mut leituras) = (Vec::new(), 0u64, 0u64);
    std::thread::scope(|s| {
        let mut hs = Vec::new();
        for w in 0..4u64 {
            let log = &log;
            hs.push(s.spawn(move || {
                let mut rng = Rng(0xABCD_0000 + w);
                let mut k = 0u64;
                let t0 = Instant::now();
                while t0.elapsed() < dur {
                    log.append(evento(&mut rng, k)).expect("append");
                    k += 1;
                }
                Trabalho {
                    leitor: false,
                    operacoes: k,
                    latencias: Vec::new(),
                }
            }));
        }
        for r in 0..4u64 {
            let log = &log;
            hs.push(s.spawn(move || {
                let mut rng = Rng(0x1234_0000 + r);
                let mut l = Vec::new();
                let t0 = Instant::now();
                while t0.elapsed() < dur {
                    let alvo = rng.ate(head) as Lsn;
                    let t = Instant::now();
                    let _ = log.read(alvo);
                    l.push(t.elapsed());
                }
                Trabalho {
                    leitor: true,
                    operacoes: l.len() as u64,
                    latencias: l,
                }
            }));
        }
        for h in hs {
            let t = h.join().expect("thread");
            if t.leitor {
                leituras += t.operacoes;
                lat_mistas.extend(t.latencias);
            } else {
                escritas += t.operacoes;
            }
        }
    });
    println!(
        "    em {dur:?}: {escritas} escritas ({:.0}/s) e {leituras} leituras ({:.0}/s)",
        escritas as f64 / dur.as_secs_f64(),
        leituras as f64 / dur.as_secs_f64()
    );
    let p50_mista = pct(&mut lat_mistas, 0.50);
    let p99_mista = pct(&mut lat_mistas, 0.99);
    println!(
        "    leitura SOB escrita: p50 {p50_mista:.2?} · p95 {:.2?} · p99 {p99_mista:.2?} · max {:.2?}",
        pct(&mut lat_mistas, 0.95),
        pct(&mut lat_mistas, 1.0)
    );
    println!(
        "    vs leitura sem escrita (p50 {p50_calma:.2?})  =>  {:.2}x\n",
        p50_mista.as_secs_f64() / p50_calma.as_secs_f64().max(1e-12)
    );

    // ── 6. ARRANQUE A FRIO ──────────────────────────────────────────────────
    println!("-- 6. ARRANQUE A FRIO · reabrir o log ---------------------------");
    let head_final = log.head();
    drop(log);
    let t = Instant::now();
    let log2 = Log::open(
        &dir_serial,
        SEG_RECOMENDADO,
        FsyncPolicy::GroupCommit { interval_ms: 1000 },
    )
    .expect("reabrir");
    let t_abrir = t.elapsed();
    println!(
        "    Log::open sobre {head_final} registos: {t_abrir:.2?}  (head recuperado = {})",
        log2.head()
    );
    println!("    E o tempo de indisponibilidade num restart do servico.");
    let t = Instant::now();
    let _ = log2.read(head_final / 2).expect("read pos-reabertura");
    println!("    primeira leitura depois de reabrir: {:.2?}\n", t.elapsed());

    // ── 7. INTEGRIDADE · verify() integral ──────────────────────────────────
    println!("-- 7. INTEGRIDADE · verify() do log inteiro ---------------------");
    println!("    crc de cada registo + raiz Merkle de cada segmento selado.");
    let t = Instant::now();
    let rel = log2.verify().expect("verify");
    let t_verify = t.elapsed();
    println!(
        "    {} registos, {} segmentos, merkle_ok {} — {t_verify:.2?}  =  {:.0} registos/s",
        rel.records,
        rel.segments,
        rel.merkle_ok,
        rel.records as f64 / t_verify.as_secs_f64()
    );
    println!("    E o custo de uma auditoria forense completa.\n");
    drop(log2);

    // ── 8. ESCRITA CONCORRENTE ──────────────────────────────────────────────
    println!("-- 8. ESCRITA · 8 escritores · segmento 8 MiB -------------------");
    println!("    A 2a mitigacao da auditoria: lotes do worker ate 128 comandos.");
    println!("    Nunca medida acima de 200k registos.");
    print!("    debito por janela de {janela}:");
    let _ = std::io::stdout().flush();
    let log3 = Log::open(
        &dir_conc,
        SEG_RECOMENDADO,
        FsyncPolicy::GroupCommit { interval_ms: 1000 },
    )
    .expect("log concorrente");
    let escrita_conc = escrever_concorrente(&log3, n, janela, 8, "8 escritores");
    let (bytes_c, segs_c) = tamanho_em_disco(&dir_conc);
    println!(
        "    log em disco: {:.1} MB em {segs_c} ficheiros\n",
        bytes_c as f64 / 1e6
    );
    drop(log3);

    println!("=== VEREDICTO ===\n");
    println!("  escrita · 1 escritor   · 8 MiB : {escrita_serial:>9.0} app/s");
    println!("  escrita · 8 escritores · 8 MiB : {escrita_conc:>9.0} app/s");
    println!(
        "  ganho da concorrencia          : {:.1}x",
        escrita_conc / escrita_serial
    );
    println!();
    println!("  leitura pontual sem escrita : p50 {p50_calma:.2?}");
    println!("  leitura pontual sob escrita : p50 {p50_mista:.2?} · p99 {p99_mista:.2?}");
    println!();
    println!("  arranque a frio (Log::open) : {t_abrir:.2?}");
    println!("  auditoria forense (verify)  : {t_verify:.2?}");
    println!();
}
