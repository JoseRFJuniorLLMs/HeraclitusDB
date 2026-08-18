//! Carga realista de 1 000 000 de registos: escrita E leitura.
//!
//! Os benchmarks anteriores mediam uma coisa de cada vez, com payload
//! artificial (um byte repetido). Este aproxima-se do caso de uso alvo —
//! ingestão de logs gerais de servidores — e mede o sistema como vai ser usado:
//!
//!  1. **escrita** com a configuração recomendada (segmento 8 MiB);
//!  2. **leitura pontual** `read(lsn)` aleatória — o caminho O(1) posicional;
//!  3. **varrimento** `scan` e `scan_capped` — o caminho analítico;
//!  4. **leitura SOB escrita** — leitores e escritores em simultâneo. É o teste
//!     que justifica (ou não) o desenho: o índice é copiado na escrita
//!     precisamente para os leitores nunca bloquearem. Se a latência de leitura
//!     se degradar com escrita concorrente, a troca não está a compensar;
//!  5. **arranque a frio** — reabrir o log de 1M reconstrói o índice. É o tempo
//!     de indisponibilidade num restart, um número operacional real;
//!  6. **escrita com 256 MiB (o default ANTIGO)** — a comparação que valida (ou não) a
//!     recomendação da auditoria no volume alvo, em vez de por extrapolação.
//!
//! ```bash
//! cargo bench -p heraclitus-log --bench carga_real_1m
//! ```
//!
//! `HERACLITUS_BENCH_N=200000` encurta. A fase 6 é lenta por desenho — é o
//! problema a ser demonstrado — e corre em último, para tudo o resto já estar
//! impresso quando ela começar.

use heraclitus_core::{Episode, EventKind, FsyncPolicy, Lsn};
use heraclitus_log::Log;
use std::io::Write;
use std::time::{Duration, Instant};

/// A recomendação da auditoria `docs/md/auditorias/append-lento-com-o-crescimento.md`.
const SEG_RECOMENDADO: u64 = 8 << 20;
/// O default ANTIGO de `HeraclitusConfig::segment_max_bytes`, mantido aqui
/// como termo de comparacao depois de o default passar a 8 MiB.
const SEG_DEFAULT: u64 = 256 << 20;

/// Gerador determinístico (xorshift64*). Reprodutível de propósito: um
/// benchmark que muda de dados a cada corrida não permite comparar corridas.
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

/// Um evento com forma de linha de log real: serviço, nível, mensagem de
/// comprimento variável e três atributos. O `BTreeMap` de atributos importa —
/// é serializado por bincode em cada append, e um payload artificial não o
/// exercita.
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

fn escrever(log: &Log, n: u64, janela: u64, rotulo: &str) -> f64 {
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
        println!("    {rotulo}: {total:.0} app/s no total ({:.1?})", t_total.elapsed());
    }
    total
}

/// O que uma thread da fase 4 devolve. Um booleano explícito em vez de inferir
/// o papel pelo vetor estar vazio — um leitor com zero leituras seria contado
/// como escritor.
struct Trabalho {
    leitor: bool,
    operacoes: u64,
    latencias: Vec<Duration>,
}

fn main() {
    let n: u64 = std::env::var("HERACLITUS_BENCH_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);
    // 40 janelas: com 10M e selagens a cada ~550k, e o suficiente para o
    // dente-de-serra das selagens aparecer em vez de ficar aliased.
    let janela = (n / 40).clamp(1_000, 250_000).min(n.max(1));

    println!("\n=== Carga realista: {n} registos, escrita + leitura ===\n");
    println!("Eventos com forma de log de servidor: 8 servicos, 5 niveis, 6 rotas,");
    println!("mensagem de 120-400 B e 3 atributos por registo (bincode real).\n");

    // ── 1. ESCRITA com a configuracao recomendada ───────────────────────────
    println!("-- 1. ESCRITA · segmento 8 MiB (recomendacao da auditoria) ------");
    print!("    debito por janela de {janela}:");
    let _ = std::io::stdout().flush();
    let dir = tempfile::tempdir().expect("tempdir");
    let log = Log::open(
        dir.path(),
        SEG_RECOMENDADO,
        FsyncPolicy::GroupCommit { interval_ms: 1000 },
    )
    .expect("log");
    let escrita_boa = escrever(&log, n, janela, "8 MiB");
    let head = log.head();

    let (bytes, segs) = match std::fs::read_dir(dir.path()) {
        Ok(rd) => {
            let v: Vec<u64> = rd
                .flatten()
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .collect();
            (v.iter().sum::<u64>(), v.len())
        }
        Err(_) => (0, 0),
    };
    println!(
        "    log em disco: {:.1} MB em {segs} ficheiros, media {:.0} B/registo\n",
        bytes as f64 / 1e6,
        bytes as f64 / n as f64
    );

    // ── 2. LEITURA PONTUAL aleatoria ────────────────────────────────────────
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
        // Imprime o que foi REALMENTE lido, não o que foi pedido: perto do
        // fim do log o intervalo é truncado por `head` e as duas linhas
        // mediriam o mesmo sem se notar.
        let obtidos = v.len();
        println!(
            "    scan de {obtidos:>7} registos (pedidos {tam:>7}): {dt:>9.2?}  =  {:.0} registos/s",
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

    // ── 4. LEITURA SOB ESCRITA ──────────────────────────────────────────────
    println!("-- 4. LEITURA SOB ESCRITA · 4 leitores + 4 escritores -----------");
    println!("    O indice e copiado na escrita para os leitores nunca bloquearem.");
    println!("    Se a latencia de leitura nao piorar, a troca esta a compensar.");
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
        "    vs leitura sem escrita (p50 {p50_calma:.2?})  =>  {:.2}x",
        p50_mista.as_secs_f64() / p50_calma.as_secs_f64().max(1e-12)
    );
    println!();

    // ── 5. ARRANQUE A FRIO ──────────────────────────────────────────────────
    println!("-- 5. ARRANQUE A FRIO · reabrir o log ---------------------------");
    let head_final = log.head();
    drop(log);
    let t = Instant::now();
    let log2 = Log::open(
        dir.path(),
        SEG_RECOMENDADO,
        FsyncPolicy::GroupCommit { interval_ms: 1000 },
    )
    .expect("reabrir");
    println!(
        "    Log::open sobre {head_final} registos: {:.2?}  (head recuperado = {})",
        t.elapsed(),
        log2.head()
    );
    println!("    E o tempo de indisponibilidade num restart do servico.");
    let t = Instant::now();
    let _ = log2.read(head_final / 2).expect("read pos-reabertura");
    println!("    primeira leitura depois de reabrir: {:.2?}\n", t.elapsed());
    drop(log2);
    drop(dir);

    // ── 6. ESCRITA com o DEFAULT de producao (a lenta) ──────────────────────
    println!("-- 6. ESCRITA · segmento 256 MiB (o DEFAULT de producao) --------");
    println!("    Lenta por desenho: e o problema a ser demonstrado no volume");
    println!("    alvo, em vez de extrapolado da curva de 200k.");
    print!("    debito por janela de {janela}:");
    let _ = std::io::stdout().flush();
    let dir2 = tempfile::tempdir().expect("tempdir");
    let log3 = Log::open(
        dir2.path(),
        SEG_DEFAULT,
        FsyncPolicy::GroupCommit { interval_ms: 1000 },
    )
    .expect("log");
    let escrita_default = escrever(&log3, n, janela, "256 MiB");

    println!("\n=== VEREDICTO ===\n");
    println!("  escrita · segmento   8 MiB (recomendado): {escrita_boa:>9.0} app/s");
    println!("  escrita · segmento 256 MiB (default)    : {escrita_default:>9.0} app/s");
    println!(
        "  ganho da recomendacao no volume alvo    : {:.1}x",
        escrita_boa / escrita_default
    );
    println!();
    println!("  leitura pontual sem escrita : p50 {p50_calma:.2?}");
    println!("  leitura pontual sob escrita : p50 {p50_mista:.2?} · p99 {p99_mista:.2?}");
    println!();
}
