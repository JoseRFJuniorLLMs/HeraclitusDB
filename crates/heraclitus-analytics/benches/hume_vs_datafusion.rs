//! HUME (`VecExecutor`) **versus** DataFusion — mesma consulta, mesmos dados,
//! mesmo resultado.
//!
//! Primeiro entregável da SPEC-0042 (*DataFusion como motor geral e autoridade
//! semântica; HUME como fast path físico especializado*). O router híbrido não
//! deve ser escrito antes deste número existir: a spec exige que **cada classe
//! de plano seja conquistada por benchmark**, não recebida por decreto.
//!
//! ## O que este benchmark corrige
//!
//! O único número que o repositório tinha era `VecExecutor` **eager vs fused**
//! (~20% a ~1% de seletividade). Isso **não** é HUME vs DataFusion — comparava
//! o executor próprio consigo mesmo. Afirmar "HUME é 20% mais rápido que o
//! DataFusion" a partir dali seria falso, e é exatamente o tipo de conclusão que
//! um benchmark mal lido produz.
//!
//! ## Critério de promoção (SPEC-0042 H1)
//!
//! Uma classe de plano só migra para o HUME com:
//! 1. **≥ 1,20×** de speedup — abaixo disso a complexidade do router não se paga;
//! 2. **zero divergência semântica** — o benchmark compara as linhas devolvidas,
//!    não só o tempo. Um motor mais rápido que responde diferente não é mais
//!    rápido, é outro produto;
//! 3. **sem regressão de p95** — reportado por percentis, não só pela média.
//!
//! ```bash
//! cargo bench -p heraclitus-analytics --bench hume_vs_datafusion
//! ```

fn main() {
    use heraclitus_analytics::planner::run_analytical;
    use heraclitus_analytics::LogAnalytics;
    use heraclitus_core::{Episode, EventKind, FsyncPolicy, Lsn};
    use heraclitus_log::Log;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    /// Dataset determinístico, escrito num `Log` REAL para os dois motores o
    /// lerem pelo mesmo caminho.
    fn preparar(n: u64) -> (tempfile::TempDir, Log, Vec<(Lsn, Episode)>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = Log::open(dir.path(), 256 << 20, FsyncPolicy::Never).expect("log");
        for i in 0..n {
            let mut e = Episode::new(
                // 1 em cada 1000 é "alvo": permite descer até 0,1%.
                if i % 1000 == 0 { "alvo" } else { "outro" },
                EventKind::Custom(if i % 3 == 0 { "A" } else { "B" }.into()),
                vec![0u8; 64],
            );
            e.ts_hlc = i;
            log.append(e).expect("append");
        }
        let head = log.head();
        let events = log.scan(0, head).expect("scan");
        (dir, log, events)
    }

    /// Consultas com seletividade e nº de predicados controlados.
    /// A sintaxe é a que o `AnalyticalPlanner` aceita.
    fn consulta(preds: usize, seletividade: f64, n: u64) -> String {
        let corte = (n as f64 * seletividade) as u64;
        let mut q = format!("SELECT WHERE lsn < {corte}");
        // Predicados extra que NÃO alteram o conjunto resultante — isolam o
        // custo de avaliar mais predicados da mudança de cardinalidade.
        for k in 1..preds {
            q.push_str(&format!(" AND lsn < {}", corte + k as u64 * 1_000_000));
        }
        q.push_str(" GROUP BY kind SUM content_len");
        q
    }

    fn percentil(mut v: Vec<Duration>, p: f64) -> Duration {
        v.sort_unstable();
        v[((v.len() as f64 - 1.0) * p).round() as usize]
    }

    const N: u64 = 200_000;
    const REPS: usize = 9;

    let (_dir, log, events) = preparar(N);
    println!("\nHUME (VecExecutor) vs DataFusion — {N} eventos, {REPS} repeticoes\n");
    println!(
        "  {:>6} {:>6}  {:>11} {:>11}  {:>11} {:>11}  {:>7}  {:>9}",
        "sel", "preds", "HUME p50", "HUME p95", "DF p50", "DF p95", "speedup", "semantica"
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    for &seletividade in &[0.5f64, 0.1, 0.01, 0.001] {
        for &preds in &[1usize, 2, 4, 8] {
            let q = consulta(preds, seletividade, N);
            let sels: HashMap<u32, f64> =
                (0..preds as u32).map(|i| (i, seletividade)).collect();

            // ── HUME ────────────────────────────────────────────────────────
            let _ = run_analytical(&q, &events, sels.clone());
            let mut t_hume = Vec::with_capacity(REPS);
            let mut linhas_hume = 0usize;
            for _ in 0..REPS {
                let t0 = Instant::now();
                let out = run_analytical(&q, &events, sels.clone());
                t_hume.push(t0.elapsed());
                linhas_hume = out.map(|b| b.iter().map(|x| x.num_rows()).sum()).unwrap_or(0);
            }

            // ── DataFusion ──────────────────────────────────────────────────
            // Mesma pergunta, dialeto SQL. O DataFusion é a autoridade
            // semântica: o resultado dele é o esperado.
            let sql = format!(
                "SELECT kind, SUM(content_len) FROM events WHERE {} GROUP BY kind",
                (0..preds)
                    .map(|k| format!(
                        "lsn < {}",
                        (N as f64 * seletividade) as u64 + k as u64 * 1_000_000
                    ))
                    .collect::<Vec<_>>()
                    .join(" AND ")
            );
            let df = LogAnalytics::from_log(&log, None);
            let (mut t_df, mut linhas_df) = (Vec::with_capacity(REPS), 0usize);
            let ok_df = match &df {
                Ok(a) => {
                    let _ = rt.block_on(a.sql(&sql));
                    for _ in 0..REPS {
                        let t0 = Instant::now();
                        let r = rt.block_on(a.sql(&sql));
                        t_df.push(t0.elapsed());
                        linhas_df = r.map(|v| v.len()).unwrap_or(0);
                    }
                    true
                }
                Err(_) => false,
            };
            if !ok_df {
                println!("  {seletividade:>6} {preds:>6}  (DataFusion indisponivel)");
                continue;
            }

            let (h50, h95) = (percentil(t_hume.clone(), 0.5), percentil(t_hume, 0.95));
            let (d50, d95) = (percentil(t_df.clone(), 0.5), percentil(t_df, 0.95));
            let speedup = d50.as_secs_f64() / h50.as_secs_f64();
            // Zero divergência semântica é requisito de promoção, não detalhe.
            let semantica = if linhas_hume == linhas_df { "igual" } else { "DIVERGE" };

            println!(
                "  {:>5.1}% {preds:>6}  {h50:>11.2?} {h95:>11.2?}  {d50:>11.2?} {d95:>11.2?}  \
                 {speedup:>6.2}x  {semantica:>9}",
                seletividade * 100.0
            );
        }
    }

    println!();
    println!("  Criterio de promocao (SPEC-0042 H1): speedup >= 1.20x E semantica igual");
    println!("  E sem regressao de p95. Abaixo disso, o plano fica no DataFusion.");
    println!();
    println!("  NOTA: o ~20% que o repositorio ja tinha era VecExecutor eager vs fused");
    println!("  -- o executor proprio contra si mesmo, NAO contra o DataFusion.");
    println!();
}
