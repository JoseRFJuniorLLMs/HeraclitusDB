//! HUME (`VecExecutor`) **versus** DataFusion — mesma pergunta, mesmos dados,
//! resultado comparado por digest canónico.
//!
//! Primeiro entregável da SPEC-0042 (§17, §22 Marco 0). A spec é explícita:
//! *"Saída: números, não wiring"*. Nenhum router é escrito antes deste número
//! existir.
//!
//! ## Classe medida: H1, e só H1
//!
//! A §27 autoriza *"somente H1 — cadeias de filtros altamente seletivas"* e o
//! Marco 0 manda "medir H1". H1 (§7) é `Scan → Filter(p0) → Filter(p1..pn)`.
//! **Sem agregação** — `Filter* → GroupBy → COUNT/SUM` é a classe H2, que a
//! spec adia para o Marco 6 e só permite *"depois de H1 estabilizar"*.
//!
//! A distinção não é burocrática. `VecExecutor::run_aggregate` constrói um
//! `Vec<String>` de chave **por linha sobrevivente** e usa-o como chave de
//! `HashMap`; a 50% de seletividade sobre 1M de linhas são ~500k alocações. Ou
//! seja: medir com `GROUP BY` faz o eixo da seletividade medir o agregador do
//! HUME, não o filtro — e o crossover que o §22 manda registar sairia deslocado
//! por um custo que não pertence a H1. `HERACLITUS_BENCH_H2=1` corre também a
//! variante com agregação, sempre rotulada como H2.
//!
//! ## Porque `exec` é a coluna que decide
//!
//! A §2.1 mantém o DataFusion como **autoridade semântica**: em produção o
//! parse/bind é dele e o HUME só recebe um plano já validado. Logo o custo de
//! parse é pago nos dois caminhos e **não** é ganho atribuível ao HUME — o
//! tokenizer à mão do `AnalyticalPlanner` nem chega a existir nesse desenho.
//! Por isso os planos são construídos **fora** do cronómetro dos dois lados, e
//! o custo de planeamento é reportado à parte, como a §17.2 exige.
//!
//! ## Guarda de cardinalidade (a lição que custou uma corrida inteira)
//!
//! A primeira versão deste ficheiro assumiu que `Episode::ts_hlc` sobrevivia ao
//! `Log::append`. Não sobrevive: o append **carimba** o HLC real por cima. Os
//! predicados extra `ts_hlc < n+k`, que deviam ser sempre-verdadeiros, ficaram
//! sempre-falsos, e todas as células com 2+ predicados devolveram **zero
//! linhas**. Os "speedups" de 7× a 30× eram dois motores a competir para não
//! devolver nada — e o digest dizia `igual` porque **ambos** acertavam em vazio.
//!
//! Comparar resultados nunca apanha um predicado errado de forma idêntica nos
//! dois lados. Por isso agora: (1) as constantes vêm dos dados REAIS lidos do
//! log, nunca de suposições; (2) a cardinalidade sobrevivente é impressa em
//! todas as células; (3) uma célula com 0 linhas, ou cuja cardinalidade mude
//! ao variar só o nº de predicados, é marcada INVÁLIDA e não conta.
//!
//! ## Critério de promoção (§9, §16 Gate B)
//!
//! 1. **≥ 1,20×** de speedup de p50; 2. **zero divergência** (§11);
//! 3. **p95 HUME ≤ p95 DataFusion**.
//!
//! ```bash
//! cargo bench -p heraclitus-analytics --bench hume_vs_datafusion
//! ```
//!
//! `HERACLITUS_BENCH_ROWS=10000,100000` corta a matriz; `HERACLITUS_BENCH_H2=1`
//! acrescenta a classe H2.

use heraclitus_analytics::datafusion::arrow::array::{
    Array, Int32Array, Int64Array, RecordBatch, StringArray, UInt64Array,
};
use heraclitus_analytics::datafusion::physical_plan::collect as df_collect;
use heraclitus_analytics::planner::AnalyticalPlanner;
use heraclitus_analytics::vectorized::{episodes_to_batches, SelectivityOptimizer, VecExecutor};
use heraclitus_analytics::LogAnalytics;
use heraclitus_core::contracts::{Optimizer, TaskScheduler};
use heraclitus_core::{Episode, EventKind, FsyncPolicy, Lsn};
use heraclitus_log::Log;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

/// Larguras de linha da §17.1 (`estreita`, `média`), em bytes de `content`.
const LARGURAS: [(&str, usize); 2] = [("estreita", 64), ("media", 256)];
/// Seletividades finais da §17.1.
const SELETIVIDADES: [f64; 5] = [0.5, 0.1, 0.05, 0.01, 0.001];
/// Nº de predicados da §17.1.
const PREDICADOS: [usize; 4] = [1, 2, 4, 8];

#[derive(Clone, Copy, PartialEq)]
enum Classe {
    /// §7 H1 — cadeia de filtros. A ÚNICA que a §27 autoriza promover.
    H1,
    /// §7 H2 — filtros + agregação. Marco 6, só depois de H1 estabilizar.
    H2,
}

impl Classe {
    fn nome(self) -> &'static str {
        match self {
            Classe::H1 => "H1",
            Classe::H2 => "H2",
        }
    }
}

fn main() {
    let linhas = std::env::var("HERACLITUS_BENCH_ROWS")
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|x| x.trim().parse::<u64>().ok())
                .collect::<Vec<_>>()
        })
        .filter(|v: &Vec<u64>| !v.is_empty())
        .unwrap_or_else(|| vec![10_000, 100_000, 1_000_000]);

    let mut classes = vec![Classe::H1];
    if std::env::var("HERACLITUS_BENCH_H2").is_ok() {
        classes.push(Classe::H2);
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");

    println!("\nSPEC-0042 §17 — HUME (VecExecutor) vs DataFusion, end-to-end\n");
    println!("  Classe medida: H1 (cadeia de filtros, SEM agregacao) — a unica que a");
    println!("  §27 autoriza. `exec` e a coluna que decide: no desenho aprovado (§2.1)");
    println!("  o parse do DataFusion e pago nos dois caminhos, logo nao e ganho do");
    println!("  HUME. Planeamento fica FORA do cronometro dos dois lados.\n");
    println!("  `linhas` = cardinalidade sobrevivente. E uma guarda, nao ornamento:");
    println!("  se for 0, ou variar ao mudar so o nº de predicados, a celula e INVALIDA.\n");

    let mut resumo: Vec<Resumo> = Vec::new();
    let mut plano_mostrado = false;

    for &n in &linhas {
        // O eixo `largura` só é informativo abaixo de 1M. Na projeção justa de
        // H1 — (lsn, agent_id, kind, ts_hlc) — NENHUM dos motores lê `content`,
        // logo a largura só muda o tamanho do log e a materialização, ambos
        // reportados à parte. Repetir 1M nas duas larguras custaria ~1,5 h de
        // geração para produzir a mesma tabela; medimos as duas em 10k/100k
        // (que É a resposta da §17.1 para este eixo: não mexe) e 1M só na
        // estreita.
        let larguras: &[(&str, usize)] = if n >= 1_000_000 {
            &LARGURAS[..1]
        } else {
            &LARGURAS
        };
        for &(nome_larg, largura) in larguras {
            println!("  ... a gerar {n} linhas / {nome_larg} (o log aceita ~180 appends/s)");
            let Some(ds) = Dataset::preparar(n, largura) else {
                println!("  [{n} linhas / {nome_larg}] indisponivel (falha a preparar)\n");
                continue;
            };

            for &classe in &classes {
                println!(
                    "── {} · {n} linhas · largura {nome_larg} ({largura} B) ─────────────────",
                    classe.nome()
                );
                println!(
                    "   materializacao (uma vez, §17.2): HUME {:.2?} · DataFusion {:.2?}",
                    ds.mat_hume, ds.mat_df
                );
                println!(
                    "   escrita do log (fora da comparacao): {:.1?} para {n} appends = {:.0} appends/s",
                    ds.gen,
                    n as f64 / ds.gen.as_secs_f64()
                );
                println!(
                    "   {:>7} {:>5} {:>9}  {:>10} {:>10}  {:>10} {:>10}  {:>8}  {:>9}  {:>10}",
                    "sel",
                    "preds",
                    "linhas",
                    "HUME p50",
                    "HUME p95",
                    "DF p50",
                    "DF p95",
                    "speedup",
                    "semantica",
                    "veredicto"
                );

                // Menos repetições no dataset grande: o custo por consulta domina.
                let reps = if n >= 1_000_000 { 7 } else { 15 };
                let (mut planos_h, mut planos_d) = (Vec::new(), Vec::new());

                for &sel in &SELETIVIDADES {
                    // Cardinalidade de referência desta seletividade: a de 1
                    // predicado. Variar só o nº de predicados NAO pode mudá-la.
                    let mut referencia: Option<usize> = None;

                    for &preds in &PREDICADOS {
                        let caso = Caso::novo(&ds, sel, preds, classe);

                        if !plano_mostrado && preds == 8 {
                            plano_mostrado = true;
                            mostrar_plano(&rt, &ds, &caso);
                        }

                        let Some(h) = medir_hume(&ds, &caso, reps) else {
                            println!("   {:>6.1}% {preds:>5}  (HUME falhou)", sel * 100.0);
                            continue;
                        };
                        let Some(d) = medir_df(&rt, &ds, &caso, reps) else {
                            println!("   {:>6.1}% {preds:>5}  (DataFusion falhou)", sel * 100.0);
                            continue;
                        };

                        planos_h.push(h.plano);
                        planos_d.push(d.plano);

                        // ── guardas ──────────────────────────────────────────
                        let vazio = h.linhas == 0;
                        let mudou = match referencia {
                            None => {
                                referencia = Some(h.linhas);
                                false
                            }
                            Some(r) => r != h.linhas,
                        };
                        let igual = h.digest == d.digest;
                        let valida = !vazio && !mudou && igual;

                        let speedup = d.exec_p50.as_secs_f64() / h.exec_p50.as_secs_f64();
                        let sem_regressao_p95 = h.exec_p95 <= d.exec_p95;
                        let promove = valida && speedup >= 1.20 && sem_regressao_p95;

                        let veredicto = if vazio {
                            "VAZIO"
                        } else if mudou {
                            "CARD MUDOU"
                        } else if !igual {
                            "DIVERGE"
                        } else if speedup >= 1.20 && !sem_regressao_p95 {
                            "p95 pior"
                        } else if promove {
                            "HUME"
                        } else {
                            "DataFusion"
                        };

                        resumo.push(Resumo {
                            classe,
                            valida,
                            promove,
                            diverge: !igual,
                        });

                        println!(
                            "   {:>6.1}% {preds:>5} {:>9}  {:>10.2?} {:>10.2?}  {:>10.2?} \
                             {:>10.2?}  {speedup:>7.2}x  {:>9}  {veredicto:>10}",
                            sel * 100.0,
                            h.linhas,
                            h.exec_p50,
                            h.exec_p95,
                            d.exec_p50,
                            d.exec_p95,
                            if igual { "igual" } else { "DIVERGE" },
                        );
                    }
                }

                // §17.2 exige medir o planeamento. Fica FORA de `exec` porque,
                // no desenho aprovado (§2.1), o DataFusion faz o parse dos dois
                // caminhos — o baixo custo do tokenizer do HUME nao e ganho real.
                if !planos_h.is_empty() {
                    println!(
                        "   planeamento (mediana, FORA de `exec`): HUME parse+lowering {:.2?} · \
                         DataFusion parse+logico+fisico {:.2?}",
                        percentil(&mut planos_h, 0.5),
                        percentil(&mut planos_d, 0.5)
                    );
                }
                println!();
            }
        }
    }

    // ── §17.3 ───────────────────────────────────────────────────────────────
    println!("── Resultado (§17.3) ────────────────────────────────────────────────");
    for classe in [Classe::H1, Classe::H2] {
        let c: Vec<_> = resumo.iter().filter(|r| r.classe == classe).collect();
        if c.is_empty() {
            continue;
        }
        let validas = c.iter().filter(|r| r.valida).count();
        let promove = c.iter().filter(|r| r.promove).count();
        let diverge = c.iter().filter(|r| r.diverge).count();
        println!(
            "   {}: {} celulas · {validas} validas · {promove} promoviveis · {diverge} divergencias",
            classe.nome(),
            c.len()
        );
        if validas < c.len() {
            println!(
                "      ATENCAO: {} celulas INVALIDAS (vazias ou de cardinalidade instavel).",
                c.len() - validas
            );
            println!("      Nao contam para o Gate B — uma celula vazia nao mede nada.");
        }
    }
    let promove_h1 = resumo
        .iter()
        .filter(|r| r.classe == Classe::H1 && r.promove)
        .count();
    let validas_h1 = resumo
        .iter()
        .filter(|r| r.classe == Classe::H1 && r.valida)
        .count();
    println!();
    if validas_h1 == 0 {
        println!("   Nenhuma celula H1 valida — o benchmark nao produziu evidencia.");
    } else if promove_h1 == 0 {
        println!("   Zero celulas H1 promoviveis => §25 aplica-se: o wiring do router NAO");
        println!("   deve avancar. As primitivas HUME continuam validas como I&D e para");
        println!("   os pipelines multimodais (H4).");
    } else {
        println!("   {promove_h1} de {validas_h1} celulas H1 validas cumprem o Gate B (§16).");
        println!("   O Marco 1 so deve cobrir ESSAS regioes — o Gate D (§16) exige que o");
        println!("   router impeca o HUME nos regimes onde perde.");
    }
    println!();
}

struct Resumo {
    classe: Classe,
    valida: bool,
    promove: bool,
    diverge: bool,
}

// ── dataset ─────────────────────────────────────────────────────────────────

struct Dataset {
    _dir: tempfile::TempDir,
    /// Batches Arrow do HUME, materializados UMA vez (§17.2).
    batches: Vec<RecordBatch>,
    df: LogAnalytics,
    mat_hume: Duration,
    mat_df: Duration,
    /// Tempo para escrever as `n` linhas no log, via `Log::append` uma a uma.
    /// Não faz parte da comparação HUME vs DataFusion — está aqui porque foi o
    /// que fez a primeira corrida da matriz completa levar horas, e porque a
    /// taxa que revela é um dado sobre o caminho de escrita do log.
    gen: Duration,
    /// LSNs REAIS lidos do log, por ordem. O corte de seletividade sai daqui,
    /// não de uma suposição sobre a numeração.
    lsns: Vec<Lsn>,
    /// `ts_hlc` máximo REAL. O `Log::append` carimba o HLC por cima do valor
    /// que o produtor põe no `Episode` — ler o valor efetivo é obrigatório.
    ts_max: u64,
    n: u64,
}

impl Dataset {
    fn preparar(n: u64, largura: usize) -> Option<Self> {
        let dir = tempfile::tempdir().ok()?;
        let log = Log::open(
            dir.path(),
            512 << 20,
            FsyncPolicy::GroupCommit { interval_ms: 1000 },
        )
        .ok()?;
        // ASCII puro: `content_len` do HUME (bytes) e `octet_length(content)` do
        // DataFusion (sobre a String de from_utf8_lossy) só coincidem se o
        // payload não tiver bytes não-UTF8. Com `b'x'` coincidem por construção.
        let payload = vec![b'x'; largura];
        let t_gen = Instant::now();
        for i in 0..n {
            let e = Episode::new(
                if i % 1000 == 0 { "alvo" } else { "outro" },
                EventKind::Custom(if i % 3 == 0 { "A" } else { "B" }.into()),
                payload.clone(),
            );
            // NOTA: não vale a pena carimbar `e.ts_hlc` aqui — o `append`
            // sobrescreve-o com o HLC real. O valor efetivo é lido do scan.
            log.append(e).ok()?;
        }
        let gen = t_gen.elapsed();

        let head = log.head();
        let events = log.scan(0, head).ok()?;
        let lsns: Vec<Lsn> = events.iter().map(|(l, _)| *l).collect();
        let ts_max = events.iter().map(|(_, e)| e.ts_hlc).max().unwrap_or(0);

        let t = Instant::now();
        let batches = episodes_to_batches(&events).ok()?;
        let mat_hume = t.elapsed();

        drop(events);

        let t = Instant::now();
        // Orçamento largo: o objetivo aqui é medir, não exercitar o admission
        // control (que tem teste próprio).
        let df = LogAnalytics::from_log_capped(&log, None, 20_000_000, 8 << 30).ok()?;
        let mat_df = t.elapsed();

        Some(Self {
            _dir: dir,
            batches,
            df,
            mat_hume,
            mat_df,
            gen,
            lsns,
            ts_max,
            n,
        })
    }
}

// ── caso: a mesma pergunta nos dois dialetos ────────────────────────────────

struct Caso {
    /// Gramática do `AnalyticalPlanner`.
    hume: String,
    /// SQL do DataFusion.
    sql: String,
    selectividades: HashMap<u32, f64>,
    /// Colunas (índice) a entrar no digest, iguais nos dois outputs.
    cols: usize,
}

impl Caso {
    fn novo(ds: &Dataset, sel: f64, preds: usize, classe: Classe) -> Self {
        // Corte tirado do LSN REAL no percentil pedido.
        let idx = ((ds.n as f64 * sel) as usize).min(ds.lsns.len().saturating_sub(1));
        let corte = ds.lsns[idx];
        let lsn_max = ds.lsns.last().copied().unwrap_or(0);

        let mut p = vec![format!("lsn < {corte}")];
        // Predicados extra SEMPRE VERDADEIROS, com constantes derivadas dos
        // dados REAIS (`lsn_max`, `ts_max` lidos do log). Isolam o custo de
        // avaliar mais predicados da mudança de cardinalidade — a guarda de
        // cardinalidade no laço principal verifica que assim é, em vez de
        // confiar neste comentário.
        //
        // Só colunas u64 simples (`lsn`, `ts_hlc`), presentes e do mesmo tipo
        // nos dois schemas: evita meter `octet_length` no filtro e dar trabalho
        // extra a um dos lados.
        for k in 1..preds as u64 {
            if k % 2 == 0 {
                p.push(format!("lsn < {}", lsn_max + k));
            } else {
                p.push(format!("ts_hlc < {}", ds.ts_max + k));
            }
        }
        let onde = p.join(" AND ");

        // Verdade nas estatísticas: só o predicado 0 corta. Mentir aqui
        // enganaria a Porta B (§8) e a decisão de fusão.
        let mut selectividades = HashMap::new();
        selectividades.insert(0u32, sel);
        for k in 1..preds as u32 {
            selectividades.insert(k, 1.0);
        }

        let (hume, sql, cols) = match classe {
            // H1: cadeia de filtros pura.
            //
            // A projeção são as 4 colunas que existem NATIVAMENTE nos dois
            // schemas, e o digest compara essas 4. A quinta coluna do
            // `batch_schema` do HUME (`content_len`) fica deliberadamente de
            // fora: pedi-la ao DataFusion obriga-o a arrastar a coluna
            // `content` inteira pelo filtro e a calcular `octet_length` por
            // linha — a 256 B são ~32× mais bytes na região cronometrada —
            // enquanto o HUME a tem PRÉ-COMPUTADA desde a materialização (que é
            // medida à parte). Isso não é o filtro a ser mais rápido, é o HUME
            // a receber trabalho já feito.
            //
            // O viés que sobra é agora contra o HUME, não a favor: ele continua
            // a carregar `content_len` pelo `filter_record_batch` (uma coluna
            // u64, barata) porque IGNORA a projeção do `ColumnScan`, enquanto o
            // DataFusion faz pushdown e nem lê a coluna. Preferível: um
            // benchmark que decide promoção deve errar contra o candidato.
            Classe::H1 => (
                format!("SELECT WHERE {onde}"),
                format!("SELECT lsn, agent_id, kind, ts_hlc FROM events WHERE {onde}"),
                4,
            ),
            // H2 (Marco 6, opt-in). RESSALVA que não se pode omitir na leitura:
            // aqui o `SUM` do DataFusion é sobre `octet_length(content)`,
            // calculado por linha, enquanto o do HUME é sobre `content_len`
            // pré-computado. A gramática do `AnalyticalPlanner` só sabe somar
            // colunas do `batch_schema`, logo não há forma de igualar sem mudar
            // o motor. Estes números favorecem o HUME por construção e servem
            // só de indicação grosseira — a promoção de H2 exige o benchmark
            // dedicado do §22 Marco 6, não este.
            Classe::H2 => (
                format!("SELECT WHERE {onde} GROUP BY kind SUM content_len"),
                format!(
                    "SELECT kind, COUNT(*) AS c, SUM(octet_length(content)) AS s \
                     FROM events WHERE {onde} GROUP BY kind"
                ),
                3,
            ),
        };

        Self {
            hume,
            sql,
            selectividades,
            cols,
        }
    }
}

// ── medição ─────────────────────────────────────────────────────────────────

struct Medida {
    exec_p50: Duration,
    exec_p95: Duration,
    /// Preparação do plano, medida uma vez e **fora** de `exec` (§17.2).
    plano: Duration,
    /// Cardinalidade do output. Para H1 são as linhas sobreviventes; para H2,
    /// os grupos. É a guarda contra células vazias.
    linhas: usize,
    digest: String,
}

fn medir_hume(ds: &Dataset, caso: &Caso, reps: usize) -> Option<Medida> {
    let t0 = Instant::now();
    let (plan, predicates) = AnalyticalPlanner::new().compile(&caso.hume).ok()?;
    let opt = SelectivityOptimizer {
        selectivities: caso.selectividades.clone(),
    };
    let dag = opt.optimize(plan).ok()?;
    let plano = t0.elapsed();

    let mut exec = VecExecutor::new(ds.batches.clone(), predicates);
    exec.selectivities = caso.selectividades.clone();

    let mut out = exec.execute(dag.clone()).ok()?; // aquecimento

    let mut t = Vec::with_capacity(reps);
    for _ in 0..reps {
        // `dag.clone()` fica DENTRO do cronómetro porque `execute` consome o
        // DAG — simétrico do plano físico reconstruído do lado DataFusion.
        let t0 = Instant::now();
        out = exec.execute(dag.clone()).ok()?;
        t.push(t0.elapsed());
    }
    Some(Medida {
        exec_p50: percentil(&mut t.clone(), 0.5),
        exec_p95: percentil(&mut t, 0.95),
        plano,
        linhas: out.iter().map(|b| b.num_rows()).sum(),
        digest: digest(&out, caso.cols),
    })
}

fn medir_df(rt: &tokio::runtime::Runtime, ds: &Dataset, caso: &Caso, reps: usize) -> Option<Medida> {
    let ctx = ds.df.ctx();

    // O plano físico é reconstruído a cada iteração, e não içado para fora do
    // laço. Não é desperdício — é obrigatório: um plano com `RepartitionExec`
    // tem estado interno consumido na primeira execução e entra em pânico
    // (`partition not used yet`) na segunda. Fica sempre FORA do cronómetro.
    let planear = || {
        rt.block_on(async {
            let df = ctx.sql(&caso.sql).await.ok()?;
            df.create_physical_plan().await.ok()
        })
    };

    let t0 = Instant::now();
    let primeiro = planear()?;
    let plano = t0.elapsed();

    let task = ctx.task_ctx();
    let mut out = rt.block_on(df_collect(primeiro, task.clone())).ok()?; // aquecimento

    let mut t = Vec::with_capacity(reps);
    for _ in 0..reps {
        let p = planear()?;
        let t0 = Instant::now();
        out = rt.block_on(df_collect(p, task.clone())).ok()?;
        t.push(t0.elapsed());
    }
    Some(Medida {
        exec_p50: percentil(&mut t.clone(), 0.5),
        exec_p95: percentil(&mut t, 0.95),
        plano,
        linhas: out.iter().map(|b| b.num_rows()).sum(),
        digest: digest(&out, caso.cols),
    })
}

fn mostrar_plano(rt: &tokio::runtime::Runtime, ds: &Dataset, caso: &Caso) {
    println!("\n   [§17.1] plano otimizado do DataFusion para 8 predicados —");
    println!("   o simplificador FUNDE predicados redundantes na mesma coluna e o");
    println!("   HUME avalia-os todos, por isso o eixo `preds` favorece o DataFusion.");
    println!("   Fica aqui a prova, em vez de uma ressalva sem evidencia:");
    match rt.block_on(ds.df.ctx().sql(&caso.sql)) {
        Ok(df) => match df.into_optimized_plan() {
            Ok(p) => {
                for l in format!("{}", p.display_indent()).lines() {
                    println!("     {l}");
                }
            }
            Err(e) => println!("     (indisponivel: {e})"),
        },
        Err(e) => println!("     (indisponivel: {e})"),
    }
    println!();
}

// ── comparação canónica (§11) ───────────────────────────────────────────────

/// Digest canónico do output, resistente à ordem: hash por linha sobre as
/// `cols` primeiras colunas normalizadas, combinado por soma e XOR (§11 ponto
/// 4 — "agregação multiset resistente"), mais a cardinalidade.
///
/// A consulta não pede `ORDER BY`, logo a ordem não é semanticamente relevante
/// e o multiset é o que tem de bater certo. Ordenar 500k strings por célula
/// seria correto e insuportável; soma+XOR+contagem dá o mesmo poder de deteção
/// a custo linear.
///
/// A §11 é explícita quanto a comparar só o nº de linhas: é insuficiente.
fn digest(batches: &[RecordBatch], cols: usize) -> String {
    let (mut soma, mut xor, mut n) = (0u64, 0u64, 0usize);
    for b in batches {
        if b.num_columns() < cols {
            return "<schema inesperado>".into();
        }
        for r in 0..b.num_rows() {
            let mut h = DefaultHasher::new();
            for c in 0..cols {
                celula(b, c, r).hash(&mut h);
            }
            let v = h.finish();
            soma = soma.wrapping_add(v);
            xor ^= v;
            n += 1;
        }
    }
    format!("n={n};soma={soma};xor={xor}")
}

/// Valor de uma célula normalizado para uma forma comparável entre motores.
/// O HUME emite `UInt64`; o DataFusion emite `Int64`/`Int32` para `COUNT(*)`,
/// `SUM` e `octet_length`. Normalizar é parte da canonização da §11.
#[derive(Hash)]
enum Celula {
    Texto(String),
    Numero(i128),
    Nulo,
}

fn celula(b: &RecordBatch, col: usize, row: usize) -> Celula {
    let a = b.column(col);
    if a.is_null(row) {
        return Celula::Nulo;
    }
    if let Some(x) = a.as_any().downcast_ref::<StringArray>() {
        return Celula::Texto(x.value(row).to_string());
    }
    if let Some(x) = a.as_any().downcast_ref::<UInt64Array>() {
        return Celula::Numero(x.value(row) as i128);
    }
    if let Some(x) = a.as_any().downcast_ref::<Int64Array>() {
        return Celula::Numero(x.value(row) as i128);
    }
    if let Some(x) = a.as_any().downcast_ref::<Int32Array>() {
        return Celula::Numero(x.value(row) as i128);
    }
    Celula::Nulo
}

fn percentil(v: &mut Vec<Duration>, p: f64) -> Duration {
    v.sort_unstable();
    v[(((v.len() - 1) as f64) * p).round() as usize]
}
