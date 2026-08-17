//! O append do log fica mais lento à medida que o segmento cresce — quanto, e
//! o que o corrige.
//!
//! ## O que se está a medir
//!
//! A FASE 4 do worker (`lib.rs:938`) publica o índice do segmento ativo por
//! **copy-on-write**: copia o vetor de `LsnEntry` INTEIRO e acrescenta as
//! entradas do lote. Isto é deliberado — o catálogo é lido por `ArcSwap` sem
//! lock nenhum, portanto o índice tem de ser imutável. O custo da leitura sem
//! lock é pago na escrita.
//!
//! O custo é `O(entradas_no_segmento_ativo)` **por lote**, não por append. Com
//! lote de tamanho `B`, cada append custa `O(n/B)`, e o total do segmento é
//! `O(n²/B)`. Duas coisas controlam o estrago:
//!
//! 1. **`segment_max_bytes`** — quando o segmento sela, o índice ativo reinicia
//!    (`lib.rs:1964`). O `n` do quadrático é *registos por segmento*, não do log
//!    todo. Segmento grande = quadrático mais longo.
//! 2. **Concorrência de escrita** — o worker junta até **128** comandos por lote
//!    (`lib.rs:651`). Um escritor síncrono (que espera cada ACK) produz lotes de
//!    1 e paga o pior caso; escritores concorrentes dividem a cópia entre si.
//!
//! ## Porque é que o bench que já existia não apanhou isto
//!
//! `benches/append.rs` mede o mesmo caminho, mas reporta a **média** do
//! criterion. Uma degradação progressiva desaparece numa média — o número sai
//! plausível e esconde a curva. Por isso aqui reporta-se **throughput por
//! janela**: é a curva que prova o efeito, e a média que o esconderia.
//!
//! ```bash
//! cargo bench -p heraclitus-log --bench append_scaling
//! ```

use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;
use std::time::Instant;

const N: u64 = 200_000;
const JANELA: u64 = 25_000;
const CONTEUDO: usize = 64;

fn episodio(i: u64) -> Episode {
    Episode::new(
        "bench",
        EventKind::Custom(if i % 3 == 0 { "A" } else { "B" }.into()),
        vec![b'x'; CONTEUDO],
    )
}

/// Um escritor síncrono, medindo o débito por janela de `JANELA` registos.
/// É a curva que interessa: mostra a degradação a acontecer DENTRO de uma
/// única corrida, o que prova que depende das entradas acumuladas e não de
/// nada externo.
fn curva(rotulo: &str, segmento: u64) -> Vec<f64> {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = Log::open(
        dir.path(),
        segmento,
        FsyncPolicy::GroupCommit { interval_ms: 1000 },
    )
    .expect("log");

    let mut debitos = Vec::new();
    let mut t = Instant::now();
    for i in 0..N {
        log.append(episodio(i)).expect("append");
        if (i + 1) % JANELA == 0 {
            debitos.push(JANELA as f64 / t.elapsed().as_secs_f64());
            t = Instant::now();
        }
    }

    println!("  {rotulo}");
    print!("    janela:");
    for k in 0..debitos.len() {
        print!(" {:>9}", format!("{}k", (k as u64 + 1) * JANELA / 1000));
    }
    println!();
    print!("    app/s :");
    for d in &debitos {
        print!(" {d:>9.0}");
    }
    println!();
    let (primeira, ultima) = (debitos[0], debitos[debitos.len() - 1]);
    println!(
        "    degradacao da 1a para a ultima janela: {:.1}x mais lento\n",
        primeira / ultima
    );
    debitos
}

/// Débito total com `escritores` threads a escrever em paralelo. Mede o efeito
/// do batching: o worker junta até 128 comandos e a cópia do índice é dividida
/// por todos eles.
fn concorrente(rotulo: &str, segmento: u64, escritores: u64) -> f64 {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = Log::open(
        dir.path(),
        segmento,
        FsyncPolicy::GroupCommit { interval_ms: 1000 },
    )
    .expect("log");

    let por_thread = N / escritores;
    let t = Instant::now();
    std::thread::scope(|s| {
        for w in 0..escritores {
            let log = &log;
            s.spawn(move || {
                for i in 0..por_thread {
                    log.append(episodio(w * por_thread + i)).expect("append");
                }
            });
        }
    });
    let dt = t.elapsed();
    let debito = (por_thread * escritores) as f64 / dt.as_secs_f64();
    println!("  {rotulo}: {debito:>9.0} app/s  ({:.1?} para {N} registos)", dt);
    debito
}

fn main() {
    println!("\nAuditoria: o append do log abranda com o crescimento do segmento");
    println!("{N} registos de {CONTEUDO} B por configuracao.\n");

    println!("── 1. A curva (1 escritor sincrono) ──────────────────────────────");
    println!("  Se o custo por append fosse constante, a linha seria plana.\n");
    let grande = curva("segmento 1 GiB (nunca sela — quadratico corre ate ao fim)", 1 << 30);
    let pequeno = curva("segmento 4 MiB (sela varias vezes — indice reinicia)", 4 << 20);
    // Contraprova obrigatoria: `roll_segment` (lib.rs:1936) faz
    // `(*catalog.sealed).clone()` — clona o vetor de segmentos SELADOS a cada
    // roll, que e O(segmentos) por seal e O(segmentos²) no total. Ou seja,
    // encolher o segmento pode limitar-se a MUDAR o quadratico de sitio: de
    // "entradas por segmento" para "numero de segmentos". Se assim for, esta
    // curva (~100 segmentos em vez de ~7) tem de cair. Se ficar plana, a
    // recomendacao de encolher o segmento aguenta-se.
    let minusculo = curva("segmento 256 KiB (~100 seals — testa o quadratico DOS SEGMENTOS)", 256 << 10);

    println!("── 2. Efeito das duas mitigacoes (debito total) ──────────────────\n");
    let total = |c: &Vec<f64>| N as f64 / c.iter().map(|d| JANELA as f64 / d).sum::<f64>();
    let a = total(&grande);
    println!("  1 escritor  · segmento   1 GiB: {a:>9.0} app/s  (pior caso)");
    let b = total(&pequeno);
    println!("  1 escritor  · segmento   4 MiB: {b:>9.0} app/s");
    let m = total(&minusculo);
    println!("  1 escritor  · segmento 256 KiB: {m:>9.0} app/s");
    let c = concorrente("8 escritores · segmento 1 GiB", 1 << 30, 8);
    let d = concorrente("8 escritores · segmento 4 MiB", 4 << 20, 8);

    println!("\n── 3. Veredicto ─────────────────────────────────────────────────\n");
    println!("  ganho so por segmento menor      : {:.1}x", b / a);
    println!("  ganho so por escrita concorrente : {:.1}x", c / a);
    println!("  ganho pelas duas juntas          : {:.1}x", d / a);
    println!();
    let queda = grande[0] / grande[grande.len() - 1];
    if queda > 3.0 {
        println!("  CONFIRMADO: com segmento grande e escritor sincrono, o debito cai");
        println!("  {queda:.1}x ao longo de apenas {N} registos. A curva e o custo da copia");
        println!("  COW do indice (lib.rs:938) a crescer com as entradas acumuladas.");
    } else {
        println!("  A degradacao NAO se reproduziu nesta maquina/escala ({queda:.1}x).");
    }
    println!();

    // Contraprova: encolher o segmento resolve, ou so muda o quadratico de
    // sitio (entradas por segmento -> numero de segmentos)?
    let queda_min = minusculo[0] / minusculo[minusculo.len() - 1];
    if queda_min > 2.0 {
        println!("  ATENCAO: a curva de 256 KiB tambem cai ({queda_min:.1}x) com ~100 seals.");
        println!("  Encolher o segmento NAO resolve — move o quadratico das entradas por");
        println!("  segmento para o NUMERO de segmentos (roll_segment clona o vetor de");
        println!("  selados). Existe um tamanho otimo, e os dois extremos sao maus.");
    } else {
        println!("  Contraprova OK: a curva de 256 KiB fica plana ({queda_min:.1}x) mesmo com");
        println!("  ~100 seals. Encolher o segmento resolve de facto; nao ha um segundo");
        println!("  quadratico escondido no numero de segmentos a esta escala.");
    }
    println!();
    println!("  Notas para ler os numeros:");
    println!("   - o quadratico e por SEGMENTO, nao pelo log todo: selar reinicia o indice;");
    println!("   - o default de producao e segment_max_bytes = 256 MiB, MAIOR que os 4 MiB");
    println!("     testados aqui, logo o efeito em producao e PIOR que a linha do 4 MiB;");
    println!("   - o batching do worker vai ate 128 comandos: quem escreve de forma");
    println!("     sincrona (um append, esperar o ACK, repetir) paga o pior caso sozinho.");
    println!();
}
