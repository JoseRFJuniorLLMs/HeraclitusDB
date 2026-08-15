//! A/B: busca exata Top-M na variedade de produto — CPU vs GPU (wgpu).
//!
//! Mesmo filtro que já reprovou o `mmap` e aprovou (com ganho pequeno) a
//! compressão: **ligação mínima, medição real, decisão pelos números**.
//!
//! A pergunta operacional não é "a GPU é mais rápida?" — é **"a partir de que
//! tamanho de coleção a GPU compensa o custo de transferir os vetores e
//! despachar o shader?"**. Abaixo desse ponto, o `search_exact_gpu` do
//! `VectorIndex` seria uma regressão disfarçada de otimização.
//!
//! ```bash
//! cargo bench -p heraclitus-gpu --bench gpu_vs_cpu --features gpu
//! ```
//!
//! Sem a feature `gpu` o benchmark diz-o e sai — não finge medir.

#[cfg(not(feature = "gpu"))]
fn main() {
    eprintln!("compile com --features gpu; sem ela nao ha caminho GPU para medir");
}

#[cfg(feature = "gpu")]
fn main() {
    
    use heraclitus_gpu::{topm_product_cpu, topm_product_gpu, ProductSig};
    use std::time::Instant;

    // Assinatura default da variedade: H32 x S8 x E8 = 48 dims (a mesma que o
    // boot do servidor anuncia).
    let sig = ProductSig::default();
    let dim = sig.a + sig.b + sig.c;

    // Gerador determinístico: o benchmark tem de ser reproduzível entre
    // execuções, senão a comparação anda com o ruído dos dados.
    let mut estado = 0x2545_F491_4F6C_DD1Du64;
    let mut proximo = move || {
        estado ^= estado << 13;
        estado ^= estado >> 7;
        estado ^= estado << 17;
        ((estado >> 11) as f32 / (1u64 << 53) as f32) * 0.2 - 0.1
    };

    println!("\nA/B busca exata Top-M — variedade H{}xS{}xE{} ({dim} dims)\n", sig.a, sig.b, sig.c);
    println!("  {:>10}  {:>12}  {:>12}  {:>8}", "vetores", "CPU", "GPU", "ganho");

    const M: usize = 10;
    const SCALE: f32 = 10_000.0;

    for &n in &[1_000usize, 10_000, 50_000, 200_000, 500_000] {
        let query: Vec<f32> = (0..dim).map(|_| proximo()).collect();
        let vectors: Vec<f32> = (0..n * dim).map(|_| proximo()).collect();

        // Aquecimento: a primeira chamada da GPU paga a criação do pipeline.
        let _ = topm_product_cpu(&query, &vectors, &sig, M, SCALE);
        let quente = topm_product_gpu(&query, &vectors, &sig, M, SCALE);
        if quente.is_none() {
            println!("  sem adaptador GPU — nada a medir");
            return;
        }

        let reps = if n > 100_000 { 3 } else { 10 };

        let t0 = Instant::now();
        let mut ancora = 0usize;
        for _ in 0..reps {
            ancora += topm_product_cpu(&query, &vectors, &sig, M, SCALE).len();
        }
        let t_cpu = t0.elapsed() / reps;

        let t0 = Instant::now();
        let mut ancora_g = 0usize;
        for _ in 0..reps {
            ancora_g += topm_product_gpu(&query, &vectors, &sig, M, SCALE)
                .expect("adaptador desapareceu a meio")
                .len();
        }
        let t_gpu = t0.elapsed() / reps;
        assert_eq!(ancora, ancora_g, "os dois caminhos devolvem M candidatos");

        println!(
            "  {n:>10}  {:>12.2?}  {:>12.2?}  {:>7.2}x",
            t_cpu,
            t_gpu,
            t_cpu.as_secs_f64() / t_gpu.as_secs_f64()
        );
    }

    println!(
        "\n  ganho > 1.0 = GPU mais rapida. Inclui a transferencia dos vetores\n  \
         a cada chamada, que e o custo real de quem chama sem manter\n  \
         a colecao residente na GPU.\n"
    );
}
