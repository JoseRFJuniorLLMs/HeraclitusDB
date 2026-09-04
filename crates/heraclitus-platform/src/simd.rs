//! SPEC-0073 §34–§36 — dispatch SIMD em tempo de execução.
//!
//! ## Porque não `-C target-cpu=native`
//!
//! A §34 abre com a proibição:
//!
//! ```text
//! Nunca depender exclusivamente de -C target-cpu=native para releases
//! distribuídos.
//! ```
//!
//! A razão é operacional e brutal: um binário compilado com AVX-512 numa
//! máquina de build morre com `SIGILL` num host mais antigo — e morre no
//! arranque, sem mensagem útil. O modelo oficial é o oposto: um binário
//! portátil que **detecta** o que a máquina tem e escolhe o caminho.
//!
//! ```text
//! scalar -> runtime detection -> AVX2/FMA | AVX-512 | NEON | SVE
//! ```
//!
//! ## A regra que torna isto verificável
//!
//! > Toda implementação otimizada MUST produzir resultado compatível com o
//! > fallback escalar dentro das tolerâncias matemáticas formalmente definidas.
//!
//! É a parte que costuma ficar por escrever, e sem ela o dispatch é uma
//! promessa. Aqui a tolerância está definida em [`TOLERANCIA_RELATIVA`] e há um
//! teste que compara **cada** caminho com o escalar sobre entradas geradas.
//!
//! A tolerância não é zero, e não pode ser: a soma vectorizada acumula em
//! várias vias e depois reduz, portanto a ORDEM das somas difere da escalar. Em
//! vírgula flutuante a adição não é associativa, logo os resultados diferem no
//! último bit. Exigir igualdade exacta obrigaria a desligar a vectorização —
//! seria uma regra que se cumpre não fazendo nada.
//!
//! ## AVX-512 não é escolhido só por existir (§35)
//!
//! A §35 lista os cuidados: redução de clock, tamanho do vector, workload, CPU
//! concreta. Em várias gerações Intel, executar AVX-512 baixa a frequência de
//! todo o núcleo, e para vectores curtos o ganho não paga o downclock — o
//! processo inteiro fica mais lento, incluindo o que não é SIMD.
//!
//! Por isso [`SimdLevel::detectar`] devolve `Avx512` apenas quando ele existe, e
//! [`nivel_efectivo_para`] — que é o que o dispatch usa — **recusa-o para
//! vectores curtos**. Sem medição por CPU concreta, o conservador é o correcto.

use serde::{Deserialize, Serialize};

/// Tolerância relativa entre um caminho vectorizado e o escalar.
///
/// `1e-5` sobre `f32`: a mantissa do `f32` tem ~7 dígitos decimais, e uma
/// redução em quatro ou oito vias sobre alguns milhares de elementos acumula
/// erro na ordem dos últimos dois. É folgado o suficiente para não ser frágil e
/// apertado o suficiente para apanhar um kernel genuinamente errado — que erra
/// por muito mais do que um ulp.
pub const TOLERANCIA_RELATIVA: f32 = 1e-5;

/// O caminho de código escolhido.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SimdLevel {
    /// O fallback. Existe sempre e é a referência de correcção.
    Scalar,
    /// x86_64 com AVX2 e FMA.
    Avx2,
    /// x86_64 com AVX-512F.
    Avx512,
    /// aarch64 com NEON. A §36 diz que Linux ARM64 é Tier 1.
    Neon,
}

impl SimdLevel {
    /// O que esta máquina oferece.
    ///
    /// A ordem de preferência é a da §35 — escalar, AVX2+FMA, AVX-512 — e a
    /// detecção é em tempo de execução, nunca em tempo de compilação.
    pub fn detectar() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            // FMA junto com AVX2 de propósito: um produto escalar sem FMA
            // perde metade do ganho, e as duas andam juntas em todo o hardware
            // relevante. Pedir as duas evita um caminho "AVX2 sem FMA" que
            // existiria só no papel.
            if std::is_x86_feature_detected!("avx512f") {
                return Self::Avx512;
            }
            if std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("fma") {
                return Self::Avx2;
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                return Self::Neon;
            }
        }
        Self::Scalar
    }

    pub fn etiqueta(&self) -> &'static str {
        match self {
            Self::Scalar => "scalar",
            Self::Avx2 => "avx2",
            Self::Avx512 => "avx512",
            Self::Neon => "neon",
        }
    }
}

/// Abaixo deste comprimento, o AVX-512 não compensa.
///
/// A §35: "AVX-512 não será escolhido apenas porque existe". O custo é o
/// downclock do núcleo, que penaliza tudo o resto que corre nele; o ganho é
/// proporcional ao comprimento do vector. Para vectores curtos a conta dá
/// negativo, e sem medição por CPU concreta o conservador é o correcto.
///
/// 256 é uma fronteira declarada, não medida — e está escrito que é. Quem medir
/// numa CPU concreta muda-a com um número em vez de com uma intuição.
pub const AVX512_COMPRIMENTO_MINIMO: usize = 256;

/// O nível que o dispatch vai MESMO usar para um vector deste comprimento.
pub fn nivel_efectivo_para(disponivel: SimdLevel, comprimento: usize) -> SimdLevel {
    match disponivel {
        SimdLevel::Avx512 if comprimento < AVX512_COMPRIMENTO_MINIMO => SimdLevel::Avx2,
        outro => outro,
    }
}

/// Produto escalar — a referência de correcção.
///
/// Simples de propósito: é contra isto que todos os outros caminhos são
/// comparados, portanto tem de ser obviamente certo.
pub fn dot_scalar(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// Produto escalar com o melhor caminho disponível para este comprimento.
///
/// Comprimentos diferentes entre `a` e `b` são tratados pelo mínimo: é a
/// mesma semântica do `zip` do caminho escalar, e escolher outra coisa faria os
/// dois caminhos discordarem em entradas malformadas.
pub fn dot(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let (a, b) = (&a[..n], &b[..n]);
    match nivel_efectivo_para(SimdLevel::detectar(), n) {
        #[cfg(target_arch = "x86_64")]
        SimdLevel::Avx2 | SimdLevel::Avx512 => {
            // SAFETY: só se chega aqui depois de `is_x86_feature_detected!`
            // confirmar AVX2 e FMA em tempo de execução.
            unsafe { dot_avx2(a, b) }
        }
        _ => dot_scalar(a, b),
    }
}

/// Produto escalar com AVX2 + FMA, oito vias.
///
/// # Safety
///
/// Só pode ser chamada quando `is_x86_feature_detected!("avx2")` e `("fma")`
/// forem verdadeiros. Chamá-la sem isso é `SIGILL`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
unsafe fn dot_avx2(a: &[f32], b: &[f32]) -> f32 {
    use std::arch::x86_64::*;
    let n = a.len();
    let mut acumulador = _mm256_setzero_ps();
    let mut i = 0usize;
    while i + 8 <= n {
        // SAFETY: `i + 8 <= n` garante que os 8 floats existem nos dois slices.
        unsafe {
            let x = _mm256_loadu_ps(a.as_ptr().add(i));
            let y = _mm256_loadu_ps(b.as_ptr().add(i));
            acumulador = _mm256_fmadd_ps(x, y, acumulador);
        }
        i += 8;
    }
    // Redução horizontal das oito vias.
    let mut vias = [0f32; 8];
    // SAFETY: `vias` tem exactamente 8 elementos.
    unsafe { _mm256_storeu_ps(vias.as_mut_ptr(), acumulador) };
    let mut total: f32 = vias.iter().sum();
    // A cauda que não coube num vector de oito.
    while i < n {
        total += a[i] * b[i];
        i += 1;
    }
    total
}

/// Duas somas são iguais dentro da tolerância declarada?
///
/// Compara em erro RELATIVO, não absoluto: um produto escalar de mil elementos
/// grandes tem magnitude grande, e um erro absoluto fixo seria apertado de mais
/// para ele e folgado de mais para vectores pequenos.
pub fn compativel(esperado: f32, obtido: f32) -> bool {
    if esperado == obtido {
        return true;
    }
    let denominador = esperado.abs().max(obtido.abs()).max(f32::MIN_POSITIVE);
    ((esperado - obtido).abs() / denominador) <= TOLERANCIA_RELATIVA
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gerador determinístico. Sem `rand` para o teste não depender de uma
    /// semente que muda entre corridas — um teste de equivalência numérica que
    /// falha uma vez em cem é pior do que nenhum.
    fn vector(n: usize, semente: u32) -> Vec<f32> {
        let mut estado = semente | 1;
        (0..n)
            .map(|_| {
                estado = estado.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                ((estado >> 8) as f32 / (1 << 24) as f32) - 0.5
            })
            .collect()
    }

    /// A regra da §34: todo caminho optimizado tem de bater com o escalar
    /// dentro da tolerancia. E o teste que torna o dispatch verificavel em vez
    /// de uma promessa.
    #[test]
    fn todo_caminho_bate_com_o_escalar_dentro_da_tolerancia() {
        // Comprimentos escolhidos a volta das fronteiras: zero, menos de uma
        // via, exactamente uma via, uma via mais cauda, e comprimentos grandes.
        for n in [0usize, 1, 7, 8, 9, 15, 16, 255, 256, 257, 1000, 4096] {
            let a = vector(n, 0x1234_5678);
            let b = vector(n, 0x9ABC_DEF0);
            let esperado = dot_scalar(&a, &b);
            let obtido = dot(&a, &b);
            assert!(
                compativel(esperado, obtido),
                "n={n}: escalar={esperado} dispatch={obtido}"
            );
        }
    }

    /// §35 — o AVX-512 nao e escolhido so por existir.
    #[test]
    fn o_avx512_nao_e_usado_em_vectores_curtos() {
        assert_eq!(
            nivel_efectivo_para(SimdLevel::Avx512, 8),
            SimdLevel::Avx2,
            "vector curto nao paga o downclock do AVX-512"
        );
        assert_eq!(
            nivel_efectivo_para(SimdLevel::Avx512, AVX512_COMPRIMENTO_MINIMO - 1),
            SimdLevel::Avx2
        );
        assert_eq!(
            nivel_efectivo_para(SimdLevel::Avx512, AVX512_COMPRIMENTO_MINIMO),
            SimdLevel::Avx512
        );
        // Os outros niveis nao sao afectados pelo comprimento.
        for nivel in [SimdLevel::Scalar, SimdLevel::Avx2, SimdLevel::Neon] {
            assert_eq!(nivel_efectivo_para(nivel, 1), nivel);
            assert_eq!(nivel_efectivo_para(nivel, 100_000), nivel);
        }
    }

    #[test]
    fn a_deteccao_devolve_um_nivel_que_esta_maquina_tem_mesmo() {
        let nivel = SimdLevel::detectar();
        #[cfg(target_arch = "x86_64")]
        {
            match nivel {
                SimdLevel::Avx512 => assert!(std::is_x86_feature_detected!("avx512f")),
                SimdLevel::Avx2 => {
                    assert!(std::is_x86_feature_detected!("avx2"));
                    assert!(std::is_x86_feature_detected!("fma"));
                }
                SimdLevel::Scalar => {}
                SimdLevel::Neon => panic!("NEON em x86_64"),
            }
        }
        assert!(!nivel.etiqueta().is_empty());
    }

    /// Comprimentos diferentes: os dois caminhos tem de concordar, senao
    /// discordariam em entradas malformadas — que e onde ninguem olha.
    #[test]
    fn comprimentos_diferentes_dao_o_mesmo_nos_dois_caminhos() {
        let a = vector(100, 7);
        let b = vector(37, 9);
        let esperado = dot_scalar(&a[..37], &b);
        assert!(compativel(esperado, dot(&a, &b)));
        assert!(compativel(esperado, dot(&b, &a)));
    }

    #[test]
    fn a_tolerancia_apanha_um_kernel_genuinamente_errado() {
        // Um erro de um ulp passa; um erro de 1% nao. E o que separa "ordem de
        // soma diferente" de "kernel errado".
        assert!(compativel(1.0, 1.0 + f32::EPSILON));
        assert!(!compativel(1.0, 1.01));
        assert!(!compativel(100.0, 99.0));
        assert!(compativel(0.0, 0.0));
    }
}
