//! SPEC-026 — capability catalog.
//!
//! A single in-memory inventory of the host's real hardware/feature profile,
//! interrogated by the planner before choosing a physical strategy (SIMD vs
//! GPU vs plain imperative). Detection is conservative and honest: features we
//! cannot reliably probe from `std` are reported as `false` rather than
//! optimistically assumed.

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CapabilityCatalog {
    /// CPU exposes wide vector registers (AVX2+ on x86_64).
    pub supports_hardware_vector_simd: bool,
    /// A massive-compute runtime (CUDA/Vulkan) is present. Not probed from std.
    pub supports_gpu_acceleration: bool,
    /// Multi-socket NUMA topology. Not probed from std.
    pub supports_numa: bool,
    pub logical_cpus: usize,
    pub registered_compression_profiles: Vec<String>,
}

#[cfg(target_arch = "x86_64")]
fn detect_simd() -> bool {
    std::arch::is_x86_feature_detected!("avx2")
}
#[cfg(not(target_arch = "x86_64"))]
fn detect_simd() -> bool {
    false
}

impl CapabilityCatalog {
    /// Probe the real host. GPU stays `false` (no reliable std probe) — the
    /// planner treats absence as "use the CPU path", which is always correct.
    ///
    /// SPEC-0073 §6 — **este catálogo e o `PlatformCapabilities` respondiam à
    /// mesma pergunta com números diferentes.**
    ///
    /// Havia dois inventários de capacidades a coexistir: este (SPEC-026) e o
    /// do `heraclitus-platform` (SPEC-0073). Este dizia `supports_numa: false`
    /// sempre, mesmo numa máquina com quatro nós NUMA que o outro detectava
    /// bem; e o `logical_cpus` vinha de `available_parallelism()`, que é o
    /// número do HOST.
    ///
    /// A segunda discrepância é a que custava. É ESTE catálogo — e não o do
    /// `heraclitus-platform` — que o `heraclitus-analytics` consulta para
    /// decidir quantos workers abrir (`vectorized.rs`, `run_filter_parallel` e
    /// o executor de projecções). Num container com `cpu.max` a valer 2 cores
    /// num host de 64, abria 64 threads para uma fatia de 2: a mesma fatia
    /// repartida por 32× mais threads, com toda a troca de contexto e memória
    /// por thread que isso traz.
    ///
    /// Passa a delegar. O `heraclitus-platform` não depende de nenhum crate
    /// deste repositório, por isso a dependência é acíclica, e a duplicação —
    /// que era a causa de os dois números poderem divergir — deixa de existir.
    pub fn detect() -> Self {
        let plataforma = heraclitus_platform::detect_capabilities();
        Self {
            supports_hardware_vector_simd: detect_simd(),
            supports_gpu_acceleration: false,
            // Detectado a sério em Linux (`/sys/devices/system/node`); noutros
            // sistemas o `heraclitus-platform` devolve 1, e "1 nó" não é NUMA.
            supports_numa: plataforma.numa_nodes > 1,
            // O número EFECTIVO: mínimo entre o que o SO reporta, o que o
            // cpuset permite e o que a quota paga.
            logical_cpus: plataforma.logical_cpus,
            registered_compression_profiles: vec![
                "dictionary".into(),
                "delta".into(),
                "delta-of-delta".into(),
                "frame-of-reference".into(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_reports_sane_host() {
        let c = CapabilityCatalog::detect();
        assert!(c.logical_cpus >= 1);
        assert!(c
            .registered_compression_profiles
            .contains(&"delta-of-delta".to_string()));
    }
}

#[cfg(test)]
mod testes_unificacao_spec0073 {
    use super::*;

    /// SPEC-0073 §6 — os dois inventarios tem de dar a MESMA resposta.
    ///
    /// Coexistiam dois catalogos de capacidades e divergiam em dois campos:
    /// este dizia `supports_numa: false` sempre, e contava os CPUs do HOST em
    /// vez dos efectivos. E este — nao o outro — que o `heraclitus-analytics`
    /// consulta para dimensionar workers.
    ///
    /// Este teste falha se alguem voltar a duplicar a deteccao em vez de
    /// delegar.
    #[test]
    fn o_catalogo_concorda_com_a_plataforma() {
        let catalogo = CapabilityCatalog::detect();
        let plataforma = heraclitus_platform::detect_capabilities();

        assert_eq!(
            catalogo.logical_cpus, plataforma.logical_cpus,
            "os dois inventarios discordam no numero de CPUs"
        );
        assert_eq!(
            catalogo.supports_numa,
            plataforma.numa_nodes > 1,
            "os dois inventarios discordam sobre NUMA"
        );
    }

    /// O numero que o planeador usa nunca pode ultrapassar o que o cgroup
    /// permite — e a razao de ser da delegacao.
    #[test]
    fn o_numero_de_cpus_nunca_ultrapassa_o_limite_efectivo() {
        let catalogo = CapabilityCatalog::detect();
        let plataforma = heraclitus_platform::detect_capabilities();
        assert!(
            catalogo.logical_cpus <= plataforma.host_cpus.max(1),
            "o catalogo reporta {} CPUs num host de {}",
            catalogo.logical_cpus,
            plataforma.host_cpus
        );
        assert!(catalogo.logical_cpus >= 1);
    }
}
