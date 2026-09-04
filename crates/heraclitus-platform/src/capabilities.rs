//! Hardware and operating system capability detection.
//!
//! Provides dynamic cataloging of kernel version, processor features,
//! NUMA nodes, cgroups constraints, and supported I/O primitives.

use crate::cgroup::{detect_cgroup_limits, EffectiveResourceLimits};
use serde::{Deserialize, Serialize};

/// Catalog of platform and hardware capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    pub os: String,
    pub arch: String,
    pub kernel_version: Option<String>,
    pub numa_nodes: usize,
    /// SPEC-0073 §22 — a topologia NUMA real, não só a contagem de nós.
    ///
    /// `numa_nodes` responde "quantos"; isto responde "quais CPUs" e "quanta
    /// memória", que é o que a §24 precisa para decidir onde correr um worker.
    #[serde(default = "crate::numa::NumaTopology::uniforme")]
    pub numa: crate::numa::NumaTopology,
    /// SPEC-0073 §46/§47 — os CPUs que este processo pode **realmente** usar.
    ///
    /// É o mínimo entre o que o SO reporta e o que o cgroup permite (cpuset e
    /// quota). Era o número do HOST, e é este campo que alimenta o
    /// dimensionamento de workers no `heraclitus-analytics` — num container
    /// com `cpu.max` a valer 2 cores num host de 64, abriam-se 64 workers para
    /// uma fatia de 2. O host continua visível em [`Self::host_cpus`].
    pub logical_cpus: usize,
    /// Os CPUs lógicos da máquina, sem descontar limites. Só para relatório:
    /// dimensionar por este número é o erro que o `logical_cpus` corrige.
    #[serde(default)]
    pub host_cpus: usize,
    pub io_uring_available: bool,
    pub cgroups_v2_active: bool,
    pub effective_limits: EffectiveResourceLimits,
    pub avx2: bool,
    pub avx512f: bool,
    pub neon: bool,
}

/// Detects capabilities of the current execution environment.
pub fn detect_capabilities() -> PlatformCapabilities {
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let host_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let effective_limits = detect_cgroup_limits();
    let cgroups_v2_active = effective_limits.cgroups_v2_active;
    // SPEC-0073 §46 — "o runtime MUST preferir limites efetivos do cgroup
    // quando mais restritivos que recursos fisicos".
    let logical_cpus = effective_limits.effective_cpus(host_cpus);
    // SPEC-0073 §22 — topologia real, nao so a contagem.
    let numa = crate::numa::detect_numa_topology();

    #[cfg(target_os = "linux")]
    let (kernel_version, io_uring_available) = (
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|s| s.trim().to_string()),
        check_linux_io_uring(),
    );

    #[cfg(not(target_os = "linux"))]
    let (kernel_version, io_uring_available) = (None, false);

    // Derivado da topologia e nao contado outra vez. Contar de novo seria criar
    // duas fontes para o mesmo facto, que foi exactamente o erro dos dois
    // catalogos de capacidades (§6) — e que divergiam.
    let numa_nodes = numa.nodes.len();

    #[cfg(target_arch = "x86_64")]
    let (avx2, avx512f) = (
        std::is_x86_feature_detected!("avx2"),
        std::is_x86_feature_detected!("avx512f"),
    );
    #[cfg(not(target_arch = "x86_64"))]
    let (avx2, avx512f) = (false, false);

    #[cfg(target_arch = "aarch64")]
    let neon = std::arch::is_aarch64_feature_detected!("neon");
    #[cfg(not(target_arch = "aarch64"))]
    let neon = false;

    PlatformCapabilities {
        os,
        arch,
        kernel_version,
        numa_nodes,
        numa,
        logical_cpus,
        host_cpus,
        io_uring_available,
        cgroups_v2_active,
        effective_limits,
        avx2,
        avx512f,
        neon,
    }
}

#[cfg(target_os = "linux")]
fn check_linux_io_uring() -> bool {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok();
    let sysctl = std::fs::read_to_string("/proc/sys/kernel/io_uring_disabled").ok();
    io_uring_disponivel(kernel.as_deref(), sysctl.as_deref())
}

/// SPEC-0073 §6.3 — o io_uring está disponível?
///
/// A versão anterior era FAIL-OPEN, e de uma maneira que não salta à vista:
///
/// ```text
/// if let Ok(c) = read("/proc/sys/kernel/io_uring_disabled") { if c == "1" || "2" { return false } }
/// true
/// ```
///
/// Aquele ficheiro só existe a partir do kernel 6.6. Num kernel 5.0 — que não
/// tem io_uring nenhum — a leitura falha, o `if` não corre, e a função devolve
/// `true`. Exactamente o caso em que a resposta certa é "não" era o caso que
/// devolvia "sim". Anunciar uma capacidade que o kernel não tem é a direcção
/// errada para um erro de detecção: quem a consome vai tentar usá-la.
///
/// Passa a exigir as duas coisas: kernel >= 5.6 (onde o io_uring entrou) E o
/// sysctl a não o desligar. É pura para poder ser testada com `/proc`
/// simulado, em qualquer sistema operativo — a versão anterior só podia ser
/// verificada em Linux, e por isso nunca foi.
pub fn io_uring_disponivel(osrelease: Option<&str>, io_uring_disabled: Option<&str>) -> bool {
    // `2` proíbe a toda a gente; `1` só permite a quem tem a capability. Nem
    // um nem outro é uma disponibilidade em que se possa confiar.
    if let Some(valor) = io_uring_disabled {
        let valor = valor.trim();
        if valor == "1" || valor == "2" {
            return false;
        }
    }
    let Some(versao) = osrelease else {
        // Sem osrelease não há como afirmar nada. Não afirmar é dizer "não".
        return false;
    };
    versao_minima(versao, 5, 6)
}

/// `major.minor` do `osrelease` >= o mínimo pedido.
///
/// O `osrelease` traz sufixos (`6.8.0-45-generic`, `5.15.0-1051-azure`), por
/// isso só os dois primeiros números são lidos, e um formato que não se deixe
/// ler devolve `false` — a mesma direcção conservadora do resto da função.
fn versao_minima(osrelease: &str, major_min: u32, minor_min: u32) -> bool {
    let mut partes = osrelease.trim().split(['.', '-', '+']);
    let Some(Ok(major)) = partes.next().map(str::parse::<u32>) else {
        return false;
    };
    let minor = partes
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0);
    (major, minor) >= (major_min, minor_min)
}

impl PlatformCapabilities {
    /// Produces a compact 1-line log string suitable for server boot.
    pub fn summary_line(&self) -> String {
        format!(
            "OS: {}/{} | Kernel: {} | CPUs: {} (host {}) | NUMA: {}{} | cgroups_v2: {} | io_uring: {} | simd: {}",
            self.os,
            self.arch,
            self.kernel_version.as_deref().unwrap_or("unknown"),
            self.logical_cpus,
            self.host_cpus,
            self.numa_nodes,
            if self.numa.e_multi_no() {
                // Num host multi-NUMA os detalhes deixam de ser curiosidade:
                // e o que decide onde correm os workers (§24).
                format!(
                    " ({})",
                    self.numa
                        .nodes
                        .iter()
                        .map(|n| format!("n{}:{}cpu", n.id, n.cpus.len()))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            } else {
                String::new()
            },
            if self.cgroups_v2_active { "yes" } else { "no" },
            if self.io_uring_available {
                "available"
            } else {
                "no"
            },
            self.simd_line()
        )
    }

    /// SPEC-0073 §6.4 — as extensões SIMD detectadas.
    ///
    /// Eram detectadas e não eram ditas: `avx2`, `avx512f` e `neon` viviam na
    /// struct e nunca chegavam à linha de arranque. Uma capacidade que se
    /// mede e não se reporta é indistinguível, para quem opera, de uma que não
    /// se mede.
    pub fn simd_line(&self) -> String {
        let mut presentes = Vec::new();
        if self.avx2 {
            presentes.push("avx2");
        }
        if self.avx512f {
            presentes.push("avx512f");
        }
        if self.neon {
            presentes.push("neon");
        }
        if presentes.is_empty() {
            "none".to_string()
        } else {
            presentes.join("+")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_basic_capabilities() {
        let caps = detect_capabilities();
        assert!(!caps.os.is_empty());
        assert!(!caps.arch.is_empty());
        assert!(caps.logical_cpus >= 1);
        let summary = caps.summary_line();
        assert!(summary.contains("OS:"));
    }
}

#[cfg(test)]
mod testes_spec0073 {
    use super::*;

    #[test]
    fn um_kernel_sem_io_uring_nao_pode_ser_dado_como_disponivel() {
        // O caso que a versao anterior errava: o sysctl so existe a partir do
        // 6.6, portanto num kernel 5.0 a leitura falha e a funcao devolvia
        // `true` — anunciando uma capacidade que o kernel nao tem.
        assert!(!io_uring_disponivel(Some("5.0.0-generic"), None));
        assert!(!io_uring_disponivel(Some("4.19.0"), None));
        assert!(!io_uring_disponivel(Some("5.5.19"), None));
    }

    #[test]
    fn um_kernel_com_io_uring_e_sem_sysctl_e_disponivel() {
        // 5.6 e a versao em que o io_uring entrou; entre 5.6 e 6.5 o sysctl
        // ainda nao existe, e ai a ausencia significa mesmo "nao desligado".
        assert!(io_uring_disponivel(Some("5.6.0"), None));
        assert!(io_uring_disponivel(Some("6.8.0-45-generic"), None));
        assert!(io_uring_disponivel(Some("6.8.0-45-generic"), Some("0\n")));
    }

    #[test]
    fn o_sysctl_a_desligar_manda_sobre_a_versao_do_kernel() {
        assert!(!io_uring_disponivel(Some("6.8.0"), Some("1\n")));
        assert!(!io_uring_disponivel(Some("6.8.0"), Some("2")));
    }

    #[test]
    fn sem_osrelease_nao_se_afirma_nada() {
        assert!(!io_uring_disponivel(None, None));
        assert!(!io_uring_disponivel(Some("nao-e-uma-versao"), None));
        assert!(!io_uring_disponivel(Some(""), Some("0")));
    }

    #[test]
    fn a_linha_de_arranque_diz_o_simd() {
        let mut caps = detect_capabilities();
        assert!(
            caps.summary_line().contains("simd:"),
            "a linha de arranque tem de reportar o SIMD: {}",
            caps.summary_line()
        );
        caps.avx2 = false;
        caps.avx512f = false;
        caps.neon = false;
        assert_eq!(caps.simd_line(), "none");
        caps.avx2 = true;
        assert_eq!(caps.simd_line(), "avx2");
        caps.avx512f = true;
        assert_eq!(caps.simd_line(), "avx2+avx512f");
    }
}

#[cfg(test)]
mod testes_numa_no_catalogo {
    use super::*;

    /// SPEC-0073 §22 — a contagem de nos e DERIVADA da topologia.
    ///
    /// Contar directorios em sysfs e depois ler a topologia noutro sitio daria
    /// duas fontes para o mesmo facto, e duas fontes divergem. E o mesmo erro
    /// dos dois catalogos de capacidades da §6, que ja divergiam em producao.
    #[test]
    fn a_contagem_de_nos_nao_pode_divergir_da_topologia() {
        let caps = detect_capabilities();
        assert_eq!(
            caps.numa_nodes,
            caps.numa.nodes.len(),
            "numa_nodes e numa.nodes discordam — sao duas fontes para o mesmo facto"
        );
        assert!(caps.numa_nodes >= 1, "uma maquina tem pelo menos um no");
    }

    #[test]
    fn a_linha_de_arranque_so_detalha_numa_quando_ha_o_que_detalhar() {
        let caps = detect_capabilities();
        let linha = caps.summary_line();
        assert!(linha.contains("NUMA:"));
        if !caps.numa.e_multi_no() {
            assert!(
                !linha.contains("n0:"),
                "numa uniforme nao tem detalhe util a dar: {linha}"
            );
        }
    }
}
