//! SPEC-0073 §51–§54 — a configuração `[linux]`, a semântica de `auto` e os
//! overrides de operação.
//!
//! ## O que `auto` significa, e o que não significa
//!
//! A §52 define-o e proíbe a leitura preguiçosa:
//!
//! ```text
//! auto = detectar capacidade -> consultar política qualificada -> escolher
//!        backend comprovadamente seguro
//!
//! NÃO:  experimentar aleatoriamente em produção.
//! ```
//!
//! A "política qualificada" é a parte que se esquece. Detectar que o io_uring
//! existe não autoriza usá-lo: o I-5 exige benchmark, correcção, qualificação
//! de crash e gate de desempenho antes de qualquer promoção. Enquanto esses não
//! existirem, `auto` **resolve para o baseline** — e é isso que
//! [`ResolvedLinuxRuntime`] faz, com o motivo escrito.
//!
//! Um `auto` que escolhesse o io_uring por ele estar disponível seria
//! exactamente "experimentar em produção", com a agravante de o fazer sem
//! ninguém ter pedido.
//!
//! ## Override sem recompilar (§53)
//!
//! ```text
//! HERACLITUS_IO_BACKEND=portable|uring
//! HERACLITUS_NUMA=auto|off
//! HERACLITUS_MMAP_ADVICE=auto|off
//! HERACLITUS_REUSEPORT=auto|on|off
//! HERACLITUS_ALLOCATOR=auto|system
//! ```
//!
//! O ambiente ganha à configuração, e a configuração ganha ao default. É a
//! ordem que serve o diagnóstico: quem está a debugar às 3 da manhã mexe numa
//! variável de ambiente, não num ficheiro que tem de distribuir.

use serde::{Deserialize, Serialize};

/// Uma escolha de três estados: automático, ligado ou desligado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Tristate {
    #[default]
    Auto,
    On,
    Off,
}

impl Tristate {
    fn do_texto(valor: &str) -> Option<Self> {
        match valor.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "on" | "true" | "1" | "yes" => Some(Self::On),
            "off" | "false" | "0" | "no" => Some(Self::Off),
            _ => None,
        }
    }
}

/// Backend de I/O do log (§51 `[linux.io] backend`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IoBackendChoice {
    #[default]
    Auto,
    Portable,
    Uring,
}

impl IoBackendChoice {
    fn do_texto(valor: &str) -> Option<Self> {
        match valor.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "portable" | "portable-file-io" => Some(Self::Portable),
            "uring" | "io_uring" | "io-uring" => Some(Self::Uring),
            _ => None,
        }
    }
}

/// `[linux.io]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LinuxIoConfig {
    pub backend: IoBackendChoice,
    pub queue_depth: u32,
}

impl Default for LinuxIoConfig {
    fn default() -> Self {
        Self {
            backend: IoBackendChoice::Auto,
            queue_depth: 32,
        }
    }
}

/// `[linux.memory]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LinuxMemoryConfig {
    pub mmap_advice: Tristate,
    pub prefetch_window_mb: u32,
    pub hugepages: Tristate,
}

impl Default for LinuxMemoryConfig {
    fn default() -> Self {
        Self {
            mmap_advice: Tristate::Auto,
            prefetch_window_mb: 64,
            hugepages: Tristate::Auto,
        }
    }
}

/// `[linux.cpu]` — a política de afinidade da §23.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AffinityPolicy {
    /// Sem pinning. É o que a §23 quer dizer com "não aplicar pinning cego":
    /// numa máquina de um nó, ou sem topologia conhecida, não há decisão a
    /// tomar.
    Off,
    /// Pinning só quando a topologia o justifica (multi-NUMA).
    #[default]
    Auto,
    /// Pinning sempre, mesmo em máquina uniforme. Para quem sabe o que está a
    /// fazer e mediu.
    Strict,
}

/// `[linux.cpu]`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LinuxCpuConfig {
    pub affinity: AffinityPolicy,
    pub numa: Tristate,
}

/// `[linux.network]` — §30/§31/§32/§33.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LinuxNetworkConfig {
    /// §31 — pequeno e ligado por omissão: para RPCs de controlo e Raft, o
    /// atraso do Nagle é latência pura.
    pub tcp_nodelay: bool,
    pub reuse_port: Tristate,
    /// §33 — **zero significa autotuning do kernel**, e é o default de
    /// propósito. A §33 nomeia o erro que se evita: "não hard-code SO_RCVBUF =
    /// 16MB por superstição". Um buffer fixo escolhido sem medir é pior do que
    /// o autotuning, que pelo menos observa a ligação.
    pub recv_buffer_bytes: u32,
    pub send_buffer_bytes: u32,
}

impl Default for LinuxNetworkConfig {
    fn default() -> Self {
        Self {
            tcp_nodelay: true,
            reuse_port: Tristate::Auto,
            recv_buffer_bytes: 0,
            send_buffer_bytes: 0,
        }
    }
}

/// `[linux.allocator]`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LinuxAllocatorConfig {
    pub backend: Tristate,
}

/// A secção `[linux]` inteira (§51).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LinuxConfig {
    pub io: LinuxIoConfig,
    pub memory: LinuxMemoryConfig,
    pub cpu: LinuxCpuConfig,
    pub network: LinuxNetworkConfig,
    pub allocator: LinuxAllocatorConfig,
}

/// O que o runtime REALMENTE vai usar, depois de resolver `auto` contra as
/// capacidades e as políticas qualificadas.
///
/// Cada campo traz o **motivo**. A §54 diz "não esconder escolha automática", e
/// uma escolha sem motivo é uma escolha escondida com outro nome: quem lê a
/// linha de arranque vê `io=portable` e não sabe se foi por configuração, por
/// falta de capacidade, ou por a política ainda não autorizar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedLinuxRuntime {
    pub io_backend: &'static str,
    pub io_backend_motivo: String,
    pub numa: bool,
    pub numa_motivo: String,
    pub affinity: AffinityPolicy,
    pub affinity_motivo: String,
    pub mmap_advice: bool,
    pub reuse_port: bool,
    pub tcp_nodelay: bool,
}

impl ResolvedLinuxRuntime {
    /// §54 — a linha única de telemetria de arranque.
    pub fn linha(&self) -> String {
        format!(
            "linux_runtime: io={} numa={} affinity={:?} mmap_advice={} reuse_port={} tcp_nodelay={}",
            self.io_backend,
            if self.numa { "on" } else { "off" },
            self.affinity,
            self.mmap_advice,
            self.reuse_port,
            self.tcp_nodelay,
        )
    }
}

/// De onde vem cada valor, por ordem de precedência.
fn env(nome: &str) -> Option<String> {
    std::env::var(nome).ok().filter(|v| !v.trim().is_empty())
}

/// Resolve a configuração contra as capacidades detectadas.
///
/// `uring_compilado` diz se este binário sequer TEM o backend io_uring — a
/// feature `linux-io-uring` do `heraclitus-log`. Sem ela, pedir `uring` não é
/// uma escolha possível, e dizer que sim seria mentir na linha de arranque.
pub fn resolver(
    config: &LinuxConfig,
    capacidades: &crate::PlatformCapabilities,
    uring_compilado: bool,
) -> ResolvedLinuxRuntime {
    // ── io backend ───────────────────────────────────────────────────────────
    let escolha_io = env("HERACLITUS_IO_BACKEND")
        .and_then(|v| IoBackendChoice::do_texto(&v))
        .unwrap_or(config.io.backend);

    let (io_backend, io_backend_motivo) = match escolha_io {
        IoBackendChoice::Portable => ("portable-file-io", "pedido explicitamente".to_string()),
        IoBackendChoice::Uring if !uring_compilado => (
            "portable-file-io",
            "uring pedido mas este binário não o traz (feature linux-io-uring desligada)"
                .to_string(),
        ),
        IoBackendChoice::Uring if !capacidades.io_uring_available => (
            "portable-file-io",
            "uring pedido mas o kernel não o oferece".to_string(),
        ),
        IoBackendChoice::Uring => ("linux-uring-io", "pedido explicitamente".to_string()),
        // AQUI está a §52. `auto` NÃO escolhe o io_uring por ele existir: a
        // política qualificada exigida pelo I-5 — benchmark da §10, gate da §11
        // — ainda não foi corrida, portanto o backend comprovadamente seguro é
        // o baseline.
        IoBackendChoice::Auto => (
            "portable-file-io",
            if capacidades.io_uring_available && uring_compilado {
                "auto: io_uring disponível mas ainda sem o gate da §11; \
                 o baseline é o backend qualificado"
                    .to_string()
            } else {
                "auto: baseline".to_string()
            },
        ),
    };

    // ── numa ─────────────────────────────────────────────────────────────────
    let escolha_numa = env("HERACLITUS_NUMA")
        .and_then(|v| Tristate::do_texto(&v))
        .unwrap_or(config.cpu.numa);
    let (numa, numa_motivo) = match escolha_numa {
        Tristate::Off => (false, "desligado".to_string()),
        Tristate::On => (
            capacidades.numa.e_multi_no(),
            if capacidades.numa.e_multi_no() {
                "ligado".to_string()
            } else {
                "ligado mas a máquina tem um só nó".to_string()
            },
        ),
        Tristate::Auto => (
            capacidades.numa.e_multi_no(),
            format!("auto: {} nó(s) detectado(s)", capacidades.numa.nodes.len()),
        ),
    };

    // ── afinidade ────────────────────────────────────────────────────────────
    let (affinity, affinity_motivo) = match config.cpu.affinity {
        AffinityPolicy::Off => (AffinityPolicy::Off, "desligado".to_string()),
        AffinityPolicy::Strict => (AffinityPolicy::Strict, "strict: pinning sempre".to_string()),
        // §23: "não aplicar pinning cego". Numa máquina uniforme não há
        // decisão a tomar, e fabricar uma é o pinning cego.
        AffinityPolicy::Auto if !numa => (
            AffinityPolicy::Off,
            "auto: topologia uniforme, nada a fixar".to_string(),
        ),
        AffinityPolicy::Auto => (
            AffinityPolicy::Auto,
            "auto: multi-NUMA, workers distribuídos pelos nós".to_string(),
        ),
    };

    let mmap_advice = match env("HERACLITUS_MMAP_ADVICE")
        .and_then(|v| Tristate::do_texto(&v))
        .unwrap_or(config.memory.mmap_advice)
    {
        Tristate::Off => false,
        Tristate::On | Tristate::Auto => true,
    };

    let reuse_port = match env("HERACLITUS_REUSEPORT")
        .and_then(|v| Tristate::do_texto(&v))
        .unwrap_or(config.network.reuse_port)
    {
        Tristate::On => true,
        // §32: "MAY ser ativado ... SE benchmarks demonstrarem accept/listener
        // contention". Não há esse benchmark, portanto `auto` é `off`.
        Tristate::Off | Tristate::Auto => false,
    };

    ResolvedLinuxRuntime {
        io_backend,
        io_backend_motivo,
        numa,
        numa_motivo,
        affinity,
        affinity_motivo,
        mmap_advice,
        reuse_port,
        tcp_nodelay: config.network.tcp_nodelay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(uring: bool, nos: usize) -> crate::PlatformCapabilities {
        let mut c = crate::detect_capabilities();
        c.io_uring_available = uring;
        c.numa = crate::numa::NumaTopology {
            nodes: (0..nos)
                .map(|id| crate::numa::NumaNode {
                    id,
                    cpus: vec![id * 2, id * 2 + 1],
                    total_memory_bytes: 1 << 30,
                })
                .collect(),
        };
        c.numa_nodes = nos;
        c
    }

    /// A §52 inteira num teste: `auto` NAO escolhe o io_uring so por ele
    /// existir. A politica qualificada — benchmark da §10, gate da §11 — ainda
    /// nao correu, portanto o backend comprovadamente seguro e o baseline.
    #[test]
    fn auto_nao_promove_o_uring_so_por_estar_disponivel() {
        let r = resolver(&LinuxConfig::default(), &caps(true, 1), true);
        assert_eq!(r.io_backend, "portable-file-io");
        assert!(
            r.io_backend_motivo.contains("§11"),
            "o motivo tem de dizer PORQUE nao escolheu: {}",
            r.io_backend_motivo
        );
    }

    #[test]
    fn pedir_uring_sem_o_binario_o_trazer_nao_mente_na_linha() {
        let mut c = LinuxConfig::default();
        c.io.backend = IoBackendChoice::Uring;
        let r = resolver(&c, &caps(true, 1), false);
        assert_eq!(r.io_backend, "portable-file-io");
        assert!(r.io_backend_motivo.contains("feature"));
    }

    #[test]
    fn pedir_uring_sem_kernel_que_o_ofereca_cai_para_o_baseline() {
        let mut c = LinuxConfig::default();
        c.io.backend = IoBackendChoice::Uring;
        let r = resolver(&c, &caps(false, 1), true);
        assert_eq!(r.io_backend, "portable-file-io");
        assert!(r.io_backend_motivo.contains("kernel"));
    }

    #[test]
    fn pedir_uring_com_tudo_no_sitio_escolhe_uring() {
        let mut c = LinuxConfig::default();
        c.io.backend = IoBackendChoice::Uring;
        let r = resolver(&c, &caps(true, 1), true);
        assert_eq!(r.io_backend, "linux-uring-io");
    }

    /// §23 — "nao aplicar pinning cego". Numa maquina uniforme nao ha decisao a
    /// tomar, e `auto` tem de resolver para `off`.
    #[test]
    fn auto_nao_fixa_workers_numa_maquina_uniforme() {
        let r = resolver(&LinuxConfig::default(), &caps(false, 1), false);
        assert_eq!(r.affinity, AffinityPolicy::Off);
        assert!(!r.numa);

        let r = resolver(&LinuxConfig::default(), &caps(false, 4), false);
        assert_eq!(r.affinity, AffinityPolicy::Auto);
        assert!(r.numa);
    }

    #[test]
    fn strict_fixa_mesmo_em_maquina_uniforme() {
        let mut c = LinuxConfig::default();
        c.cpu.affinity = AffinityPolicy::Strict;
        let r = resolver(&c, &caps(false, 1), false);
        assert_eq!(r.affinity, AffinityPolicy::Strict);
    }

    /// §32 — o SO_REUSEPORT so entra "SE benchmarks demonstrarem contention".
    /// Nao ha esse benchmark, portanto `auto` e `off`.
    #[test]
    fn auto_nao_liga_reuse_port_sem_benchmark() {
        let r = resolver(&LinuxConfig::default(), &caps(true, 2), true);
        assert!(!r.reuse_port);
    }

    /// §33 — zero e autotuning do kernel, e e o default.
    #[test]
    fn os_buffers_tcp_ficam_ao_cuidado_do_kernel_por_omissao() {
        let c = LinuxConfig::default();
        assert_eq!(c.network.recv_buffer_bytes, 0);
        assert_eq!(c.network.send_buffer_bytes, 0);
        assert!(c.network.tcp_nodelay, "§31: ligado para RPCs de controlo");
    }

    #[test]
    fn a_linha_de_arranque_diz_tudo_o_que_foi_escolhido() {
        let r = resolver(&LinuxConfig::default(), &caps(true, 2), true);
        let l = r.linha();
        for esperado in [
            "io=",
            "numa=",
            "affinity=",
            "mmap_advice=",
            "reuse_port=",
            "tcp_nodelay=",
        ] {
            assert!(l.contains(esperado), "falta {esperado:?} em {l:?}");
        }
    }

    #[test]
    fn o_tristate_le_as_formas_habituais() {
        for (t, esperado) in [
            ("auto", Tristate::Auto),
            ("ON", Tristate::On),
            ("true", Tristate::On),
            ("1", Tristate::On),
            ("off", Tristate::Off),
            ("0", Tristate::Off),
        ] {
            assert_eq!(Tristate::do_texto(t), Some(esperado), "{t:?}");
        }
        assert_eq!(Tristate::do_texto("talvez"), None);
    }
}
