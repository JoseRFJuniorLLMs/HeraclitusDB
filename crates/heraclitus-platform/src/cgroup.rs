//! cgroups v2 resource limit detection and enforcement.
//!
//! Under containerized or systemd-managed Linux environments, total physical RAM
//! and CPU count do not reflect the effective constraints imposed on the process.
//! If the server sizes its caches against total host RAM instead of the cgroup limit,
//! it is vulnerable to being terminated by the Linux OOM-killer.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Effective resource limits computed from host and cgroups v2 boundaries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveResourceLimits {
    /// Maximum memory in bytes allowed for this process, or None if unbounded.
    pub memory_limit_bytes: Option<u64>,
    /// Current memory usage in bytes, if available.
    pub memory_current_bytes: Option<u64>,
    /// Effective CPU quota in millicores (e.g., 2000 = 2 cores), or None if unbounded.
    pub cpu_quota_millicores: Option<u32>,
    /// SPEC-0073 §46 — os CPUs que o `cpuset` deixa usar.
    ///
    /// Vazio quando não há restrição de cpuset. É separado da quota porque são
    /// duas coisas diferentes: o cpuset diz QUAIS os cores, a quota diz QUANTO
    /// tempo deles. Um container pode ter os 64 cores visíveis e uma quota de
    /// 2 — e é esse o caso que faz mal.
    pub allowed_cpus: Vec<usize>,
    /// Whether cgroups v2 was detected and active.
    pub cgroups_v2_active: bool,
}

impl EffectiveResourceLimits {
    /// SPEC-0073 §46/§47 — quantos CPUs este processo pode realmente usar.
    ///
    /// "O runtime MUST preferir limites efetivos do cgroup quando mais
    /// restritivos que recursos físicos." É o mínimo de três coisas: os CPUs
    /// que o SO reporta, os que o `cpuset` permite, e os que a quota paga.
    ///
    /// A quota é a que faltava, e é a que faz mal. `available_parallelism()`
    /// respeita a afinidade (logo o cpuset), mas **não** respeita `cpu.max`:
    /// num host de 64 cores com `cpu.max = 200000 100000` reporta 64, e o
    /// `heraclitus-analytics` abre 64 workers para uma fatia de 2 cores. Não é
    /// mais rápido — é a mesma fatia repartida por 32× mais threads, com toda
    /// a troca de contexto e a memória por thread que isso traz.
    ///
    /// Nunca devolve 0: um processo que corre tem pelo menos um CPU.
    pub fn effective_cpus(&self, logical_cpus: usize) -> usize {
        let mut efectivo = logical_cpus.max(1);
        if !self.allowed_cpus.is_empty() {
            efectivo = efectivo.min(self.allowed_cpus.len());
        }
        if let Some(millicores) = self.cpu_quota_millicores {
            // Arredonda para cima: uma quota de 1500 millicores dá para dois
            // workers a fazerem progresso, e limitar a 1 desperdiçaria meio
            // core. Arredondar para baixo seria conservador ao ponto de ser
            // errado.
            let da_quota = millicores.div_ceil(1000) as usize;
            efectivo = efectivo.min(da_quota.max(1));
        }
        efectivo.max(1)
    }
}

/// Interpreta `cpuset.cpus.effective` — listas com intervalos, `0-3,8,12-15`.
///
/// Um formato que não se deixe ler devolve vazio, que significa "sem
/// restrição": preferível a devolver uma lista errada, porque um erro de
/// parsing não deve poder inventar um limite mais apertado do que existe.
pub fn parse_cpuset(valor: &str) -> Vec<usize> {
    let mut cpus = Vec::new();
    for parte in valor.trim().split(',').filter(|p| !p.is_empty()) {
        match parte.split_once('-') {
            Some((inicio, fim)) => {
                let (Ok(i), Ok(f)) = (inicio.trim().parse::<usize>(), fim.trim().parse::<usize>())
                else {
                    return Vec::new();
                };
                if i > f || f - i > 65_535 {
                    return Vec::new();
                }
                cpus.extend(i..=f);
            }
            None => match parte.trim().parse::<usize>() {
                Ok(n) => cpus.push(n),
                Err(_) => return Vec::new(),
            },
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    cpus
}

/// Detects cgroups v2 limits for **this process**.
///
/// Lê `/proc/self/cgroup` para descobrir onde o processo vive e percorre a
/// hierarquia até à raiz, ficando com o limite mais apertado que encontrar.
///
/// A versão anterior lia `/sys/fs/cgroup` directamente, e isso é a raiz da
/// hierarquia — onde, em cgroups v2, `memory.max` e `cpu.max` **não existem**
/// (só os cgroups não-raiz os têm). Funcionava em Docker por acidente, porque o
/// namespace de cgroup faz o cgroup do contentor aparecer como raiz; sob
/// systemd, onde o processo vive em `system.slice/heraclitusdb.service`,
/// devolvia sempre "sem limites". É o pior modo de falha possível para esta
/// função: dimensionar caches contra a RAM da máquina inteira dentro de uma
/// unidade com `MemoryMax=` termina no OOM-killer.
pub fn detect_cgroup_limits() -> EffectiveResourceLimits {
    #[cfg(target_os = "linux")]
    {
        let raiz = Path::new("/sys/fs/cgroup");
        let Some(relativo) = cgroup_relativo_do_processo() else {
            return detect_cgroup_limits_at(raiz);
        };
        // O limite efectivo é o mínimo ao longo da cadeia: um ancestral pode
        // ser mais apertado que a folha.
        let mut efectivo = EffectiveResourceLimits::default();
        let mut actual = raiz.join(relativo.trim_start_matches('/'));
        loop {
            let neste = detect_cgroup_limits_at(&actual);
            efectivo.cgroups_v2_active |= neste.cgroups_v2_active;
            efectivo.memory_limit_bytes =
                minimo(efectivo.memory_limit_bytes, neste.memory_limit_bytes);
            efectivo.cpu_quota_millicores =
                minimo(efectivo.cpu_quota_millicores, neste.cpu_quota_millicores);
            // O cpuset mais apertado ganha: um ancestral pode restringir
            // mais do que a folha, e quem manda e a interseccao.
            if !neste.allowed_cpus.is_empty() {
                efectivo.allowed_cpus = if efectivo.allowed_cpus.is_empty() {
                    neste.allowed_cpus
                } else {
                    efectivo
                        .allowed_cpus
                        .iter()
                        .filter(|c| neste.allowed_cpus.contains(c))
                        .copied()
                        .collect()
                };
            }
            if efectivo.memory_current_bytes.is_none() {
                efectivo.memory_current_bytes = neste.memory_current_bytes;
            }
            if actual == raiz {
                break;
            }
            match actual.parent() {
                Some(pai) if pai.starts_with(raiz) => actual = pai.to_path_buf(),
                _ => break,
            }
        }
        efectivo
    }
    #[cfg(not(target_os = "linux"))]
    {
        detect_cgroup_limits_at(Path::new("/sys/fs/cgroup"))
    }
}

#[cfg(target_os = "linux")]
fn minimo<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) => Some(x),
        (None, y) => y,
    }
}

/// O caminho do cgroup v2 deste processo, relativo à raiz da hierarquia.
///
/// `/proc/self/cgroup` na v2 tem uma única linha da forma `0::/caminho`.
#[cfg(target_os = "linux")]
fn cgroup_relativo_do_processo() -> Option<String> {
    let conteudo = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    conteudo
        .lines()
        .find_map(|linha| linha.strip_prefix("0::"))
        .map(|caminho| caminho.trim().to_string())
        .filter(|caminho| !caminho.is_empty())
}

/// Detects cgroups v2 limits at a specific root path (useful for testing).
pub fn detect_cgroup_limits_at(cgroup_root: &Path) -> EffectiveResourceLimits {
    #[cfg(target_os = "linux")]
    {
        if !cgroup_root.exists() {
            return EffectiveResourceLimits::default();
        }

        let memory_max_path = cgroup_root.join("memory.max");
        let memory_current_path = cgroup_root.join("memory.current");
        let cpu_max_path = cgroup_root.join("cpu.max");

        let memory_limit_bytes = if memory_max_path.exists() {
            std::fs::read_to_string(&memory_max_path)
                .ok()
                .and_then(|s| parse_cgroup_val(s.trim()))
        } else {
            None
        };

        let memory_current_bytes = if memory_current_path.exists() {
            std::fs::read_to_string(&memory_current_path)
                .ok()
                .and_then(|s| parse_cgroup_val(s.trim()))
        } else {
            None
        };

        let cpu_quota_millicores = if cpu_max_path.exists() {
            std::fs::read_to_string(&cpu_max_path)
                .ok()
                .and_then(|s| parse_cpu_max(s.trim()))
        } else {
            None
        };

        // SPEC-0073 §46 — o cpuset e o outro eixo do limite de CPU.
        let cpuset_path = cgroup_root.join("cpuset.cpus.effective");
        let allowed_cpus = std::fs::read_to_string(&cpuset_path)
            .ok()
            .map(|s| parse_cpuset(&s))
            .unwrap_or_default();

        let cgroups_v2_active = memory_max_path.exists() || cpu_max_path.exists();

        EffectiveResourceLimits {
            memory_limit_bytes,
            memory_current_bytes,
            cpu_quota_millicores,
            allowed_cpus,
            cgroups_v2_active,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = cgroup_root;
        EffectiveResourceLimits::default()
    }
}

/// Parses a cgroup value: an integer or 'max' which becomes None.
pub fn parse_cgroup_val(val: &str) -> Option<u64> {
    if val == "max" || val.is_empty() {
        None
    } else {
        val.parse::<u64>().ok()
    }
}

/// Parses cgroups v2 cpu.max format: [quota] [period].
/// Example: 200000 100000 -> 2.0 cores -> 2000 millicores.
/// Example: max 100000 -> None.
pub fn parse_cpu_max(val: &str) -> Option<u32> {
    let mut parts = val.split_whitespace();
    let quota_str = parts.next()?;
    let period_str = parts.next()?;

    if quota_str == "max" {
        return None;
    }

    let quota: u64 = quota_str.parse().ok()?;
    let period: u64 = period_str.parse().ok()?;

    if period == 0 {
        return None;
    }

    // millicores = (quota * 1000) / period
    let millicores = (quota.saturating_mul(1000)) / period;
    Some(millicores as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_memory_values() {
        assert_eq!(parse_cgroup_val("max"), None);
        assert_eq!(parse_cgroup_val(""), None);
        assert_eq!(parse_cgroup_val("1073741824"), Some(1073741824));
    }

    #[test]
    fn parse_cpu_values() {
        assert_eq!(parse_cpu_max("max 100000"), None);
        assert_eq!(parse_cpu_max("200000 100000"), Some(2000));
        assert_eq!(parse_cpu_max("50000 100000"), Some(500));
        assert_eq!(parse_cpu_max("invalid"), None);
    }
}

#[cfg(test)]
mod testes_cpus_efectivos {
    use super::*;

    fn limites(quota: Option<u32>, cpus: &[usize]) -> EffectiveResourceLimits {
        EffectiveResourceLimits {
            cpu_quota_millicores: quota,
            allowed_cpus: cpus.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn a_quota_limita_o_numero_de_workers_e_o_host_nao() {
        // O caso que motivou isto: 64 cores visiveis, `cpu.max = 200000 100000`
        // (2 cores). `available_parallelism()` diz 64 porque respeita afinidade
        // e nao quota, e o analytics abria 64 workers para uma fatia de 2.
        assert_eq!(limites(Some(2000), &[]).effective_cpus(64), 2);
        assert_eq!(limites(Some(500), &[]).effective_cpus(64), 1);
        assert_eq!(limites(Some(1500), &[]).effective_cpus(64), 2);
    }

    #[test]
    fn sem_limites_o_numero_e_o_do_host() {
        assert_eq!(limites(None, &[]).effective_cpus(64), 64);
        assert_eq!(EffectiveResourceLimits::default().effective_cpus(8), 8);
    }

    #[test]
    fn o_limite_mais_apertado_ganha_e_nunca_se_devolve_zero() {
        // cpuset de 4, quota de 8: manda o cpuset.
        assert_eq!(limites(Some(8000), &[0, 1, 2, 3]).effective_cpus(64), 4);
        // cpuset de 8, quota de 2: manda a quota.
        assert_eq!(
            limites(Some(2000), &[0, 1, 2, 3, 4, 5, 6, 7]).effective_cpus(64),
            2
        );
        // Nunca abaixo de 1: um processo que corre tem pelo menos um CPU.
        assert_eq!(limites(Some(0), &[]).effective_cpus(64), 1);
        assert_eq!(limites(None, &[]).effective_cpus(0), 1);
    }

    #[test]
    fn um_limite_do_cgroup_nunca_aumenta_o_numero_de_cpus() {
        // Um cgroup generoso nao pode fazer o processo achar que tem mais
        // cores do que a maquina.
        assert_eq!(limites(Some(64_000), &[]).effective_cpus(4), 4);
        assert_eq!(
            limites(None, &(0..64).collect::<Vec<_>>()).effective_cpus(4),
            4
        );
    }

    #[test]
    fn o_cpuset_le_intervalos_e_listas() {
        assert_eq!(parse_cpuset("0-3"), vec![0, 1, 2, 3]);
        assert_eq!(parse_cpuset("0,2,4"), vec![0, 2, 4]);
        assert_eq!(parse_cpuset("0-1,4,6-7"), vec![0, 1, 4, 6, 7]);
        assert_eq!(parse_cpuset(" 2 \n"), vec![2]);
        assert!(parse_cpuset("").is_empty());
    }

    #[test]
    fn um_cpuset_ilegivel_nao_inventa_um_limite() {
        // Vazio significa "sem restricao". E a direccao certa para um erro de
        // parsing: devolver uma lista errada apertaria um limite que ninguem
        // configurou.
        for mau in ["abc", "3-1", "0-", "-5", "1,,2x", "999999999999999999999"] {
            assert!(
                parse_cpuset(mau).is_empty(),
                "{mau:?} nao devia produzir lista nenhuma"
            );
        }
    }
}
