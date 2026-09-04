//! SPEC-0073 §22 — topologia NUMA real.
//!
//! A detecção anterior contava directórios `/sys/devices/system/node/nodeN` e
//! devolvia um número. Isso responde "quantos nós há" e mais nada — e a §24
//! quer decidir *em que nó* corre um worker e *de que nó* vem a sua arena, o
//! que exige saber que CPUs pertencem a cada nó e quanta memória cada um tem.
//!
//! Tudo o que interessa está em sysfs e é texto:
//!
//! ```text
//! /sys/devices/system/node/node0/cpulist   ->  "0-7,16-23"
//! /sys/devices/system/node/node0/meminfo   ->  "Node 0 MemTotal:  16384000 kB"
//! ```
//!
//! O parsing vive em funções puras que recebem esse texto, e é por isso que
//! esta topologia se consegue testar numa máquina de um só nó — que é a
//! máquina em que quase toda a gente a vai escrever.

use serde::{Deserialize, Serialize};

/// Um nó NUMA, com os CPUs que lhe pertencem e a memória que tem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaNode {
    pub id: usize,
    pub cpus: Vec<usize>,
    pub total_memory_bytes: u64,
}

/// A topologia observada. Nunca vazia: uma máquina sem sysfs NUMA é uma
/// máquina de um nó, e é isso que se reporta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaTopology {
    pub nodes: Vec<NumaNode>,
}

impl NumaTopology {
    /// A topologia de quem não tem nós NUMA distintos.
    ///
    /// `cpus` vazio significa "não sei quais" e não "nenhum": em UMA, todos os
    /// CPUs são igualmente locais, portanto a pergunta não tem conteúdo.
    pub fn uniforme() -> Self {
        Self {
            nodes: vec![NumaNode {
                id: 0,
                cpus: Vec::new(),
                total_memory_bytes: 0,
            }],
        }
    }

    pub fn e_multi_no(&self) -> bool {
        self.nodes.len() > 1
    }

    /// O nó a que um CPU pertence.
    pub fn no_do_cpu(&self, cpu: usize) -> Option<usize> {
        self.nodes
            .iter()
            .find(|n| n.cpus.contains(&cpu))
            .map(|n| n.id)
    }

    /// SPEC-0073 §24 — distribui `quantos` workers pelos nós, em rodízio.
    ///
    /// Devolve, para cada worker, o CPU em que deve correr. A ordem alterna
    /// entre nós de propósito: encher o nó 0 antes de tocar no nó 1 poria toda
    /// a carga num controlador de memória enquanto o outro fica parado, que é
    /// o oposto do que a consciência NUMA existe para fazer.
    ///
    /// Numa topologia uniforme devolve vazio — não há decisão a tomar, e
    /// fabricar uma seria o "pinning cego" que a §23 proíbe.
    pub fn distribuir_workers(&self, quantos: usize) -> Vec<usize> {
        if !self.e_multi_no() || quantos == 0 {
            return Vec::new();
        }
        let com_cpus: Vec<&NumaNode> = self.nodes.iter().filter(|n| !n.cpus.is_empty()).collect();
        if com_cpus.is_empty() {
            return Vec::new();
        }
        (0..quantos)
            .map(|i| {
                let no = com_cpus[i % com_cpus.len()];
                // Dentro do nó, roda pelos CPUs desse nó.
                no.cpus[(i / com_cpus.len()) % no.cpus.len()]
            })
            .collect()
    }
}

/// Lê a topologia real do sysfs. Fora de Linux devolve a uniforme.
pub fn detect_numa_topology() -> NumaTopology {
    #[cfg(target_os = "linux")]
    {
        detect_numa_topology_at(std::path::Path::new("/sys/devices/system/node"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        NumaTopology::uniforme()
    }
}

/// A leitura, com a raiz explícita — é o que a torna testável com um sysfs
/// simulado em vez de exigir uma máquina de dois sockets.
pub fn detect_numa_topology_at(raiz: &std::path::Path) -> NumaTopology {
    let Ok(entradas) = std::fs::read_dir(raiz) else {
        return NumaTopology::uniforme();
    };
    let mut nodes: Vec<NumaNode> = Vec::new();
    for entrada in entradas.flatten() {
        let nome = entrada.file_name();
        let Some(nome) = nome.to_str() else { continue };
        let Some(numero) = nome.strip_prefix("node") else {
            continue;
        };
        let Ok(id) = numero.parse::<usize>() else {
            continue;
        };
        let dir = entrada.path();
        let cpus = std::fs::read_to_string(dir.join("cpulist"))
            .map(|t| parse_cpulist(&t))
            .unwrap_or_default();
        let total_memory_bytes = std::fs::read_to_string(dir.join("meminfo"))
            .map(|t| parse_meminfo_total(&t))
            .unwrap_or(0);
        nodes.push(NumaNode {
            id,
            cpus,
            total_memory_bytes,
        });
    }
    if nodes.is_empty() {
        return NumaTopology::uniforme();
    }
    nodes.sort_by_key(|n| n.id);
    NumaTopology { nodes }
}

/// `cpulist`: `0-7,16,20-23`.
///
/// Um formato ilegível devolve vazio — "não sei quais" e não uma lista
/// inventada. É a mesma direcção conservadora do `parse_cpuset` do cgroup, e
/// pela mesma razão: um erro de parsing não pode produzir uma afinidade que
/// ninguém configurou.
pub fn parse_cpulist(texto: &str) -> Vec<usize> {
    let mut cpus = Vec::new();
    for parte in texto.trim().split(',').filter(|p| !p.trim().is_empty()) {
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

/// `meminfo` de um nó: `Node 0 MemTotal:  16384000 kB`.
///
/// Devolve BYTES. O ficheiro fala em kB (que são KiB, apesar do nome — é a
/// convenção do kernel), portanto multiplica-se por 1024.
pub fn parse_meminfo_total(texto: &str) -> u64 {
    for linha in texto.lines() {
        if !linha.contains("MemTotal:") {
            continue;
        }
        let mut campos = linha.split_whitespace();
        // "Node", "0", "MemTotal:", "16384000", "kB"
        while let Some(campo) = campos.next() {
            if campo == "MemTotal:" {
                if let Some(Ok(kib)) = campos.next().map(str::parse::<u64>) {
                    return kib.saturating_mul(1024);
                }
                return 0;
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sysfs_com(nos: &[(usize, &str, u64)]) -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        for (id, cpulist, mem_kib) in nos {
            let dir = temp.path().join(format!("node{id}"));
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("cpulist"), cpulist).unwrap();
            fs::write(
                dir.join("meminfo"),
                format!("Node {id} MemTotal:  {mem_kib} kB\nNode {id} MemFree: 1 kB\n"),
            )
            .unwrap();
        }
        temp
    }

    #[test]
    fn a_topologia_sai_do_sysfs_com_cpus_e_memoria() {
        // O que a deteccao anterior nao sabia dizer: QUAIS cpus e QUANTA
        // memoria. Sem isso nao ha como decidir onde por um worker.
        let temp = sysfs_com(&[(0, "0-3,8", 16_384_000), (1, "4-7", 8_192_000)]);
        let t = detect_numa_topology_at(temp.path());
        assert!(t.e_multi_no());
        assert_eq!(t.nodes.len(), 2);
        assert_eq!(t.nodes[0].id, 0);
        assert_eq!(t.nodes[0].cpus, vec![0, 1, 2, 3, 8]);
        assert_eq!(t.nodes[0].total_memory_bytes, 16_384_000 * 1024);
        assert_eq!(t.nodes[1].cpus, vec![4, 5, 6, 7]);
        assert_eq!(t.no_do_cpu(8), Some(0));
        assert_eq!(t.no_do_cpu(5), Some(1));
        assert_eq!(t.no_do_cpu(99), None);
    }

    #[test]
    fn sem_sysfs_a_topologia_e_uniforme_e_nao_vazia() {
        let t = detect_numa_topology_at(std::path::Path::new("/nao/existe/de/certeza"));
        assert!(!t.e_multi_no());
        assert_eq!(t.nodes.len(), 1, "uma topologia sem nós não é utilizável");
    }

    #[test]
    fn um_no_so_continua_a_ser_uma_maquina_uniforme() {
        let temp = sysfs_com(&[(0, "0-15", 32_768_000)]);
        let t = detect_numa_topology_at(temp.path());
        assert!(!t.e_multi_no());
        assert_eq!(t.nodes[0].cpus.len(), 16);
    }

    #[test]
    fn os_workers_alternam_entre_nos_antes_de_encher_um() {
        // Encher o nó 0 antes de tocar no 1 poria toda a carga num controlador
        // de memória com o outro parado — o oposto do que isto existe para
        // fazer.
        let temp = sysfs_com(&[(0, "0-1", 1), (1, "2-3", 1)]);
        let t = detect_numa_topology_at(temp.path());
        assert_eq!(t.distribuir_workers(4), vec![0, 2, 1, 3]);
        assert_eq!(t.distribuir_workers(2), vec![0, 2]);
        assert_eq!(
            t.distribuir_workers(6),
            vec![0, 2, 1, 3, 0, 2],
            "com mais workers que CPUs, roda"
        );
    }

    #[test]
    fn numa_uniforme_nao_produz_pinning() {
        // §23: "não aplicar pinning cego". Numa máquina de um nó não há decisão
        // a tomar, e fabricar uma seria exactamente isso.
        let temp = sysfs_com(&[(0, "0-7", 1)]);
        let t = detect_numa_topology_at(temp.path());
        assert!(t.distribuir_workers(8).is_empty());
        assert!(NumaTopology::uniforme().distribuir_workers(4).is_empty());
    }

    #[test]
    fn um_cpulist_ilegivel_nao_inventa_cpus() {
        for mau in ["abc", "3-1", "0-", "-5", "1,,2x"] {
            assert!(
                parse_cpulist(mau).is_empty(),
                "{mau:?} não devia produzir lista nenhuma"
            );
        }
        assert_eq!(parse_cpulist("0-3"), vec![0, 1, 2, 3]);
        assert_eq!(parse_cpulist(" 5 \n"), vec![5]);
    }

    #[test]
    fn o_meminfo_e_lido_em_bytes() {
        assert_eq!(
            parse_meminfo_total("Node 0 MemTotal:  16384000 kB"),
            16_384_000 * 1024
        );
        assert_eq!(parse_meminfo_total("Node 3 MemFree: 12 kB"), 0);
        assert_eq!(parse_meminfo_total("lixo"), 0);
        assert_eq!(parse_meminfo_total(""), 0);
    }
}
