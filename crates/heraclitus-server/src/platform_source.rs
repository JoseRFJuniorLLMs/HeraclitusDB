//! SPEC-0077 §37/§38 — o estado da plataforma, lido do motor.
//!
//! # Porque é que isto vive aqui e não no crate da consola
//!
//! Porque é aqui que o `Engine` existe. O crate que serve a Platform Console
//! declara só um *trait* ([`PlatformSource`]); a implementação é esta. A
//! separação não é cerimónia: é ela que garante que a consola não tem nenhum
//! caminho para produzir um número sem alguém o ter ido buscar ao log.
//!
//! # Porque é que a integridade NÃO é verificada a cada pedido
//!
//! `Engine::verify()` percorre os segmentos e recalcula as raízes de Merkle.
//! Num log de gigabytes isso são minutos — e chamá-lo no carregamento da página
//! daria uma home que ou bloqueia, ou (pior) aprende a devolver um resultado
//! velho e a chamar-lhe actual.
//!
//! O que esta fonte reporta é o que o motor **observou durante leituras
//! normais**: `canonical_verify_failures` e `physical_crc_failures`. Isso
//! chega para distinguir os dois estados que importam:
//!
//! ```text
//! falhas > 0   BROKEN       o motor viu adulteração; não se discute
//! falhas = 0   UNVERIFIED   nada falhou no que foi lido — o que NÃO é o
//!                           mesmo que "tudo foi verificado"
//! ```
//!
//! `UNVERIFIED` não promove a `VERIFIED` por não ter havido falhas. A distinção
//! entre "não verificado" e "válido" é a razão de existir do produto (0076
//! §33); colapsá-la na home desfaria na primeira tela o cuidado que o resto do
//! sistema tem. Quem quer a verificação completa corre-a de propósito, por
//! `heraclitus verify`, e sabe o que está a pagar.

use heraclitus_agent_gateway::platform::{
    IndexRow, IntegrityState, ModuleState, ModuleStatus, PlatformSnapshot, PlatformSource,
    SourceRow, StorageRow,
};
use heraclitus_core::HeraclitusConfig;
use std::sync::Arc;

pub struct EnginePlatformSource {
    engine: Arc<crate::engine::Engine>,
    modules: Vec<ModuleStatus>,
}

impl EnginePlatformSource {
    pub fn new(
        engine: Arc<crate::engine::Engine>,
        config: &HeraclitusConfig,
        agent_enabled: bool,
    ) -> Self {
        Self {
            modules: modules_reais(config, agent_enabled),
            engine,
        }
    }
}

fn u64_de(v: Option<&serde_json::Value>) -> Option<u64> {
    v.and_then(|x| x.as_u64())
}

impl PlatformSource for EnginePlatformSource {
    fn snapshot(&self) -> PlatformSnapshot {
        let stats = self.engine.stats();
        let fontes = self.engine.fontes();

        let m = stats.get("storage_metrics");
        let disponivel = m
            .and_then(|x| x.get("available"))
            .and_then(|x| x.as_bool())
            .unwrap_or(false);

        let (storage, integrity, integrity_detail) = if disponivel {
            let canonicas = u64_de(m.and_then(|x| x.get("canonical_verify_failures"))).unwrap_or(0);
            let fisicas = u64_de(m.and_then(|x| x.get("physical_crc_failures"))).unwrap_or(0);
            let falhas = canonicas + fisicas;
            let estado = if falhas > 0 {
                IntegrityState::Broken
            } else {
                IntegrityState::Unverified
            };
            let detalhe = if falhas > 0 {
                Some(format!(
                    "o motor observou {canonicas} falha(s) de verificação canónica e \
                     {fisicas} de CRC físico durante leituras normais. Isto é adulteração \
                     ou corrupção detectada — não represente estes dados como verificados."
                ))
            } else {
                Some(
                    "nenhuma falha de integridade foi observada nas leituras feitas por este \
                     processo. Isto NÃO é o mesmo que verificação completa: para verificar \
                     todos os segmentos, corra `heraclitus verify <data-dir>`."
                        .to_string(),
                )
            };
            (
                StorageRow {
                    raw_bytes: u64_de(m.and_then(|x| x.get("hrkl_raw_bytes"))),
                    packed_bytes: u64_de(m.and_then(|x| x.get("hrkl_packed_bytes"))),
                    compression_ratio: m
                        .and_then(|x| x.get("hrkl_compression_ratio"))
                        .and_then(|x| x.as_f64()),
                    append_bytes_total: u64_de(m.and_then(|x| x.get("hrkl_append_bytes_total"))),
                    unavailable_reason: None,
                },
                estado,
                detalhe,
            )
        } else {
            // Formato legado: as métricas HRKL v6 não existem. Dizer `NOT
            // CONFIGURED` seria errado (o log existe e funciona); dizer
            // `VERIFIED` seria uma mentira. `UNAVAILABLE` é o que é.
            let motivo = m
                .and_then(|x| x.get("reason").or_else(|| x.get("error")))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            (
                StorageRow {
                    unavailable_reason: motivo.clone(),
                    ..StorageRow::default()
                },
                IntegrityState::Unavailable,
                motivo,
            )
        };

        let contagem = |chave: &str, rotulo: &str| -> Option<IndexRow> {
            u64_de(stats.get(chave)).map(|count| IndexRow {
                id: chave.to_string(),
                label: rotulo.to_string(),
                count,
            })
        };
        let indexes = [
            contagem("text_indexed", "Text"),
            contagem("vector_indexed", "Vector"),
            contagem("graph_nodes", "Graph nodes"),
            contagem("tgraph_edges", "Graph edges"),
            contagem("entity_keys", "Entities"),
            contagem("activation_tracked", "Activation"),
        ]
        .into_iter()
        .flatten()
        .collect();

        let sources = fontes
            .get("fontes")
            .and_then(|x| x.as_array())
            .map(|linhas| {
                linhas
                    .iter()
                    .map(|f| SourceRow {
                        id: f
                            .get("agente")
                            .and_then(|x| x.as_str())
                            .unwrap_or("(unnamed)")
                            .to_string(),
                        events: u64_de(f.get("eventos")).unwrap_or(0),
                        first_ms: u64_de(f.get("primeiro_ms")),
                        last_ms: u64_de(f.get("ultimo_ms")),
                        first_lsn: u64_de(f.get("primeiro_lsn")),
                        last_lsn: u64_de(f.get("ultimo_lsn")),
                    })
                    .collect()
            })
            .unwrap_or_default();

        PlatformSnapshot {
            last_lsn: Some(self.engine.head()),
            storage_format: stats
                .get("storage_format")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            memtable_pending: u64_de(stats.get("memtable")),
            integrity,
            integrity_detail,
            indexes,
            views: stats
                .get("views")
                .and_then(|x| x.as_array())
                .map(|v| {
                    v.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
            sources,
            oldest_event_ms: u64_de(fontes.get("mais_antigo_ms")),
            newest_event_ms: u64_de(fontes.get("mais_recente_ms")),
            storage,
            modules: self.modules.clone(),
            ..PlatformSnapshot::default()
        }
    }
}

/// Os módulos, com os estados que realmente têm (§18, §38).
///
/// `NOT BUILT` não é o mesmo que `DISABLED`, e a diferença é operacional: um
/// resolve-se no ficheiro de configuração, o outro exige recompilar. §38 é
/// explícita em não inferir disponibilidade de um 404 — por isso isto lê
/// `cfg!(feature = ...)` e a configuração, e não o que uma rota respondeu.
fn modules_reais(config: &HeraclitusConfig, agent_enabled: bool) -> Vec<ModuleStatus> {
    let mut v = Vec::new();

    v.push(ModuleStatus {
        id: "agent".into(),
        name: "Agent Evidence & Control".into(),
        summary: "Capture and control AI-agent activity: OTLP GenAI, MCP proxy, \
                  policy, human approval, evidence bundles."
            .into(),
        state: if cfg!(not(feature = "agent")) {
            ModuleState::NotBuilt
        } else if agent_enabled {
            ModuleState::Enabled
        } else {
            ModuleState::Disabled
        },
        detail: if cfg!(feature = "agent") && !agent_enabled {
            Some("set [agent_black_box] enabled = true".into())
        } else {
            None
        },
        href: agent_enabled.then(|| "/agent".to_string()),
    });

    v.push(ModuleStatus {
        id: "sentinel".into(),
        name: "Sentinel".into(),
        summary: "Security analytics and incident response over the same log.".into(),
        state: if config.sentinel.enabled {
            ModuleState::Enabled
        } else {
            ModuleState::Disabled
        },
        detail: (!config.sentinel.enabled).then(|| "set [sentinel] enabled = true".into()),
        href: None,
    });

    v.push(ModuleStatus {
        id: "analytics".into(),
        name: "Analytics".into(),
        summary: "SQL over the log via DataFusion and Arrow.".into(),
        state: if cfg!(feature = "analytics") {
            ModuleState::Enabled
        } else {
            ModuleState::NotBuilt
        },
        detail: if cfg!(feature = "analytics") {
            None
        } else {
            Some("build with --features analytics".into())
        },
        href: None,
    });

    v.push(ModuleStatus {
        id: "compliance".into(),
        name: "Compliance".into(),
        summary: "RFC 3161 timestamping and evidence anchoring.".into(),
        state: if !config.compliance_enabled {
            ModuleState::Disabled
        } else if config.compliance_tsa_url.is_empty() {
            // Ligado e sem TSA é o estado mais perigoso de todos: parece
            // configurado e não ancora nada em lado nenhum.
            ModuleState::NotConfigured
        } else {
            ModuleState::Enabled
        },
        detail: if config.compliance_enabled && config.compliance_tsa_url.is_empty() {
            Some("compliance is on but no TSA URL is set: nothing is being anchored".into())
        } else {
            None
        },
        href: None,
    });

    v.push(ModuleStatus {
        id: "tier".into(),
        name: "Cold tier".into(),
        summary: "Demote sealed segments to object storage with Merkle receipts.".into(),
        state: if cfg!(feature = "tier") {
            ModuleState::Enabled
        } else {
            ModuleState::NotBuilt
        },
        detail: if cfg!(feature = "tier") {
            None
        } else {
            Some("build with --features tier".into())
        },
        href: None,
    });

    v.push(ModuleStatus {
        id: "replication".into(),
        name: "Replication".into(),
        summary: "Raft consensus across nodes.".into(),
        state: if cfg!(not(feature = "replication")) {
            ModuleState::NotBuilt
        } else if config.replication.is_some() {
            ModuleState::Enabled
        } else {
            ModuleState::Disabled
        },
        detail: None,
        href: None,
    });

    v.push(ModuleStatus {
        id: "gpu".into(),
        name: "GPU".into(),
        summary: "wgpu dispatch for exact vector recall.".into(),
        state: if cfg!(feature = "gpu") {
            ModuleState::Enabled
        } else {
            ModuleState::NotBuilt
        },
        detail: if cfg!(feature = "gpu") {
            None
        } else {
            Some("build with --features gpu".into())
        },
        href: None,
    });

    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn um_modulo_desligado_nao_se_confunde_com_um_nao_compilado() {
        let mut c = HeraclitusConfig::default();
        c.sentinel.enabled = false; // campo aninhado: nao ha forma literal
        let mods = modules_reais(&c, false);

        let sentinel = mods.iter().find(|m| m.id == "sentinel").unwrap();
        assert_eq!(sentinel.state, ModuleState::Disabled);
        assert!(
            sentinel.detail.is_some(),
            "DISABLED tem de dizer como ligar"
        );

        let agent = mods.iter().find(|m| m.id == "agent").unwrap();
        assert_eq!(agent.state, ModuleState::Disabled);
        // §6/§30 — com o módulo desligado não há link para /agent.
        assert!(agent.href.is_none());
    }

    #[test]
    fn compliance_ligada_sem_tsa_e_not_configured_e_nao_enabled() {
        // O modo de falha que isto apanha: um operador liga compliance, vê
        // ENABLED na consola e assume que a ancoragem externa está a acontecer.
        // Não está — não há TSA para onde ir.
        let c = HeraclitusConfig {
            compliance_enabled: true,
            compliance_tsa_url: String::new(),
            ..Default::default()
        };
        let mods = modules_reais(&c, false);
        let compliance = mods.iter().find(|m| m.id == "compliance").unwrap();
        assert_eq!(compliance.state, ModuleState::NotConfigured);
        assert!(compliance.detail.is_some());
    }

    #[test]
    fn com_o_modulo_ligado_ha_porta_para_a_agent_console() {
        let c = HeraclitusConfig::default();
        let mods = modules_reais(&c, true);
        let agent = mods.iter().find(|m| m.id == "agent").unwrap();
        assert_eq!(agent.state, ModuleState::Enabled);
        assert_eq!(agent.href.as_deref(), Some("/agent"));
    }
}
