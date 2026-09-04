//! SPEC-0071 Δ4 — Content Hub, event-sourced, **sem duplicar o Registry**.
//!
//! ## A restrição que define o crate
//!
//! A §7.1 abre com uma proibição:
//!
//! > `.hcx` continua sendo a unidade imutável e assinada. **Não será criado
//! > outro formato executável** para connectors/parsers.
//!
//! Este crate não define formato nenhum. Não lê `.hcx`, não os valida, não os
//! executa — isso é do `Heraclitus-Forge`, que já o faz com verificação Ed25519
//! fail-closed. O que falta, e é o que está aqui, é o **ciclo de vida**: quem
//! publicou o quê, quando foi activado em que tenant, e com que digest.
//!
//! O `.hrkp` da §7.2 é, pelas palavras da própria spec, "apenas agregado de
//! distribuição, nunca um segundo runtime format". Aqui é uma lista de
//! referências `(id, versão, digest)` e mais nada — instalar um pack é instalar
//! as unidades individualmente e activá-las por política.
//!
//! ## Publicar e activar são actos diferentes (§7.3)
//!
//! > Um pacote assinado pode estar publicado e ainda não autorizado num tenant.
//!
//! É a distinção mais importante deste módulo, e a que um modelo de estados
//! ingénuo apaga. [`ContentState`] guarda o estado do ARTEFACTO (publicado,
//! obsoleto, revogado) separado do estado POR TENANT (staged, activo, revertido)
//! — porque um artefacto publicado globalmente pode estar activo num tenant,
//! em canário noutro, e por instalar num terceiro, tudo ao mesmo tempo.
//!
//! ## Rollback acrescenta, não apaga (§7.5)
//!
//! > Rollback cria novo evento de ativação; não apaga o histórico.
//!
//! O que torna isto verdadeiro não é disciplina: é não haver caminho para
//! apagar. Um `Rollback` é um evento como os outros, e o digest anterior fica
//! visível na cadeia.

use heraclitus_core::{Episode, EventKind, Lsn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CONTENT_SCHEMA: &str = "heraclitus-content/1.0";
pub const CONTENT_KIND: &str = "ContentLifecycle";

/// O ciclo de vida do ARTEFACTO (§7.3), global.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentStatus {
    Draft,
    Validated,
    Signed,
    Published,
    Deprecated,
    Revoked,
}

/// O estado POR TENANT — separado do global de propósito (§7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRollout {
    /// Instalado e verificado, ainda sem efeito.
    Staged,
    /// §7.5 — só valida, não corre.
    ValidateOnly,
    /// Corre em paralelo sem produzir efeito observável.
    Shadow,
    /// §7.5 — canário por datasource.
    Canary,
    Active,
    RolledBack,
}

/// Uma referência a uma unidade `.hcx`, por identidade e digest.
///
/// **Nunca o conteúdo.** O artefacto vive no registry do Forge; aqui guarda-se
/// o que permite dizer exactamente qual — e um digest é o que torna essa
/// afirmação verificável em vez de nominal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ContentRef {
    pub content_id: String,
    pub version: String,
    /// SHA-256 hex do `.hcx`, como o Forge o publica.
    pub digest: String,
}

impl ContentRef {
    pub fn validar(&self) -> Result<(), ContentError> {
        if self.content_id.trim().is_empty() || self.version.trim().is_empty() {
            return Err(ContentError::Invalido("content_id/version vazios".into()));
        }
        // 64 hex: um digest curto ou com prefixo não é comparável com o que o
        // Forge publica, e um digest que não se compara não prova nada.
        if self.digest.len() != 64 || !self.digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ContentError::Invalido(format!(
                "digest deve ser 64 hex, veio {:?}",
                self.digest
            )));
        }
        Ok(())
    }
}

/// Os eventos do ciclo de vida.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ContentEvent {
    /// Publicado no hub. NÃO activa em tenant nenhum.
    Published {
        artefacto: ContentRef,
        publisher: String,
        /// A chave que assinou, tal como o Forge a reporta.
        signing_key: String,
    },
    /// Um pack `.hrkp` — agregado de distribuição, nunca um runtime (§7.2).
    PackPublished {
        pack_id: String,
        conteudos: Vec<ContentRef>,
        publisher: String,
    },
    /// Instalado num tenant, sem efeito ainda.
    Staged {
        artefacto: ContentRef,
        tenant_id: String,
    },
    /// §7.5 — modo de rollout.
    RolloutChanged {
        artefacto: ContentRef,
        tenant_id: String,
        rollout: TenantRollout,
        /// Para `Canary`: em que datasources.
        datasources: Vec<String>,
    },
    Deprecated {
        artefacto: ContentRef,
        reason: String,
    },
    /// Revogação — o estado terminal. Um artefacto revogado não volta.
    Revoked {
        artefacto: ContentRef,
        reason: String,
    },
    /// §7.5 — rollback para um digest anterior. É um evento NOVO.
    RolledBack {
        tenant_id: String,
        de: ContentRef,
        para: ContentRef,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentEnvelope {
    pub schema: String,
    pub command_id: String,
    pub principal: String,
    pub reason: String,
    pub event: ContentEvent,
}

impl ContentEnvelope {
    pub fn novo(
        command_id: impl Into<String>,
        principal: impl Into<String>,
        reason: impl Into<String>,
        event: ContentEvent,
    ) -> Self {
        Self {
            schema: CONTENT_SCHEMA.into(),
            command_id: command_id.into(),
            principal: principal.into(),
            reason: reason.into(),
            event,
        }
    }

    pub fn validar(&self) -> Result<(), ContentError> {
        if self.schema != CONTENT_SCHEMA {
            return Err(ContentError::Invalido(format!(
                "esquema não suportado: {}",
                self.schema
            )));
        }
        for (nome, v) in [
            ("command_id", &self.command_id),
            ("principal", &self.principal),
            ("reason", &self.reason),
        ] {
            if v.trim().is_empty() {
                return Err(ContentError::Invalido(format!("{nome} vazio")));
            }
        }
        match &self.event {
            ContentEvent::Published { artefacto, .. }
            | ContentEvent::Staged { artefacto, .. }
            | ContentEvent::RolloutChanged { artefacto, .. }
            | ContentEvent::Deprecated { artefacto, .. }
            | ContentEvent::Revoked { artefacto, .. } => artefacto.validar()?,
            ContentEvent::PackPublished { conteudos, .. } => {
                for c in conteudos {
                    c.validar()?;
                }
            }
            ContentEvent::RolledBack { de, para, .. } => {
                de.validar()?;
                para.validar()?;
            }
        }
        Ok(())
    }

    pub fn para_episodio(&self) -> Result<Episode, ContentError> {
        self.validar()?;
        let content =
            serde_json::to_vec(self).map_err(|e| ContentError::Invalido(e.to_string()))?;
        let mut ep = Episode::new(
            "content-hub",
            EventKind::Custom(CONTENT_KIND.into()),
            content,
        );
        ep.attrs
            .insert("content.schema".into(), self.schema.clone());
        ep.attrs
            .insert("content.command_id".into(), self.command_id.clone());
        ep.attrs
            .insert("content.principal".into(), self.principal.clone());
        Ok(ep)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContentError {
    #[error("comando de conteúdo inválido: {0}")]
    Invalido(String),
    #[error("o artefacto {0} está revogado e não pode voltar a ser activado")]
    Revogado(String),
    #[error("o artefacto {0} não foi publicado")]
    NaoPublicado(String),
}

/// A chave de um artefacto: `id@versão`. O digest fica no estado, para poder
/// ser comparado com o que o Forge publica.
fn chave(r: &ContentRef) -> String {
    format!("{}@{}", r.content_id, r.version)
}

/// O estado de um artefacto no hub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtefactoState {
    pub artefacto: ContentRef,
    pub status: ContentStatus,
    pub publisher: Option<String>,
    pub signing_key: Option<String>,
    /// Estado por tenant. Um artefacto publicado pode estar activo num tenant,
    /// em canário noutro, e por instalar num terceiro.
    pub por_tenant: BTreeMap<String, TenantRollout>,
    /// Datasources do canário, por tenant.
    pub canary_datasources: BTreeMap<String, Vec<String>>,
    /// A cadeia de rollbacks. Acrescenta, nunca apaga (§7.5).
    pub historico_rollback: Vec<(String, String, String)>,
}

/// O hub inteiro, derivado do log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentState {
    pub artefactos: BTreeMap<String, ArtefactoState>,
    pub packs: BTreeMap<String, Vec<ContentRef>>,
}

impl ContentState {
    /// Aplica um evento. Devolve `Err` para as transições que a spec proíbe.
    pub fn aplicar(&mut self, envelope: &ContentEnvelope) -> Result<(), ContentError> {
        envelope.validar()?;
        match &envelope.event {
            ContentEvent::Published {
                artefacto,
                publisher,
                signing_key,
            } => {
                let e = self
                    .artefactos
                    .entry(chave(artefacto))
                    .or_insert_with(|| ArtefactoState {
                        artefacto: artefacto.clone(),
                        status: ContentStatus::Draft,
                        publisher: None,
                        signing_key: None,
                        por_tenant: BTreeMap::new(),
                        canary_datasources: BTreeMap::new(),
                        historico_rollback: Vec::new(),
                    });
                // Revogado é TERMINAL. Republicar por cima de uma revogação
                // seria a maneira mais silenciosa de reactivar conteúdo que
                // alguém revogou por uma razão.
                if e.status == ContentStatus::Revoked {
                    return Err(ContentError::Revogado(chave(artefacto)));
                }
                e.status = ContentStatus::Published;
                e.publisher = Some(publisher.clone());
                e.signing_key = Some(signing_key.clone());
            }
            ContentEvent::PackPublished {
                pack_id, conteudos, ..
            } => {
                // O pack é uma LISTA. Publicá-lo não publica o que ele
                // referencia — a §7.2 diz que instalar um pack "equivale a
                // instalar unidades .hcx verificadas individualmente".
                self.packs.insert(pack_id.clone(), conteudos.clone());
            }
            ContentEvent::Staged {
                artefacto,
                tenant_id,
            } => {
                let e = self
                    .artefactos
                    .get_mut(&chave(artefacto))
                    .ok_or_else(|| ContentError::NaoPublicado(chave(artefacto)))?;
                if e.status == ContentStatus::Revoked {
                    return Err(ContentError::Revogado(chave(artefacto)));
                }
                e.por_tenant
                    .insert(tenant_id.clone(), TenantRollout::Staged);
            }
            ContentEvent::RolloutChanged {
                artefacto,
                tenant_id,
                rollout,
                datasources,
            } => {
                let e = self
                    .artefactos
                    .get_mut(&chave(artefacto))
                    .ok_or_else(|| ContentError::NaoPublicado(chave(artefacto)))?;
                if e.status == ContentStatus::Revoked {
                    return Err(ContentError::Revogado(chave(artefacto)));
                }
                e.por_tenant.insert(tenant_id.clone(), *rollout);
                if *rollout == TenantRollout::Canary {
                    e.canary_datasources
                        .insert(tenant_id.clone(), datasources.clone());
                } else {
                    e.canary_datasources.remove(tenant_id);
                }
            }
            ContentEvent::Deprecated { artefacto, .. } => {
                if let Some(e) = self.artefactos.get_mut(&chave(artefacto)) {
                    if e.status != ContentStatus::Revoked {
                        e.status = ContentStatus::Deprecated;
                    }
                }
            }
            ContentEvent::Revoked { artefacto, .. } => {
                if let Some(e) = self.artefactos.get_mut(&chave(artefacto)) {
                    e.status = ContentStatus::Revoked;
                    // Revogar tira de TODOS os tenants. Deixar um activo seria
                    // deixar a correr precisamente o que se revogou.
                    for estado in e.por_tenant.values_mut() {
                        *estado = TenantRollout::RolledBack;
                    }
                }
            }
            ContentEvent::RolledBack {
                tenant_id,
                de,
                para,
                reason,
            } => {
                if let Some(e) = self.artefactos.get_mut(&chave(de)) {
                    e.por_tenant
                        .insert(tenant_id.clone(), TenantRollout::RolledBack);
                    // O histórico ACRESCENTA. A §7.5: "rollback cria novo
                    // evento de ativação; não apaga o histórico".
                    e.historico_rollback.push((
                        tenant_id.clone(),
                        para.digest.clone(),
                        reason.clone(),
                    ));
                }
                if let Some(alvo) = self.artefactos.get_mut(&chave(para)) {
                    if alvo.status != ContentStatus::Revoked {
                        alvo.por_tenant
                            .insert(tenant_id.clone(), TenantRollout::Active);
                    }
                }
            }
        }
        Ok(())
    }

    /// Este artefacto está a correr neste tenant?
    ///
    /// Só `Active` e `Canary` contam. `Shadow` corre mas não produz efeito
    /// observável, e `ValidateOnly` nem corre — tratá-los como activos seria
    /// dizer que um rollout de segurança está em vigor quando não está.
    pub fn esta_activo(&self, artefacto: &ContentRef, tenant_id: &str) -> bool {
        self.artefactos
            .get(&chave(artefacto))
            .filter(|e| e.status != ContentStatus::Revoked)
            .and_then(|e| e.por_tenant.get(tenant_id))
            .is_some_and(|r| matches!(r, TenantRollout::Active | TenantRollout::Canary))
    }
}

/// Reconstrói o hub a partir dos envelopes, por ordem de LSN.
pub fn reconstruir<'a>(envelopes: impl IntoIterator<Item = &'a ContentEnvelope>) -> ContentState {
    let mut estado = ContentState::default();
    for e in envelopes {
        // Um evento que a spec proíbe é IGNORADO na reconstrução, não aborta.
        // O log é imutável: se um comando inválido lá chegou, a view tem de
        // conseguir ser construída na mesma — recusar-se a arrancar por causa
        // de uma linha antiga tornaria o hub inutilizável para sempre.
        let _ = estado.aplicar(e);
    }
    estado
}

pub fn do_episodio(episode: &Episode) -> Option<ContentEnvelope> {
    let EventKind::Custom(kind) = &episode.kind else {
        return None;
    };
    if kind != CONTENT_KIND {
        return None;
    }
    serde_json::from_slice(&episode.content).ok()
}

/// O LSN não é usado no estado, mas mantém a assinatura simétrica com as outras
/// projecções do repositório e evita que um chamador tenha de o descartar.
pub fn do_episodio_com_lsn(_lsn: Lsn, episode: &Episode) -> Option<ContentEnvelope> {
    do_episodio(episode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artefacto(id: &str, versao: &str, d: u8) -> ContentRef {
        ContentRef {
            content_id: id.into(),
            version: versao.into(),
            digest: format!("{d:02x}").repeat(32),
        }
    }

    fn env(cmd: &str, e: ContentEvent) -> ContentEnvelope {
        ContentEnvelope::novo(cmd, "publisher-a", "porque sim", e)
    }

    fn publicar(a: &ContentRef, cmd: &str) -> ContentEnvelope {
        env(
            cmd,
            ContentEvent::Published {
                artefacto: a.clone(),
                publisher: "orgao-x".into(),
                signing_key: "ed25519:abc".into(),
            },
        )
    }

    /// §7.3 — publicar e activar sao actos DIFERENTES.
    ///
    /// "Um pacote assinado pode estar publicado e ainda nao autorizado num
    /// tenant." E a distincao que um modelo de estados ingenuo apaga.
    #[test]
    fn publicar_nao_activa_em_tenant_nenhum() {
        let a = artefacto("postgresql", "1.2.0", 0xab);
        let estado = reconstruir(&[publicar(&a, "c1")]);
        let e = &estado.artefactos[&chave(&a)];
        assert_eq!(e.status, ContentStatus::Published);
        assert!(
            e.por_tenant.is_empty(),
            "publicar nao instala em lado nenhum"
        );
        assert!(!estado.esta_activo(&a, "tenant-1"));
    }

    #[test]
    fn o_mesmo_artefacto_pode_ter_estados_diferentes_por_tenant() {
        let a = artefacto("linux_sshd", "1.1.0", 0x11);
        let estado = reconstruir(&[
            publicar(&a, "c1"),
            env(
                "c2",
                ContentEvent::RolloutChanged {
                    artefacto: a.clone(),
                    tenant_id: "tenant-1".into(),
                    rollout: TenantRollout::Active,
                    datasources: vec![],
                },
            ),
            env(
                "c3",
                ContentEvent::RolloutChanged {
                    artefacto: a.clone(),
                    tenant_id: "tenant-2".into(),
                    rollout: TenantRollout::Canary,
                    datasources: vec!["sshd-prod".into()],
                },
            ),
            env(
                "c4",
                ContentEvent::Staged {
                    artefacto: a.clone(),
                    tenant_id: "tenant-3".into(),
                },
            ),
        ]);
        assert!(estado.esta_activo(&a, "tenant-1"));
        assert!(
            estado.esta_activo(&a, "tenant-2"),
            "canario conta como activo"
        );
        assert!(!estado.esta_activo(&a, "tenant-3"), "staged nao corre");
        assert_eq!(
            estado.artefactos[&chave(&a)].canary_datasources["tenant-2"],
            vec!["sshd-prod".to_string()]
        );
    }

    /// `Shadow` e `ValidateOnly` NAO contam como activos: tratá-los assim seria
    /// dizer que um rollout esta em vigor quando nao esta.
    #[test]
    fn shadow_e_validate_only_nao_sao_activos() {
        let a = artefacto("nginx_access", "1.0.0", 0x22);
        for modo in [TenantRollout::Shadow, TenantRollout::ValidateOnly] {
            let estado = reconstruir(&[
                publicar(&a, "c1"),
                env(
                    "c2",
                    ContentEvent::RolloutChanged {
                        artefacto: a.clone(),
                        tenant_id: "t".into(),
                        rollout: modo,
                        datasources: vec![],
                    },
                ),
            ]);
            assert!(!estado.esta_activo(&a, "t"), "{modo:?} nao devia contar");
        }
    }

    /// Revogar e TERMINAL, e tira de todos os tenants.
    #[test]
    fn revogar_desactiva_em_todo_o_lado_e_nao_se_desfaz() {
        let a = artefacto("windows_security", "1.0.0", 0x33);
        let mut estado = reconstruir(&[
            publicar(&a, "c1"),
            env(
                "c2",
                ContentEvent::RolloutChanged {
                    artefacto: a.clone(),
                    tenant_id: "t1".into(),
                    rollout: TenantRollout::Active,
                    datasources: vec![],
                },
            ),
            env(
                "c3",
                ContentEvent::Revoked {
                    artefacto: a.clone(),
                    reason: "parser vulneravel".into(),
                },
            ),
        ]);
        assert!(!estado.esta_activo(&a, "t1"), "revogar tem de desactivar");

        // Republicar por cima de uma revogacao seria a maneira mais silenciosa
        // de reactivar conteudo que alguem revogou por uma razao.
        let erro = estado.aplicar(&publicar(&a, "c4")).unwrap_err();
        assert!(matches!(erro, ContentError::Revogado(_)));
        // E activar tambem nao.
        assert!(estado
            .aplicar(&env(
                "c5",
                ContentEvent::RolloutChanged {
                    artefacto: a.clone(),
                    tenant_id: "t1".into(),
                    rollout: TenantRollout::Active,
                    datasources: vec![],
                },
            ))
            .is_err());
    }

    /// §7.5 — rollback ACRESCENTA, nao apaga.
    #[test]
    fn o_rollback_deixa_rasto_do_digest_anterior() {
        let novo = artefacto("postgresql", "1.2.0", 0xaa);
        let antigo = artefacto("postgresql", "1.1.0", 0xbb);
        let estado = reconstruir(&[
            publicar(&antigo, "c0"),
            publicar(&novo, "c1"),
            env(
                "c2",
                ContentEvent::RolloutChanged {
                    artefacto: novo.clone(),
                    tenant_id: "t1".into(),
                    rollout: TenantRollout::Active,
                    datasources: vec![],
                },
            ),
            env(
                "c3",
                ContentEvent::RolledBack {
                    tenant_id: "t1".into(),
                    de: novo.clone(),
                    para: antigo.clone(),
                    reason: "regressao de parsing".into(),
                },
            ),
        ]);
        assert!(!estado.esta_activo(&novo, "t1"));
        assert!(
            estado.esta_activo(&antigo, "t1"),
            "o anterior volta a activo"
        );

        let historico = &estado.artefactos[&chave(&novo)].historico_rollback;
        assert_eq!(historico.len(), 1);
        assert_eq!(historico[0].0, "t1");
        assert_eq!(historico[0].1, antigo.digest, "o digest anterior fica");
        assert!(historico[0].2.contains("regressao"));
    }

    /// §7.2 — publicar um pack NAO publica o que ele referencia.
    #[test]
    fn um_pack_e_uma_lista_e_nao_um_runtime() {
        let a = artefacto("postgresql", "1.2.0", 0x44);
        let estado = reconstruir(&[env(
            "c1",
            ContentEvent::PackPublished {
                pack_id: "pack-gov-2026".into(),
                conteudos: vec![a.clone()],
                publisher: "orgao-x".into(),
            },
        )]);
        assert_eq!(estado.packs["pack-gov-2026"].len(), 1);
        assert!(
            !estado.artefactos.contains_key(&chave(&a)),
            "instalar um pack e instalar as unidades individualmente"
        );
    }

    #[test]
    fn instalar_o_que_nao_foi_publicado_e_recusado() {
        let a = artefacto("desconhecido", "9.9.9", 0x55);
        let mut estado = ContentState::default();
        let erro = estado
            .aplicar(&env(
                "c1",
                ContentEvent::Staged {
                    artefacto: a.clone(),
                    tenant_id: "t".into(),
                },
            ))
            .unwrap_err();
        assert!(matches!(erro, ContentError::NaoPublicado(_)));
    }

    #[test]
    fn um_digest_que_nao_e_64_hex_e_recusado() {
        for mau in ["", "abc", &"zz".repeat(32), &"ab".repeat(31)] {
            let r = ContentRef {
                content_id: "x".into(),
                version: "1".into(),
                digest: mau.to_string(),
            };
            assert!(r.validar().is_err(), "{mau:?} devia ser recusado");
        }
        assert!(artefacto("x", "1", 0xab).validar().is_ok());
    }

    /// A reconstrucao nao pode abortar por causa de uma linha antiga: o log e
    /// imutavel, e recusar arrancar tornaria o hub inutilizavel para sempre.
    #[test]
    fn um_comando_invalido_no_log_nao_impede_a_reconstrucao() {
        let a = artefacto("postgresql", "1.2.0", 0x66);
        let estado = reconstruir(&[
            // Este e invalido: instalar sem publicar.
            env(
                "mau",
                ContentEvent::Staged {
                    artefacto: a.clone(),
                    tenant_id: "t".into(),
                },
            ),
            publicar(&a, "c1"),
        ]);
        assert_eq!(
            estado.artefactos[&chave(&a)].status,
            ContentStatus::Published
        );
    }

    #[test]
    fn o_envelope_atravessa_o_log_e_volta() {
        let a = artefacto("postgresql", "1.2.0", 0x77);
        let envelope = publicar(&a, "c1");
        let ep = envelope.para_episodio().unwrap();
        assert_eq!(ep.attrs["content.command_id"], "c1");
        assert_eq!(do_episodio(&ep).unwrap(), envelope);
    }
}
