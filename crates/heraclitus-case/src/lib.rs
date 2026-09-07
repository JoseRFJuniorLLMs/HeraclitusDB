//! SPEC-0071 Δ5 — Case Management event-sourced.
//!
//! ## O que este crate é, e o que recusa ser
//!
//! Um caso é uma **view derivada** de eventos imutáveis no log. A §8.2 é
//! explícita:
//!
//! > O estado é uma view derivada. Não existe `UPDATE case SET ...` como fonte
//! > de verdade.
//!
//! Não há aqui uma tabela de casos, nem um `Case` mutável que alguém guarde.
//! Há [`CaseEvent`], que vai para o log, e [`CaseState`], que se reconstrói a
//! partir dele para qualquer LSN. Fechar um caso é acrescentar um
//! `CaseClosed`; reabri-lo é acrescentar um `CaseReopened`. O histórico não se
//! reescreve porque não há onde o reescrever.
//!
//! ## Concorrência: `expected_revision`, não "último a escrever ganha"
//!
//! A §8.3 exige que todo comando traga `command_id`, `case_id`,
//! `expected_revision`, `principal` e `reason`, e que:
//!
//! - uma `expected_revision` divergente gere **conflito explícito**;
//! - repetir o mesmo `command_id` devolva o resultado original.
//!
//! São duas propriedades diferentes e as duas fazem falta. Sem a primeira, dois
//! analistas a fechar o mesmo caso ao mesmo tempo produzem dois desfechos e um
//! deles perde-se em silêncio. Sem a segunda, um cliente que repete por timeout
//! duplica a acção — e num caso de segurança "escalar duas vezes" pode acordar
//! duas equipas.
//!
//! ## SLA: prazos são factos, não políticas (§8.4)
//!
//! > Deadlines são eventos versionados e derivados da política vigente quando o
//! > caso é criado. Alterar a policy não reescreve prazos históricos.
//!
//! Por isso [`SlaDeadlines`] é gravado NO evento de abertura, com a versão da
//! política que o produziu. Mudar a política amanhã não move o prazo de um caso
//! aberto ontem — o que importa numa auditoria, onde a pergunta é "cumpriu o
//! prazo que tinha na altura", e não "cumpriria o prazo de hoje".

use heraclitus_core::{Episode, EventKind, Lsn};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const CASE_SCHEMA: &str = "heraclitus-case/1.0";
pub const CASE_KIND: &str = "SecurityCase";

/// SPEC-0071 §8.5 — a proveniência de uma nota ou anexo.
///
/// A separação é obrigatória e não decorativa. Uma conclusão de analista e uma
/// hipótese de modelo têm peso probatório diferente, e um relatório que as
/// misture é um relatório que não se pode usar. `ModelHypothesis` ao lado de
/// `AnalystConclusion` sem distinção é como uma nota de rodapé apagada.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    RawEvidence,
    NormalizedEvent,
    DerivedDetection,
    ModelHypothesis,
    AnalystConclusion,
    ExternalEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Open,
    Triage,
    Investigating,
    Contained,
    Review,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CasePriority {
    Low,
    Medium,
    High,
    Critical,
}

/// SPEC-0071 §8.4 — os prazos, congelados na abertura.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlaDeadlines {
    /// A versão da política que produziu estes prazos. Sem ela, um prazo é um
    /// número sem proveniência — e a §8.4 existe precisamente para os prazos
    /// terem proveniência.
    pub policy_version: String,
    pub triage_due_micros: Option<i64>,
    pub investigation_due_micros: Option<i64>,
    pub containment_due_micros: Option<i64>,
    pub review_due_micros: Option<i64>,
    pub regulatory_due_micros: Option<i64>,
}

/// Uma tarefa dentro do caso.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseTask {
    pub task_id: String,
    pub description: String,
    pub assignee: Option<String>,
    pub completed: bool,
}

/// Uma nota, com a sua proveniência (§8.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseNote {
    pub note_id: String,
    pub kind: EvidenceKind,
    pub author: String,
    pub body: String,
    /// Revisões acrescentam, não substituem: `CaseNoteRevised` empilha aqui.
    pub revisions: Vec<String>,
}

/// Uma referência a evidência no log, por LSN.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EvidenceBookmark {
    pub lsn: Lsn,
    pub kind: EvidenceKind,
    pub note: Option<String>,
}

/// Os 18 eventos da §8.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum CaseEvent {
    CaseOpened {
        title: String,
        priority: CasePriority,
        opened_by: String,
        sla: SlaDeadlines,
    },
    CaseTitleChanged {
        title: String,
    },
    CasePriorityChanged {
        priority: CasePriority,
    },
    CaseOwnerAssigned {
        owner: String,
    },
    CaseWatcherAdded {
        watcher: String,
    },
    CaseTaskCreated {
        task_id: String,
        description: String,
        assignee: Option<String>,
    },
    CaseTaskCompleted {
        task_id: String,
    },
    CaseNoteAdded {
        note_id: String,
        kind: EvidenceKind,
        author: String,
        body: String,
    },
    CaseNoteRevised {
        note_id: String,
        body: String,
    },
    EvidenceBookmarked {
        lsn: Lsn,
        kind: EvidenceKind,
        note: Option<String>,
    },
    IncidentLinked {
        incident_id: String,
    },
    IncidentUnlinked {
        incident_id: String,
    },
    CaseEscalated {
        to: String,
        reason: String,
    },
    CaseStatusChanged {
        status: CaseStatus,
    },
    CaseMerged {
        into_case_id: String,
    },
    CaseSplit {
        new_case_id: String,
    },
    CaseClosed {
        resolution: String,
    },
    CaseReopened {
        reason: String,
    },
}

impl CaseEvent {
    pub fn nome(&self) -> &'static str {
        match self {
            Self::CaseOpened { .. } => "CaseOpened",
            Self::CaseTitleChanged { .. } => "CaseTitleChanged",
            Self::CasePriorityChanged { .. } => "CasePriorityChanged",
            Self::CaseOwnerAssigned { .. } => "CaseOwnerAssigned",
            Self::CaseWatcherAdded { .. } => "CaseWatcherAdded",
            Self::CaseTaskCreated { .. } => "CaseTaskCreated",
            Self::CaseTaskCompleted { .. } => "CaseTaskCompleted",
            Self::CaseNoteAdded { .. } => "CaseNoteAdded",
            Self::CaseNoteRevised { .. } => "CaseNoteRevised",
            Self::EvidenceBookmarked { .. } => "EvidenceBookmarked",
            Self::IncidentLinked { .. } => "IncidentLinked",
            Self::IncidentUnlinked { .. } => "IncidentUnlinked",
            Self::CaseEscalated { .. } => "CaseEscalated",
            Self::CaseStatusChanged { .. } => "CaseStatusChanged",
            Self::CaseMerged { .. } => "CaseMerged",
            Self::CaseSplit { .. } => "CaseSplit",
            Self::CaseClosed { .. } => "CaseClosed",
            Self::CaseReopened { .. } => "CaseReopened",
        }
    }
}

/// O envelope que vai para o log: o comando da §8.3 mais o evento.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseEnvelope {
    pub schema: String,
    pub case_id: String,
    /// Idempotência (§8.3): repetir o mesmo `command_id` devolve o resultado
    /// original em vez de aplicar duas vezes.
    pub command_id: String,
    /// A revisão que quem comanda ESPERAVA encontrar. Divergente é conflito.
    pub expected_revision: u64,
    pub principal: String,
    /// Porquê. Num caso de segurança, uma acção sem motivo é uma acção que
    /// ninguém consegue auditar depois.
    pub reason: String,
    pub event: CaseEvent,
}

impl CaseEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn novo(
        case_id: impl Into<String>,
        command_id: impl Into<String>,
        expected_revision: u64,
        principal: impl Into<String>,
        reason: impl Into<String>,
        event: CaseEvent,
    ) -> Self {
        Self {
            schema: CASE_SCHEMA.into(),
            case_id: case_id.into(),
            command_id: command_id.into(),
            expected_revision,
            principal: principal.into(),
            reason: reason.into(),
            event,
        }
    }

    pub fn validar(&self) -> Result<(), CaseError> {
        for (nome, valor) in [
            ("case_id", &self.case_id),
            ("command_id", &self.command_id),
            ("principal", &self.principal),
            ("reason", &self.reason),
        ] {
            if valor.trim().is_empty() {
                return Err(CaseError::Invalido(format!("{nome} vazio")));
            }
        }
        if self.schema != CASE_SCHEMA {
            return Err(CaseError::Invalido(format!(
                "esquema não suportado: {}",
                self.schema
            )));
        }
        Ok(())
    }

    pub fn para_episodio(&self) -> Result<Episode, CaseError> {
        self.validar()?;
        let content = serde_json::to_vec(self).map_err(|e| CaseError::Invalido(e.to_string()))?;
        let mut episode =
            Episode::new("case-manager", EventKind::Custom(CASE_KIND.into()), content);
        episode
            .attrs
            .insert("case.schema".into(), self.schema.clone());
        episode.attrs.insert("case.id".into(), self.case_id.clone());
        episode
            .attrs
            .insert("case.command_id".into(), self.command_id.clone());
        episode
            .attrs
            .insert("case.event".into(), self.event.nome().into());
        episode
            .attrs
            .insert("case.principal".into(), self.principal.clone());
        Ok(episode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaseError {
    #[error("comando de caso inválido: {0}")]
    Invalido(String),
    /// §8.3 — conflito EXPLÍCITO. Nunca "último a escrever ganha".
    #[error("conflito de revisão no caso {case_id}: esperada {esperada}, actual {actual}")]
    Conflito {
        case_id: String,
        esperada: u64,
        actual: u64,
    },
    #[error("o caso {0} não existe")]
    Inexistente(String),
    #[error("o caso {0} já foi aberto")]
    JaAberto(String),
}

/// O estado de um caso, DERIVADO dos seus eventos.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseState {
    pub case_id: String,
    /// Quantos eventos foram aplicados. É o `expected_revision` do próximo
    /// comando, e é o que torna a concorrência detectável.
    pub revision: u64,
    pub title: String,
    pub status: CaseStatus,
    pub priority: CasePriority,
    pub owner: Option<String>,
    pub watchers: BTreeSet<String>,
    pub tasks: BTreeMap<String, CaseTask>,
    pub notes: BTreeMap<String, CaseNote>,
    pub bookmarks: Vec<EvidenceBookmark>,
    pub incidents: BTreeSet<String>,
    pub sla: Option<SlaDeadlines>,
    pub escalations: Vec<(String, String)>,
    pub merged_into: Option<String>,
    pub splits: Vec<String>,
    pub resolution: Option<String>,
    /// Os `command_id` já aplicados. É a memória da idempotência da §8.3.
    pub applied_commands: BTreeSet<String>,
}

impl CaseState {
    fn novo(case_id: &str) -> Self {
        Self {
            case_id: case_id.to_string(),
            revision: 0,
            title: String::new(),
            status: CaseStatus::Open,
            priority: CasePriority::Medium,
            owner: None,
            watchers: BTreeSet::new(),
            tasks: BTreeMap::new(),
            notes: BTreeMap::new(),
            bookmarks: Vec::new(),
            incidents: BTreeSet::new(),
            sla: None,
            escalations: Vec::new(),
            merged_into: None,
            splits: Vec::new(),
            resolution: None,
            applied_commands: BTreeSet::new(),
        }
    }

    /// Aplica um envelope.
    ///
    /// Devolve `Ok(true)` quando aplicou, `Ok(false)` quando o comando já tinha
    /// sido aplicado (idempotência), e `Err(Conflito)` quando a revisão
    /// esperada não bate.
    ///
    /// A ordem dos testes importa: a idempotência é verificada ANTES da
    /// revisão. Um cliente que repete por timeout traz a revisão que tinha
    /// quando tentou — que já não é a actual, porque a primeira tentativa
    /// passou. Testar a revisão primeiro devolveria "conflito" a um comando
    /// que na verdade teve sucesso, e o cliente concluiria que falhou.
    pub fn aplicar(&mut self, envelope: &CaseEnvelope) -> Result<bool, CaseError> {
        envelope.validar()?;
        if self.applied_commands.contains(&envelope.command_id) {
            return Ok(false);
        }
        if envelope.expected_revision != self.revision {
            return Err(CaseError::Conflito {
                case_id: self.case_id.clone(),
                esperada: envelope.expected_revision,
                actual: self.revision,
            });
        }
        self.aplicar_evento(&envelope.event);
        self.applied_commands.insert(envelope.command_id.clone());
        self.revision += 1;
        Ok(true)
    }

    fn aplicar_evento(&mut self, evento: &CaseEvent) {
        match evento {
            CaseEvent::CaseOpened {
                title,
                priority,
                opened_by,
                sla,
            } => {
                self.title = title.clone();
                self.priority = *priority;
                self.owner = Some(opened_by.clone());
                self.status = CaseStatus::Open;
                // §8.4 — os prazos ficam gravados COM a versão de política que
                // os produziu, e nunca mais mudam por causa dela.
                self.sla = Some(sla.clone());
            }
            CaseEvent::CaseTitleChanged { title } => self.title = title.clone(),
            CaseEvent::CasePriorityChanged { priority } => self.priority = *priority,
            CaseEvent::CaseOwnerAssigned { owner } => self.owner = Some(owner.clone()),
            CaseEvent::CaseWatcherAdded { watcher } => {
                self.watchers.insert(watcher.clone());
            }
            CaseEvent::CaseTaskCreated {
                task_id,
                description,
                assignee,
            } => {
                self.tasks.insert(
                    task_id.clone(),
                    CaseTask {
                        task_id: task_id.clone(),
                        description: description.clone(),
                        assignee: assignee.clone(),
                        completed: false,
                    },
                );
            }
            CaseEvent::CaseTaskCompleted { task_id } => {
                if let Some(t) = self.tasks.get_mut(task_id) {
                    t.completed = true;
                }
            }
            CaseEvent::CaseNoteAdded {
                note_id,
                kind,
                author,
                body,
            } => {
                self.notes.insert(
                    note_id.clone(),
                    CaseNote {
                        note_id: note_id.clone(),
                        kind: *kind,
                        author: author.clone(),
                        body: body.clone(),
                        revisions: Vec::new(),
                    },
                );
            }
            CaseEvent::CaseNoteRevised { note_id, body } => {
                if let Some(n) = self.notes.get_mut(note_id) {
                    // A revisão EMPILHA. O corpo antigo fica na pilha, porque
                    // apagar o que um analista escreveu antes de mudar de ideias
                    // destrói o raciocínio que a auditoria vai querer ver.
                    let anterior = std::mem::replace(&mut n.body, body.clone());
                    n.revisions.push(anterior);
                }
            }
            CaseEvent::EvidenceBookmarked { lsn, kind, note } => {
                self.bookmarks.push(EvidenceBookmark {
                    lsn: *lsn,
                    kind: *kind,
                    note: note.clone(),
                });
                self.bookmarks.sort();
                self.bookmarks.dedup();
            }
            CaseEvent::IncidentLinked { incident_id } => {
                self.incidents.insert(incident_id.clone());
            }
            CaseEvent::IncidentUnlinked { incident_id } => {
                self.incidents.remove(incident_id);
            }
            CaseEvent::CaseEscalated { to, reason } => {
                self.escalations.push((to.clone(), reason.clone()));
            }
            CaseEvent::CaseStatusChanged { status } => self.status = *status,
            CaseEvent::CaseMerged { into_case_id } => {
                self.merged_into = Some(into_case_id.clone());
                self.status = CaseStatus::Closed;
            }
            CaseEvent::CaseSplit { new_case_id } => self.splits.push(new_case_id.clone()),
            CaseEvent::CaseClosed { resolution } => {
                self.status = CaseStatus::Closed;
                self.resolution = Some(resolution.clone());
            }
            CaseEvent::CaseReopened { reason } => {
                self.status = CaseStatus::Investigating;
                // A resolução anterior NÃO é apagada: fica no histórico, e o
                // motivo da reabertura é uma escalada registada. Um caso
                // reaberto sem memória do que o fechou perde exactamente a
                // informação que explica porque foi reaberto.
                self.escalations
                    .push(("reopen".to_string(), reason.clone()));
            }
        }
    }
}

/// Um envelope que a reconstrução NÃO conseguiu aplicar, e porquê.
///
/// Auditoria 2026-09-05, A08 — saltar um envelope não pode ser saltá-lo em
/// silêncio: num caso de segurança, um comando que está no log mas não está na
/// view é precisamente o que a auditoria precisa de ver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseRejeitado {
    pub command_id: String,
    pub erro: CaseError,
}

/// Reconstrói o estado de um caso a partir dos envelopes, por ordem de LSN.
///
/// É a única maneira de obter um `CaseState`. Não há construtor público que
/// aceite um estado pronto, e isso é deliberado: se houvesse, alguém acabaria
/// por o usar como fonte da verdade — que é exactamente o que a §8.2 proíbe.
///
/// Um envelope que não se aplica é SALTADO, não aborta — ver
/// [`reconstruir_auditado`], que é onde está o porquê e onde os rejeitados
/// ficam visíveis. Continua a devolver `Result` (hoje sempre `Ok`) por
/// compatibilidade com quem já a chama: o erro que ela propagava ERA o defeito.
pub fn reconstruir<'a>(
    case_id: &str,
    envelopes: impl IntoIterator<Item = &'a CaseEnvelope>,
) -> Result<Option<CaseState>, CaseError> {
    Ok(reconstruir_auditado(case_id, envelopes).0)
}

/// O mesmo que [`reconstruir`], mas devolve também os envelopes rejeitados.
///
/// Auditoria 2026-09-05, A08 — porque é que um envelope mau é SALTADO em vez de
/// abortar a reconstrução:
///
/// O log é append-only. Se um envelope que nunca devia lá ter entrado lá chegou
/// — dois analistas em corrida (`Engine::case_command` lê a revisão e só depois
/// apende, sem lock por `case_id`), ou um Writer a apender à mão um episódio
/// com o kind `SecurityCase` e conteúdo à escolha — abortar aqui transformava
/// uma linha antiga numa sentença perpétua: `case_state` e TODO o comando
/// seguinte passam por esta função, e do log não se remove nada. O caso ficava
/// ilegível e imutável para sempre, que é o oposto do gate CA0 ("estado do caso
/// é reconstruído do log"). A crate irmã já tinha escrito este raciocínio:
/// `heraclitus-content::reconstruir` ignora o evento que a spec proíbe porque
/// «recusar-se a arrancar por causa de uma linha antiga tornaria o hub
/// inutilizável para sempre».
///
/// O que NÃO se afrouxa: [`CaseState::aplicar`] continua a devolver
/// `Err(Conflito)` numa revisão divergente, e é aí — e na fronteira do comando,
/// antes de apender — que a §8.3 tem de morder. Saltar aqui é literalmente não
/// aplicar: `aplicar` só muta o estado depois de todas as verificações
/// passarem, portanto um envelope rejeitado não deixa metade de um efeito.
pub fn reconstruir_auditado<'a>(
    case_id: &str,
    envelopes: impl IntoIterator<Item = &'a CaseEnvelope>,
) -> (Option<CaseState>, Vec<CaseRejeitado>) {
    let mut estado: Option<CaseState> = None;
    let mut rejeitados: Vec<CaseRejeitado> = Vec::new();
    for envelope in envelopes {
        if envelope.case_id != case_id {
            continue;
        }
        let resultado = match (&mut estado, &envelope.event) {
            (None, CaseEvent::CaseOpened { .. }) => {
                let mut novo = CaseState::novo(case_id);
                let r = novo.aplicar(envelope);
                if r.is_ok() {
                    estado = Some(novo);
                }
                r
            }
            // Um evento antes do `CaseOpened` é ignorado, não inventa um caso.
            // Aceitá-lo criaria um caso sem abertura, sem SLA e sem dono — um
            // registo que parece um caso e não tem a proveniência de um.
            (None, _) => continue,
            (Some(e), _) => e.aplicar(envelope),
        };
        if let Err(erro) = resultado {
            rejeitados.push(CaseRejeitado {
                command_id: envelope.command_id.clone(),
                erro,
            });
        }
    }
    (estado, rejeitados)
}

/// Projecta um episódio do log de volta a um envelope, se for um evento de caso.
pub fn do_episodio(episode: &Episode) -> Option<CaseEnvelope> {
    let EventKind::Custom(kind) = &episode.kind else {
        return None;
    };
    if kind != CASE_KIND {
        return None;
    }
    serde_json::from_slice(&episode.content).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sla() -> SlaDeadlines {
        SlaDeadlines {
            policy_version: "sla-v1".into(),
            triage_due_micros: Some(1_000),
            investigation_due_micros: Some(2_000),
            containment_due_micros: Some(3_000),
            review_due_micros: None,
            regulatory_due_micros: Some(9_000),
        }
    }

    fn abrir(rev: u64, cmd: &str) -> CaseEnvelope {
        CaseEnvelope::novo(
            "case-1",
            cmd,
            rev,
            "analista-a",
            "sinal do Sentinel",
            CaseEvent::CaseOpened {
                title: "Acessos falhados em massa".into(),
                priority: CasePriority::High,
                opened_by: "analista-a".into(),
                sla: sla(),
            },
        )
    }

    fn evento(rev: u64, cmd: &str, e: CaseEvent) -> CaseEnvelope {
        CaseEnvelope::novo("case-1", cmd, rev, "analista-a", "porque sim", e)
    }

    #[test]
    fn um_caso_e_reconstruido_dos_seus_eventos() {
        let eventos = vec![
            abrir(0, "c1"),
            evento(
                1,
                "c2",
                CaseEvent::CaseStatusChanged {
                    status: CaseStatus::Investigating,
                },
            ),
            evento(
                2,
                "c3",
                CaseEvent::IncidentLinked {
                    incident_id: "inc-9".into(),
                },
            ),
            evento(
                3,
                "c4",
                CaseEvent::CaseClosed {
                    resolution: "falso positivo".into(),
                },
            ),
        ];
        let estado = reconstruir("case-1", &eventos).unwrap().unwrap();
        assert_eq!(estado.revision, 4);
        assert_eq!(estado.status, CaseStatus::Closed);
        assert_eq!(estado.resolution.as_deref(), Some("falso positivo"));
        assert!(estado.incidents.contains("inc-9"));
        assert_eq!(estado.sla.as_ref().unwrap().policy_version, "sla-v1");
    }

    /// §8.3 — uma revisao divergente e CONFLITO EXPLICITO.
    ///
    /// Sem isto, dois analistas a fechar o mesmo caso ao mesmo tempo produzem
    /// dois desfechos e um deles perde-se em silencio.
    #[test]
    fn uma_revisao_divergente_da_conflito_e_nao_ultimo_a_escrever_ganha() {
        let mut estado = CaseState::novo("case-1");
        estado.aplicar(&abrir(0, "c1")).unwrap();

        let atrasado = evento(
            0, // já não é 0: a abertura passou-o para 1
            "c2",
            CaseEvent::CaseClosed {
                resolution: "fechado por engano".into(),
            },
        );
        let erro = estado.aplicar(&atrasado).unwrap_err();
        assert_eq!(
            erro,
            CaseError::Conflito {
                case_id: "case-1".into(),
                esperada: 0,
                actual: 1,
            }
        );
        assert_eq!(
            estado.status,
            CaseStatus::Open,
            "o comando em conflito NAO pode ter efeito"
        );
    }

    /// §8.3 — repetir o mesmo `command_id` devolve o resultado original.
    ///
    /// E a ORDEM dos testes importa: a idempotencia e verificada ANTES da
    /// revisao. Um cliente que repete por timeout traz a revisao que tinha
    /// quando tentou — que ja nao e a actual porque a primeira tentativa
    /// passou. Testar a revisao primeiro devolveria "conflito" a um comando que
    /// teve sucesso.
    #[test]
    fn repetir_o_mesmo_comando_nao_aplica_duas_vezes_nem_da_conflito() {
        let mut estado = CaseState::novo("case-1");
        assert!(estado.aplicar(&abrir(0, "c1")).unwrap());

        let repetido = abrir(0, "c1");
        assert!(
            !estado.aplicar(&repetido).unwrap(),
            "a repeticao nao aplica"
        );
        assert_eq!(estado.revision, 1, "e nao avanca a revisao");

        // E, criticamente, NAO da conflito — apesar de a revisao esperada (0)
        // ja nao ser a actual (1).
        assert!(estado.aplicar(&repetido).is_ok());
    }

    #[test]
    fn escalar_duas_vezes_por_timeout_nao_acorda_duas_equipas() {
        let mut estado = CaseState::novo("case-1");
        estado.aplicar(&abrir(0, "c1")).unwrap();
        let escalada = evento(
            1,
            "esc-1",
            CaseEvent::CaseEscalated {
                to: "equipa-ir".into(),
                reason: "impacto confirmado".into(),
            },
        );
        estado.aplicar(&escalada).unwrap();
        estado.aplicar(&escalada).unwrap();
        assert_eq!(estado.escalations.len(), 1);
    }

    /// §8.4 — mudar a politica nao reescreve prazos historicos.
    #[test]
    fn os_prazos_ficam_congelados_na_politica_da_abertura() {
        let mut estado = CaseState::novo("case-1");
        estado.aplicar(&abrir(0, "c1")).unwrap();
        let gravado = estado.sla.clone().unwrap();

        // Uma politica nova entra em vigor. O caso ja aberto nao se mexe: nao
        // ha caminho no codigo que reescreva o SLA de um caso existente.
        assert_eq!(gravado.policy_version, "sla-v1");
        assert_eq!(gravado.triage_due_micros, Some(1_000));
        estado
            .aplicar(&evento(
                1,
                "c2",
                CaseEvent::CasePriorityChanged {
                    priority: CasePriority::Critical,
                },
            ))
            .unwrap();
        assert_eq!(
            estado.sla.as_ref().unwrap(),
            &gravado,
            "mudar a prioridade nao pode mexer nos prazos ja fixados"
        );
    }

    /// §8.5 — os tipos de evidencia sao distintos e nao se confundem.
    #[test]
    fn uma_hipotese_de_modelo_nao_se_confunde_com_uma_conclusao_de_analista() {
        let mut estado = CaseState::novo("case-1");
        estado.aplicar(&abrir(0, "c1")).unwrap();
        estado
            .aplicar(&evento(
                1,
                "n1",
                CaseEvent::CaseNoteAdded {
                    note_id: "n1".into(),
                    kind: EvidenceKind::ModelHypothesis,
                    author: "modelo".into(),
                    body: "possivel exfiltracao".into(),
                },
            ))
            .unwrap();
        estado
            .aplicar(&evento(
                2,
                "n2",
                CaseEvent::CaseNoteAdded {
                    note_id: "n2".into(),
                    kind: EvidenceKind::AnalystConclusion,
                    author: "analista-b".into(),
                    body: "confirmado, e um backup agendado".into(),
                },
            ))
            .unwrap();

        assert_eq!(estado.notes["n1"].kind, EvidenceKind::ModelHypothesis);
        assert_eq!(estado.notes["n2"].kind, EvidenceKind::AnalystConclusion);
        assert_ne!(estado.notes["n1"].kind, estado.notes["n2"].kind);
    }

    /// Rever uma nota EMPILHA: o que o analista escreveu antes fica.
    #[test]
    fn rever_uma_nota_nao_apaga_o_que_estava_la() {
        let mut estado = CaseState::novo("case-1");
        estado.aplicar(&abrir(0, "c1")).unwrap();
        estado
            .aplicar(&evento(
                1,
                "n1",
                CaseEvent::CaseNoteAdded {
                    note_id: "n1".into(),
                    kind: EvidenceKind::AnalystConclusion,
                    author: "analista-b".into(),
                    body: "parece ataque".into(),
                },
            ))
            .unwrap();
        estado
            .aplicar(&evento(
                2,
                "n1r",
                CaseEvent::CaseNoteRevised {
                    note_id: "n1".into(),
                    body: "afinal e um job de backup".into(),
                },
            ))
            .unwrap();

        let n = &estado.notes["n1"];
        assert_eq!(n.body, "afinal e um job de backup");
        assert_eq!(
            n.revisions,
            vec!["parece ataque".to_string()],
            "o raciocinio anterior tem de sobreviver a revisao"
        );
    }

    #[test]
    fn um_evento_antes_da_abertura_nao_inventa_um_caso() {
        let eventos = vec![evento(
            0,
            "c1",
            CaseEvent::CaseClosed {
                resolution: "?".into(),
            },
        )];
        assert!(reconstruir("case-1", &eventos).unwrap().is_none());
    }

    #[test]
    fn reabrir_nao_apaga_a_resolucao_anterior() {
        let mut estado = CaseState::novo("case-1");
        estado.aplicar(&abrir(0, "c1")).unwrap();
        estado
            .aplicar(&evento(
                1,
                "c2",
                CaseEvent::CaseClosed {
                    resolution: "falso positivo".into(),
                },
            ))
            .unwrap();
        estado
            .aplicar(&evento(
                2,
                "c3",
                CaseEvent::CaseReopened {
                    reason: "novo indicador".into(),
                },
            ))
            .unwrap();

        assert_eq!(estado.status, CaseStatus::Investigating);
        assert_eq!(
            estado.resolution.as_deref(),
            Some("falso positivo"),
            "um caso reaberto sem memoria do que o fechou perde a informacao \
             que explica porque foi reaberto"
        );
        assert!(estado.escalations.iter().any(|(t, _)| t == "reopen"));
    }

    #[test]
    fn o_envelope_atravessa_o_log_e_volta() {
        let envelope = abrir(0, "c1");
        let episodio = envelope.para_episodio().unwrap();
        assert_eq!(episodio.attrs["case.id"], "case-1");
        assert_eq!(episodio.attrs["case.event"], "CaseOpened");
        let volta = do_episodio(&episodio).unwrap();
        assert_eq!(volta, envelope);
    }

    #[test]
    fn um_comando_sem_motivo_ou_sem_principal_e_recusado() {
        for mau in [
            CaseEnvelope::novo(
                "c",
                "cmd",
                0,
                "",
                "razao",
                CaseEvent::CaseReopened { reason: "r".into() },
            ),
            CaseEnvelope::novo(
                "c",
                "cmd",
                0,
                "p",
                "  ",
                CaseEvent::CaseReopened { reason: "r".into() },
            ),
            CaseEnvelope::novo(
                "",
                "cmd",
                0,
                "p",
                "razao",
                CaseEvent::CaseReopened { reason: "r".into() },
            ),
            CaseEnvelope::novo(
                "c",
                "",
                0,
                "p",
                "razao",
                CaseEvent::CaseReopened { reason: "r".into() },
            ),
        ] {
            assert!(mau.validar().is_err(), "{mau:?} devia ser recusado");
        }
    }

    #[test]
    fn os_dezoito_eventos_da_seccao_8_2_existem_todos() {
        // Se alguem acrescentar um evento sem lhe dar nome, este teste nao o
        // apanha — mas se remover um dos 18 que a spec lista, apanha.
        let nomes = [
            "CaseOpened",
            "CaseTitleChanged",
            "CasePriorityChanged",
            "CaseOwnerAssigned",
            "CaseWatcherAdded",
            "CaseTaskCreated",
            "CaseTaskCompleted",
            "CaseNoteAdded",
            "CaseNoteRevised",
            "EvidenceBookmarked",
            "IncidentLinked",
            "IncidentUnlinked",
            "CaseEscalated",
            "CaseStatusChanged",
            "CaseMerged",
            "CaseSplit",
            "CaseClosed",
            "CaseReopened",
        ];
        assert_eq!(nomes.len(), 18);
        let amostras = [
            CaseEvent::CaseOpened {
                title: "t".into(),
                priority: CasePriority::Low,
                opened_by: "a".into(),
                sla: sla(),
            },
            CaseEvent::CaseTitleChanged { title: "t".into() },
            CaseEvent::CasePriorityChanged {
                priority: CasePriority::Low,
            },
            CaseEvent::CaseOwnerAssigned { owner: "o".into() },
            CaseEvent::CaseWatcherAdded {
                watcher: "w".into(),
            },
            CaseEvent::CaseTaskCreated {
                task_id: "t".into(),
                description: "d".into(),
                assignee: None,
            },
            CaseEvent::CaseTaskCompleted {
                task_id: "t".into(),
            },
            CaseEvent::CaseNoteAdded {
                note_id: "n".into(),
                kind: EvidenceKind::RawEvidence,
                author: "a".into(),
                body: "b".into(),
            },
            CaseEvent::CaseNoteRevised {
                note_id: "n".into(),
                body: "b".into(),
            },
            CaseEvent::EvidenceBookmarked {
                lsn: 1,
                kind: EvidenceKind::RawEvidence,
                note: None,
            },
            CaseEvent::IncidentLinked {
                incident_id: "i".into(),
            },
            CaseEvent::IncidentUnlinked {
                incident_id: "i".into(),
            },
            CaseEvent::CaseEscalated {
                to: "t".into(),
                reason: "r".into(),
            },
            CaseEvent::CaseStatusChanged {
                status: CaseStatus::Triage,
            },
            CaseEvent::CaseMerged {
                into_case_id: "c".into(),
            },
            CaseEvent::CaseSplit {
                new_case_id: "c".into(),
            },
            CaseEvent::CaseClosed {
                resolution: "r".into(),
            },
            CaseEvent::CaseReopened { reason: "r".into() },
        ];
        assert_eq!(amostras.len(), 18);
        for (evento, esperado) in amostras.iter().zip(nomes) {
            assert_eq!(evento.nome(), esperado);
        }
    }

    /// Auditoria 2026-09-05, A08 — o log e imutavel: um envelope que nunca
    /// devia la ter entrado NAO pode tornar o caso ilegivel para sempre.
    ///
    /// Dois analistas em corrida (`case_command` le a revisao e so depois
    /// apende, sem lock por `case_id`) deixam no log duas revisoes iguais com
    /// `command_id` distintos. Abortar a reconstrucao por causa da segunda
    /// mataria o caso: toda a leitura e todo o comando seguinte passam por
    /// `reconstruir`.
    #[test]
    fn reconstruir_ignora_o_envelope_em_conflito_em_vez_de_abortar() {
        let eventos = vec![
            abrir(0, "c1"),
            evento(
                1,
                "c2",
                CaseEvent::CaseStatusChanged {
                    status: CaseStatus::Contained,
                },
            ),
            // O perdedor da corrida: mesma revisao esperada, comando diferente.
            evento(
                1,
                "c3",
                CaseEvent::CaseClosed {
                    resolution: "fechado por engano".into(),
                },
            ),
        ];

        let estado = reconstruir("case-1", &eventos)
            .expect("um envelope em conflito nao pode abortar a reconstrucao")
            .expect("o caso foi aberto");
        assert_eq!(estado.revision, 2, "o envelope em conflito nao conta");
        assert_eq!(
            estado.status,
            CaseStatus::Contained,
            "o comando em conflito NAO pode ter efeito"
        );
        assert!(
            estado.resolution.is_none(),
            "o perdedor da corrida nao pode fechar o caso"
        );
    }

    /// Auditoria 2026-09-05, A08 — o mesmo, mas por `validar()`: qualquer
    /// Writer pode apender um episodio com o kind `SecurityCase` e conteudo a
    /// gosto, e um `schema` errado bastava para envenenar o caso.
    #[test]
    fn reconstruir_ignora_envelope_invalido_injectado_em_bruto() {
        let mut forjado = evento(
            1,
            "c2",
            CaseEvent::CaseClosed {
                resolution: "injectado".into(),
            },
        );
        forjado.schema = "spoof/9".into();
        assert!(forjado.validar().is_err(), "o envelope tem de ser invalido");

        let estado = reconstruir("case-1", &[abrir(0, "c1"), forjado])
            .expect("um envelope invalido nao pode abortar a reconstrucao")
            .expect("o caso foi aberto");
        assert_eq!(estado.revision, 1);
        assert_eq!(estado.status, CaseStatus::Open);
    }

    /// Auditoria 2026-09-05, A08 — envenenar ANTES da abertura era ainda pior:
    /// um `CaseOpened` invalido bloqueava a criacao do caso para sempre.
    #[test]
    fn um_caseopened_invalido_nao_cria_caso_nem_aborta() {
        let mut forjado = abrir(0, "c1");
        forjado.principal = "   ".into();

        assert!(
            reconstruir("case-1", &[forjado])
                .expect("nao pode abortar")
                .is_none(),
            "um CaseOpened invalido nao abre o caso"
        );
    }

    /// Auditoria 2026-09-05, A08 — saltar nao pode ser saltar EM SILENCIO: num
    /// caso de seguranca, um comando que esta no log mas nao esta na view e
    /// exactamente o que a auditoria precisa de ver.
    #[test]
    fn reconstruir_auditado_expoe_os_envelopes_rejeitados() {
        let mut forjado = evento(
            1,
            "c3",
            CaseEvent::CaseClosed {
                resolution: "injectado".into(),
            },
        );
        forjado.schema = "spoof/9".into();
        let eventos = vec![
            abrir(0, "c1"),
            evento(
                1,
                "c2",
                CaseEvent::CaseStatusChanged {
                    status: CaseStatus::Contained,
                },
            ),
            forjado,
            // E o perdedor de uma corrida, ja depois de "c2" ter passado.
            evento(
                1,
                "c4",
                CaseEvent::CaseClosed {
                    resolution: "fechado por engano".into(),
                },
            ),
        ];

        let (estado, rejeitados) = reconstruir_auditado("case-1", &eventos);
        assert_eq!(estado.unwrap().revision, 2);
        assert_eq!(
            rejeitados
                .iter()
                .map(|r| r.command_id.as_str())
                .collect::<Vec<_>>(),
            vec!["c3", "c4"],
            "os rejeitados nao podem desaparecer da auditoria"
        );
        assert!(matches!(rejeitados[0].erro, CaseError::Invalido(_)));
        assert!(matches!(rejeitados[1].erro, CaseError::Conflito { .. }));
    }
}
