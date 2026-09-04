//! SPEC-0072 §14–§18 — reconciliação tripartite do arranque.
//!
//! O arranque do Sentinel não pode olhar para o cursor isoladamente. O cursor
//! regista apenas o progresso do *stream*; o estado em memória (grafo,
//! baselines, histórico de regras) vem do snapshot. São três números, e é a
//! relação entre os três que decide o que o arranque tem de fazer:
//!
//! ```text
//! watermark (W) <= cursor (C) <= head (H)
//! ```
//!
//! O código anterior a esta SPEC olhava para um par e abortava:
//!
//! ```text
//! if cursor.next_lsn > log.head() { return Err(...) }
//! ```
//!
//! Isso é a política `strict` aplicada sem alternativa e sem registo. Pelo
//! INV-4, nada do que o Sentinel persiste fora do log é source of truth — o
//! cursor é derivado. Recusar arrancar por causa de um artefacto derivado é
//! deixar a base indisponível para proteger uma cópia. O default passa a ser
//! `rebuild`, com a divergência registada em telemetria e o cursor divergente
//! preservado para auditoria (§16); `strict` continua disponível para
//! ambientes forenses, mas agora é uma escolha declarada.

use crate::error::SentinelError;
use heraclitus_core::{CursorPolicy, Lsn};

/// Porque é que o arranque vai reconstruir a partir do log canónico.
///
/// Existe para telemetria e para a mensagem de log obrigatória da §25: "o
/// snapshot não serviu" não é diagnóstico; *qual* das razões serviu é.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebuildReason {
    /// Primeiro arranque, ou o ficheiro nunca foi publicado.
    SnapshotAusente,
    /// O digest BLAKE3 não bate com o conteúdo (§8).
    DigestInvalido,
    /// `format_version` que este binário não sabe ler.
    FormatoDesconhecido { encontrado: u32, suportado: u32 },
    /// O snapshot foi produzido por outra versão do pipeline (§46).
    PipelineDiferente { encontrado: u32, configurado: u32 },
    /// O ficheiro existe mas não se deixa ler ou desserializar.
    Ilegivel(String),
    /// Divergência patológica sob a política `rebuild` (§17).
    Divergencia(StateDivergenceReason),
}

impl RebuildReason {
    /// Etiqueta estável para métricas e logs. Não muda com o texto.
    pub fn etiqueta(&self) -> &'static str {
        match self {
            Self::SnapshotAusente => "snapshot_ausente",
            Self::DigestInvalido => "digest_invalido",
            Self::FormatoDesconhecido { .. } => "formato_desconhecido",
            Self::PipelineDiferente { .. } => "pipeline_diferente",
            Self::Ilegivel(_) => "ilegivel",
            Self::Divergencia(_) => "divergencia",
        }
    }
}

/// As três violações de invariante que a §15 (caso 4) classifica como
/// patológicas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateDivergenceReason {
    /// O cursor avançou para além do log canónico.
    ///
    /// Só há duas maneiras honestas de aqui chegar: o log perdeu a cauda
    /// (restauro de backup, truncagem por corrupção), ou o cursor foi
    /// escrito antes do append a que se refere ser durável — que é
    /// exactamente o que o INV-2 diz que o cursor nunca prova.
    CursorAlemDoHead { cursor: Lsn, head: Lsn },
    /// O snapshot afirma estado válido para LSNs que o log não tem.
    SnapshotAlemDoHead { watermark: Lsn, head: Lsn },
    /// O cursor regrediu para trás do snapshot: o estado em memória saberia
    /// mais do que o stream diz ter processado.
    CursorAtrasDoSnapshot { cursor: Lsn, watermark: Lsn },
}

impl StateDivergenceReason {
    pub fn etiqueta(&self) -> &'static str {
        match self {
            Self::CursorAlemDoHead { .. } => "cursor_alem_do_head",
            Self::SnapshotAlemDoHead { .. } => "snapshot_alem_do_head",
            Self::CursorAtrasDoSnapshot { .. } => "cursor_atras_do_snapshot",
        }
    }
}

impl std::fmt::Display for StateDivergenceReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CursorAlemDoHead { cursor, head } => {
                write!(f, "cursor next_lsn={cursor} está além do head={head}")
            }
            Self::SnapshotAlemDoHead { watermark, head } => {
                write!(f, "snapshot watermark={watermark} está além do head={head}")
            }
            Self::CursorAtrasDoSnapshot { cursor, watermark } => write!(
                f,
                "cursor next_lsn={cursor} está atrás do snapshot watermark={watermark}"
            ),
        }
    }
}

/// O que o arranque tem de fazer, decidido a partir de `(head, cursor,
/// watermark)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupReconciliation {
    /// `watermark == cursor == head`. Nada a reproduzir; o arranque é O(1) no
    /// tamanho da base — é isto que o INV-5 compra.
    Synchronized { cursor: Lsn },
    /// Snapshot válido até `watermark`; falta reproduzir `[watermark, head)`.
    CatchUpTail {
        watermark: Lsn,
        head: Lsn,
        cursor: Lsn,
    },
    /// Sem snapshot utilizável: rebuild em streaming sobre `[0, head)`.
    RebuildCanonical { head: Lsn, reason: RebuildReason },
    /// Violação de invariante. Sob `rebuild` é convertida em
    /// `RebuildCanonical` por [`StartupReconciliation::aplicar_politica`];
    /// sob `strict` recusa o arranque.
    DivergenceDetected {
        head: Lsn,
        reason: StateDivergenceReason,
    },
}

impl StartupReconciliation {
    /// Etiqueta estável para a métrica e para a linha de log da §25.
    pub fn etiqueta(&self) -> &'static str {
        match self {
            Self::Synchronized { .. } => "synchronized",
            Self::CatchUpTail { .. } => "catch_up_tail",
            Self::RebuildCanonical { .. } => "rebuild_canonical",
            Self::DivergenceDetected { .. } => "divergence_detected",
        }
    }

    /// O intervalo de LSN que o arranque tem de reproduzir, `[de, até)`.
    ///
    /// É esta função — e não o chamador — que garante o INV-5: `CatchUpTail`
    /// devolve a cauda, nunca a base inteira.
    pub fn intervalo_de_replay(&self) -> Option<(Lsn, Lsn)> {
        match self {
            Self::Synchronized { .. } => None,
            Self::CatchUpTail {
                watermark, head, ..
            } => Some((*watermark, *head)),
            Self::RebuildCanonical { head, .. } => Some((0, *head)),
            Self::DivergenceDetected { .. } => None,
        }
    }

    /// Aplica a política de recuperação da §17.
    ///
    /// A separação é deliberada: [`reconcile_startup_state`] responde "qual é
    /// o estado", e isto responde "o que fazemos com ele". Misturá-las era o
    /// que o código antigo fazia — o `return Err` estava soldado à detecção, e
    /// por isso não havia como escolher outra coisa.
    pub fn aplicar_politica(self, politica: CursorPolicy) -> Result<Self, SentinelError> {
        match (self, politica) {
            (Self::DivergenceDetected { reason, .. }, CursorPolicy::Strict) => {
                Err(SentinelError::Cursor(format!(
                    "{reason}; sentinel.recovery.cursor_policy=strict recusa recuperação automática"
                )))
            }
            (Self::DivergenceDetected { head, reason }, CursorPolicy::Rebuild) => {
                Ok(Self::RebuildCanonical {
                    head,
                    reason: RebuildReason::Divergencia(reason),
                })
            }
            (outro, _) => Ok(outro),
        }
    }
}

/// A reconciliação tripartite propriamente dita (§14).
///
/// É pura de propósito. A assinatura da spec recebe `&AnyLog` e
/// `Option<&SentinelStateSnapshot>`, mas o log só é consultado por `head()` e
/// o snapshot só por `applied_until_exclusive`; passar os três números torna
/// toda a matriz da §15 testável sem construir um log em disco. O invólucro
/// que fala com o log vive no arranque.
///
/// `watermark` é `None` quando não há snapshot utilizável, e nesse caso
/// `motivo_sem_snapshot` diz porquê.
pub fn reconcile_startup_state(
    head: Lsn,
    cursor_next_lsn: Lsn,
    watermark: Option<Lsn>,
    motivo_sem_snapshot: RebuildReason,
) -> StartupReconciliation {
    // As violações de invariante são testadas ANTES de qualquer outra coisa.
    // Um cursor além do head com snapshot válido continua a ser divergência:
    // classificar primeiro pelo snapshot esconderia a perda de cauda por trás
    // de um catch-up que leria zero eventos e daria tudo por bom.
    if cursor_next_lsn > head {
        return StartupReconciliation::DivergenceDetected {
            head,
            reason: StateDivergenceReason::CursorAlemDoHead {
                cursor: cursor_next_lsn,
                head,
            },
        };
    }
    if let Some(w) = watermark {
        if w > head {
            return StartupReconciliation::DivergenceDetected {
                head,
                reason: StateDivergenceReason::SnapshotAlemDoHead {
                    watermark: w,
                    head,
                },
            };
        }
        if cursor_next_lsn < w {
            return StartupReconciliation::DivergenceDetected {
                head,
                reason: StateDivergenceReason::CursorAtrasDoSnapshot {
                    cursor: cursor_next_lsn,
                    watermark: w,
                },
            };
        }
    }

    let Some(w) = watermark else {
        return StartupReconciliation::RebuildCanonical {
            head,
            reason: motivo_sem_snapshot,
        };
    };

    if w == head && cursor_next_lsn == head {
        StartupReconciliation::Synchronized {
            cursor: cursor_next_lsn,
        }
    } else {
        StartupReconciliation::CatchUpTail {
            watermark: w,
            head,
            cursor: cursor_next_lsn,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caso_1_sincronizado_nao_reproduz_nada() {
        let r = reconcile_startup_state(1_000, 1_000, Some(1_000), RebuildReason::SnapshotAusente);
        assert_eq!(r, StartupReconciliation::Synchronized { cursor: 1_000 });
        assert_eq!(r.intervalo_de_replay(), None);
    }

    #[test]
    fn caso_2_cauda_pendente_reproduz_so_a_cauda() {
        // É este o teste do INV-5: numa base de 100M eventos com o snapshot a
        // 4 eventos do fim, o arranque lê 4 — não 100M.
        let r = reconcile_startup_state(
            100_000_000,
            99_999_996,
            Some(99_999_996),
            RebuildReason::SnapshotAusente,
        );
        assert_eq!(r.intervalo_de_replay(), Some((99_999_996, 100_000_000)));
        assert!(matches!(r, StartupReconciliation::CatchUpTail { .. }));
    }

    #[test]
    fn caso_3_sem_snapshot_reconstroi_do_zero_com_o_motivo_preservado() {
        let r = reconcile_startup_state(500, 0, None, RebuildReason::DigestInvalido);
        assert_eq!(
            r,
            StartupReconciliation::RebuildCanonical {
                head: 500,
                reason: RebuildReason::DigestInvalido,
            }
        );
        assert_eq!(r.intervalo_de_replay(), Some((0, 500)));
    }

    #[test]
    fn um_cursor_avancado_sem_snapshot_nao_e_dado_por_bom() {
        // Sem snapshot o watermark é 0, e 0 <= cursor sempre. Se a divergência
        // só fosse testada contra o watermark, este caso — cursor além do head,
        // que é perda de cauda — passaria despercebido.
        let r = reconcile_startup_state(10, 42, None, RebuildReason::SnapshotAusente);
        assert_eq!(
            r,
            StartupReconciliation::DivergenceDetected {
                head: 10,
                reason: StateDivergenceReason::CursorAlemDoHead {
                    cursor: 42,
                    head: 10
                },
            }
        );
    }

    #[test]
    fn caso_4_as_tres_divergencias_patologicas() {
        assert!(matches!(
            reconcile_startup_state(10, 11, Some(5), RebuildReason::SnapshotAusente),
            StartupReconciliation::DivergenceDetected {
                reason: StateDivergenceReason::CursorAlemDoHead { .. },
                ..
            }
        ));
        assert!(matches!(
            reconcile_startup_state(10, 10, Some(11), RebuildReason::SnapshotAusente),
            StartupReconciliation::DivergenceDetected {
                reason: StateDivergenceReason::SnapshotAlemDoHead { .. },
                ..
            }
        ));
        assert!(matches!(
            reconcile_startup_state(10, 3, Some(7), RebuildReason::SnapshotAusente),
            StartupReconciliation::DivergenceDetected {
                reason: StateDivergenceReason::CursorAtrasDoSnapshot { .. },
                ..
            }
        ));
    }

    #[test]
    fn um_cursor_alem_do_head_com_snapshot_valido_continua_a_ser_divergencia() {
        // Se a classificação olhasse primeiro para o snapshot, este caso daria
        // `CatchUpTail{watermark: 10, head: 10}` — zero eventos a reproduzir —
        // e o arranque declararia tudo em ordem enquanto o cursor prova que se
        // perdeu cauda do log.
        let r = reconcile_startup_state(10, 12, Some(10), RebuildReason::SnapshotAusente);
        assert!(matches!(
            r,
            StartupReconciliation::DivergenceDetected {
                reason: StateDivergenceReason::CursorAlemDoHead { .. },
                ..
            }
        ));
    }

    #[test]
    fn a_politica_strict_recusa_e_a_rebuild_reconstroi() {
        let divergente =
            reconcile_startup_state(10, 42, Some(5), RebuildReason::SnapshotAusente);

        let erro = divergente
            .clone()
            .aplicar_politica(CursorPolicy::Strict)
            .unwrap_err();
        assert!(
            erro.to_string().contains("strict"),
            "a mensagem tem de dizer que foi a política que recusou: {erro}"
        );

        let recuperado = divergente.aplicar_politica(CursorPolicy::Rebuild).unwrap();
        assert_eq!(
            recuperado,
            StartupReconciliation::RebuildCanonical {
                head: 10,
                reason: RebuildReason::Divergencia(StateDivergenceReason::CursorAlemDoHead {
                    cursor: 42,
                    head: 10
                }),
            }
        );
        assert_eq!(
            recuperado.intervalo_de_replay(),
            Some((0, 10)),
            "reconstruir a partir do log canónico é reconstruir do zero, \
             não aceitar o cursor divergente"
        );
    }

    #[test]
    fn a_politica_nao_toca_nos_casos_saudaveis() {
        for r in [
            reconcile_startup_state(10, 10, Some(10), RebuildReason::SnapshotAusente),
            reconcile_startup_state(10, 5, Some(5), RebuildReason::SnapshotAusente),
            reconcile_startup_state(10, 0, None, RebuildReason::SnapshotAusente),
        ] {
            assert_eq!(
                r.clone().aplicar_politica(CursorPolicy::Strict).unwrap(),
                r,
                "strict só recusa divergência; não é um modo mais lento"
            );
            assert_eq!(r.clone().aplicar_politica(CursorPolicy::Rebuild).unwrap(), r);
        }
    }

    #[test]
    fn nunca_e_inventado_um_lsn_que_o_log_nao_prove() {
        // §18: recovery não pode fazer `cursor.next_lsn = head`. A única saída
        // desta função que avança o cursor é a que também manda reproduzir o
        // intervalo correspondente.
        for (head, cursor, w) in [
            (100u64, 42u64, Some(42u64)),
            (100, 0, None),
            (100, 150, Some(10)),
        ] {
            let r = reconcile_startup_state(head, cursor, w, RebuildReason::SnapshotAusente)
                .aplicar_politica(CursorPolicy::Rebuild)
                .unwrap();
            match r {
                StartupReconciliation::Synchronized { cursor } => assert_eq!(cursor, head),
                outro => {
                    let (de, ate) = outro.intervalo_de_replay().expect("tem de reproduzir");
                    assert_eq!(ate, head);
                    assert!(
                        de <= head,
                        "o início do replay nunca pode estar além do head"
                    );
                }
            }
        }
    }
}
