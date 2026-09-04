//! Durable LSN cursor for replayable Sentinel processing.

use crate::error::SentinelError;
use heraclitus_core::Lsn;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentinelCursor {
    pub next_lsn: Lsn,
    pub pipeline_version: u32,
}

impl SentinelCursor {
    pub const fn new(pipeline_version: u32) -> Self {
        Self {
            next_lsn: 0,
            pipeline_version,
        }
    }
}

/// SPEC-0072 §35 — porque é que o cursor no disco não serviu.
///
/// Existe para que a rejeição seja *visível*. A alternativa — devolver um
/// cursor a zero e seguir — é a definição de estado silenciosamente inventado
/// que a §35 proíbe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorRejeitado {
    pub motivo: String,
    /// Onde ficou o ficheiro rejeitado, quando foi possível guardá-lo.
    pub preservado_em: Option<PathBuf>,
}

/// Atomic cursor persistence.  A missing cursor is a clean first boot; a
/// malformed one is an error rather than silently replaying from zero.
#[derive(Debug, Clone)]
pub struct CursorStore {
    path: PathBuf,
}

impl CursorStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self, pipeline_version: u32) -> Result<SentinelCursor, SentinelError> {
        if !self.path.exists() {
            return Ok(SentinelCursor::new(pipeline_version));
        }
        let bytes = std::fs::read(&self.path)?;
        let cursor: SentinelCursor = serde_json::from_slice(&bytes)
            .map_err(|error| SentinelError::Cursor(format!("{}: {error}", self.path.display())))?;
        if cursor.pipeline_version != pipeline_version {
            return Err(SentinelError::Cursor(format!(
                "pipeline version mismatch: cursor={} configured={}",
                cursor.pipeline_version, pipeline_version
            )));
        }
        Ok(cursor)
    }

    /// SPEC-0072 §35 — carrega o cursor sem recusar o arranque por causa de um
    /// ficheiro mau.
    ///
    /// [`Self::load`] devolve `Err` para JSON truncado, JSON inválido, ficheiro
    /// vazio ou versão de pipeline diferente. Isso satisfaz metade da §35 — o
    /// estado nunca é *silenciosamente* inventado — mas deixa a base sem
    /// arrancar por causa de um artefacto que o INV-4 classifica como derivado
    /// e descartável.
    ///
    /// Esta variante separa as duas perguntas: devolve o cursor **e** o motivo
    /// pelo qual o ficheiro no disco não serviu, se não serviu. Quem arranca
    /// decide o que fazer com o motivo — sob `strict` recusa, sob `rebuild`
    /// reconstrói a partir do log. O que não pode acontecer, e não acontece, é
    /// o motivo desaparecer: o ficheiro rejeitado é preservado e o motivo sobe
    /// para a telemetria.
    ///
    /// O cursor devolvido em caso de rejeição é `next_lsn = 0` — não uma
    /// adivinha. Zero não é inventar um LSN: é dizer "não sei nada", que é
    /// exactamente verdade, e obriga ao rebuild canónico.
    pub fn carregar_tolerante(
        &self,
        pipeline_version: u32,
    ) -> Result<(SentinelCursor, Option<CursorRejeitado>), SentinelError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Primeiro arranque limpo. Não é rejeição nenhuma.
                return Ok((SentinelCursor::new(pipeline_version), None));
            }
            Err(error) => {
                return Ok((
                    SentinelCursor::new(pipeline_version),
                    Some(CursorRejeitado {
                        motivo: format!("ilegível: {error}"),
                        preservado_em: None,
                    }),
                ));
            }
        };
        let rejeitar = |motivo: String| -> Result<_, SentinelError> {
            let preservado = self.preservar_rejeitado(&bytes).ok();
            Ok((
                SentinelCursor::new(pipeline_version),
                Some(CursorRejeitado {
                    motivo,
                    preservado_em: preservado,
                }),
            ))
        };
        if bytes.is_empty() {
            return rejeitar("ficheiro vazio".into());
        }
        let cursor: SentinelCursor = match serde_json::from_slice(&bytes) {
            Ok(cursor) => cursor,
            Err(error) => return rejeitar(format!("JSON inválido: {error}")),
        };
        if cursor.pipeline_version != pipeline_version {
            return rejeitar(format!(
                "pipeline version mismatch: cursor={} configurado={pipeline_version}",
                cursor.pipeline_version
            ));
        }
        Ok((cursor, None))
    }

    /// Guarda o conteúdo rejeitado com um nome derivado do próprio conteúdo.
    /// Determinístico: o mesmo ficheiro mau converge para o mesmo destino em
    /// vez de acumular uma cópia por arranque.
    fn preservar_rejeitado(&self, bytes: &[u8]) -> Result<PathBuf, SentinelError> {
        let parent = self.path.parent().ok_or_else(|| {
            SentinelError::Cursor("cursor path must have an explicit parent".into())
        })?;
        std::fs::create_dir_all(parent)?;
        let digest = blake3::hash(bytes).to_hex();
        let destino = parent.join(format!("cursor.rejeitado.{}.json", &digest[..16]));
        std::fs::write(&destino, bytes)?;
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(destino)
    }

    /// SPEC-0072 §16 — preserva o cursor divergente antes de o substituir.
    ///
    /// O passo 1 da §16 é "preservar cursor divergente para auditoria". Sem
    /// isto, a política `rebuild` apagaria a única prova de que houve
    /// divergência: reconstruía o estado, escrevia um cursor novo e coerente, e
    /// não sobrava nada que dissesse que o log tinha perdido cauda.
    ///
    /// O nome é **determinístico**, derivado dos dois números que definem a
    /// divergência, e não de um relógio. A spec aceita "timestamp ou
    /// equivalente determinístico/auditável", e um timestamp teria dois
    /// defeitos: dois arranques da mesma divergência produziriam dois
    /// ficheiros que dizem o mesmo, e o teste não conseguiria nomear o
    /// ficheiro que espera. Com `next<N>.head<H>` a mesma divergência
    /// converge para o mesmo ficheiro, e duas divergências diferentes nunca
    /// colidem.
    ///
    /// Devolve o caminho escrito.
    pub fn preservar_divergente(
        &self,
        cursor: SentinelCursor,
        head: heraclitus_core::Lsn,
    ) -> Result<PathBuf, SentinelError> {
        let parent = self.path.parent().ok_or_else(|| {
            SentinelError::Cursor("cursor path must have an explicit parent".into())
        })?;
        std::fs::create_dir_all(parent)?;
        let destino = parent.join(format!(
            "cursor.divergent.next{}.head{head}.json",
            cursor.next_lsn
        ));
        let bytes = serde_json::to_vec_pretty(&cursor)
            .map_err(|error| SentinelError::Cursor(error.to_string()))?;
        std::fs::write(&destino, &bytes)?;
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(destino)
    }

    pub fn commit(&self, cursor: SentinelCursor) -> Result<(), SentinelError> {
        let parent = self.path.parent().ok_or_else(|| {
            SentinelError::Cursor("cursor path must have an explicit parent".into())
        })?;
        std::fs::create_dir_all(parent)?;
        let temp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&cursor)
            .map_err(|error| SentinelError::Cursor(error.to_string()))?;
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        // POSIX rename replaces atomically.  Windows refuses replacement, so
        // retry with the documented remove+rename fallback; the temporary file
        // is always complete and durable before this point.
        //
        // O fallback TEM de ser exclusivo do Windows. Não estava gated, e em
        // Linux isso era destrutivo: aqui o `rename` substitui sempre, logo só
        // falha por uma razão real — ENOSPC, EACCES, EIO. Nessas condições o
        // ramo apagava o cursor VIVO e tentava outra vez, falhando pelo mesmo
        // motivo. Um erro de I/O transitório passava a perda do cursor, e com
        // ele o Sentinel perde a posição e reprocessa a base do início.
        match std::fs::rename(&temp, &self.path) {
            Ok(()) => {}
            Err(error) => {
                #[cfg(windows)]
                {
                    if self.path.exists() {
                        std::fs::remove_file(&self.path)?;
                        std::fs::rename(&temp, &self.path)?;
                    } else {
                        return Err(error.into());
                    }
                }
                #[cfg(not(windows))]
                {
                    let _ = std::fs::remove_file(&temp);
                    return Err(error.into());
                }
            }
        }
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip_and_version_guard() {
        let temp = tempfile::tempdir().unwrap();
        let store = CursorStore::new(temp.path().join("sentinel/cursor.json"));
        assert_eq!(store.load(3).unwrap(), SentinelCursor::new(3));
        store
            .commit(SentinelCursor {
                next_lsn: 42,
                pipeline_version: 3,
            })
            .unwrap();
        assert_eq!(store.load(3).unwrap().next_lsn, 42);
        assert!(store.load(4).is_err());
    }
}

#[cfg(test)]
mod testes_spec0072 {
    use super::*;

    fn loja() -> (tempfile::TempDir, CursorStore) {
        let temp = tempfile::tempdir().unwrap();
        let store = CursorStore::new(temp.path().join("sentinel/cursor.json"));
        (temp, store)
    }

    #[test]
    fn um_cursor_ausente_continua_a_ser_primeiro_arranque_limpo() {
        let (_t, store) = loja();
        let (cursor, rejeicao) = store.carregar_tolerante(3).unwrap();
        assert_eq!(cursor, SentinelCursor::new(3));
        assert!(
            rejeicao.is_none(),
            "não haver ficheiro não é o ficheiro estar mau"
        );
    }

    #[test]
    fn os_quatro_casos_da_seccao_35_sao_rejeitados_com_motivo_e_preservados() {
        // §35: JSON truncado, JSON inválido, pipeline mismatch, ficheiro vazio.
        // "Nenhum caso pode resultar em estado silenciosamente inventado" — o
        // que este teste fixa é o *silenciosamente*: o cursor volta a zero, mas
        // com motivo e com o ficheiro original guardado.
        let casos: [(&str, &[u8]); 4] = [
            ("vazio", b""),
            ("truncado", b"{\"next_lsn\": 42, \"pipeline_ver"),
            ("inválido", b"isto nao e json"),
            ("mismatch", b"{\"next_lsn\":42,\"pipeline_version\":9}"),
        ];
        for (nome, conteudo) in casos {
            let (_t, store) = loja();
            std::fs::create_dir_all(store.path().parent().unwrap()).unwrap();
            std::fs::write(store.path(), conteudo).unwrap();

            let (cursor, rejeicao) = store.carregar_tolerante(3).unwrap();
            assert_eq!(
                cursor.next_lsn, 0,
                "{nome}: um cursor rejeitado não pode devolver posição nenhuma"
            );
            let rejeicao = rejeicao.unwrap_or_else(|| panic!("{nome}: tinha de ser rejeitado"));
            assert!(
                !rejeicao.motivo.is_empty(),
                "{nome}: a rejeição tem de dizer porquê"
            );
            if !conteudo.is_empty() {
                let guardado = rejeicao
                    .preservado_em
                    .unwrap_or_else(|| panic!("{nome}: o ficheiro tinha de ser preservado"));
                assert_eq!(
                    std::fs::read(&guardado).unwrap(),
                    conteudo,
                    "{nome}: o preservado tem de ser byte a byte o original"
                );
            }
        }
    }

    #[test]
    fn preservar_o_mesmo_ficheiro_mau_duas_vezes_nao_acumula_copias() {
        let (_t, store) = loja();
        std::fs::create_dir_all(store.path().parent().unwrap()).unwrap();
        std::fs::write(store.path(), b"nao e json").unwrap();

        let primeiro = store.carregar_tolerante(1).unwrap().1.unwrap();
        let segundo = store.carregar_tolerante(1).unwrap().1.unwrap();
        assert_eq!(
            primeiro.preservado_em, segundo.preservado_em,
            "o nome é derivado do conteúdo; dois arranques da mesma \
             corrupção não podem encher o directório"
        );
    }

    #[test]
    fn um_cursor_valido_atravessa_a_leitura_tolerante_intacto() {
        let (_t, store) = loja();
        let original = SentinelCursor {
            next_lsn: 4_096,
            pipeline_version: 3,
        };
        store.commit(original).unwrap();
        let (lido, rejeicao) = store.carregar_tolerante(3).unwrap();
        assert_eq!(lido, original);
        assert!(rejeicao.is_none());
    }

    #[test]
    fn o_cursor_divergente_e_preservado_com_nome_deterministico() {
        // §16 passo 1. Sem isto a política `rebuild` apagava a única prova de
        // que houve divergência: reconstruía, escrevia um cursor coerente, e
        // não sobrava nada a dizer que o log tinha perdido cauda.
        let (_t, store) = loja();
        let divergente = SentinelCursor {
            next_lsn: 500,
            pipeline_version: 1,
        };
        let destino = store.preservar_divergente(divergente, 100).unwrap();
        assert_eq!(
            destino.file_name().unwrap().to_string_lossy(),
            "cursor.divergent.next500.head100.json"
        );
        let relido: SentinelCursor =
            serde_json::from_slice(&std::fs::read(&destino).unwrap()).unwrap();
        assert_eq!(relido, divergente);

        assert_eq!(
            store.preservar_divergente(divergente, 100).unwrap(),
            destino,
            "a mesma divergência converge para o mesmo ficheiro"
        );
        assert_ne!(
            store.preservar_divergente(divergente, 101).unwrap(),
            destino,
            "divergências diferentes não podem colidir"
        );
    }
}
