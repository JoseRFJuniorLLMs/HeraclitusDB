//! Varrimento janelado do log, partilhado pelos replays de compliance.
//!
//! Todos os `state()` deste crate reconstruíam o seu estado com
//! `log.scan(0, end)` — e `scan` é literalmente `scan_capped(from, to,
//! usize::MAX)`, ou seja materializa o log **inteiro** num `Vec<(Lsn,
//! Episode)>` antes de olhar para a primeira linha.
//!
//! Isso não era só o arranque a ficar lento. Seis handlers gRPC de papel
//! `Auditor` — o mais baixo com acesso de leitura — disparam um destes replays
//! por chamada, e `GET /compliance/status` dispara cinco. Uma consulta de
//! leitura de baixo privilégio conseguia obrigar o servidor a carregar a base
//! toda para RAM, o que é uma negação de serviço barata antes de ser um
//! problema de desempenho.
//!
//! O padrão certo já existia no repositório — o «scan janelado» do R22
//! (`heraclitus-raft/src/consensus.rs`) e do R25
//! (`heraclitus-analytics/src/flight.rs`). O `heraclitus-compliance` era o
//! único crate com zero utilizações de `scan_capped`, o que explica porque é
//! que todos os replays por migrar se concentravam aqui.
//!
//! A memória passa a ser limitada pelo estado materializado mais uma janela,
//! em vez de pelo tamanho da base. O custo em tempo é o mesmo: percorrem-se as
//! mesmas linhas.

use heraclitus_core::{Episode, HeraclitusError, Lsn};
use heraclitus_log::EpisodeLog;

/// Quantos episódios cada janela traz para RAM de cada vez.
///
/// 20 000 é o mesmo valor que o resto do servidor já usa nos varrimentos
/// janelados; grande o suficiente para o custo por janela ser irrelevante,
/// pequeno o suficiente para o pico de memória não depender da base.
pub(crate) const JANELA: usize = 20_000;

/// Percorre `[0, ate)` em janelas, chamando `visitar` por episódio.
///
/// `mapear_erro` converte a falha de leitura do log no erro do módulo que
/// chama — cada replay de compliance tem o seu, e passá-lo explicitamente
/// evita impor um `From` a todos eles.
pub(crate) fn por_episodio<L, E, F, M>(
    log: &L,
    ate: Lsn,
    mapear_erro: M,
    mut visitar: F,
) -> Result<(), E>
where
    L: EpisodeLog + ?Sized,
    F: FnMut(Lsn, Episode) -> Result<(), E>,
    M: Fn(HeraclitusError) -> E,
{
    let mut cursor: Lsn = 0;
    while cursor < ate {
        let janela = log.scan_capped(cursor, ate, JANELA).map_err(&mapear_erro)?;
        // Uma janela vazia antes de `ate` significa que não há mais nada a ler
        // — parar aqui em vez de girar para sempre sobre o mesmo cursor.
        let Some(&(ultimo, _)) = janela.last() else {
            break;
        };
        for (lsn, episodio) in janela {
            visitar(lsn, episodio)?;
        }
        cursor = ultimo.saturating_add(1);
    }
    Ok(())
}
