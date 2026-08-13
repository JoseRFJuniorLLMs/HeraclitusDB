//! Varredura por janelas LSN — contorna o `QUERY_SCAN_CAP` (250k) do motor.
//!
//! Uma query `MATCH (n:Kind) RETURN n` só varre os primeiros 250k eventos do
//! log. Num log grande (milhões), kinds ingeridos mais tarde (Servidor,
//! Contrato, Despesa…) ficam INALCANÇÁVEIS. Aqui iteramos janelas de
//! `SCAN_WINDOW` eventos (`n.lsn >= lo AND n.lsn < hi`), cada uma dentro do cap,
//! cobrindo todo o log e juntando as linhas.

use heraclitus_client::Client;
use tracing::info;

/// Largura da janela. < `QUERY_SCAN_CAP` (250k) para a varredura capturar a
/// janela inteira sem truncar; e pequena o suficiente para o payload gRPC de
/// um kind denso caber com folga no limite (100k nós ≈ 28MB << 256MB).
pub const SCAN_WINDOW: u64 = 100_000;

fn conta_linhas(v: &serde_json::Value) -> usize {
    if let Some(a) = v.as_array() {
        a.len()
    } else if let Some(a) = v.get("rows").and_then(|x| x.as_array()) {
        a.len()
    } else {
        0
    }
}

/// Projeção lean para o cache: mantém só `{id, lsn, attrs}` de cada nó e larga o
/// resto (sobretudo `content`, que é grande e nunca é usado pelos index-builders).
/// Reduz drasticamente a RAM ao cachear milhões de nós.
fn projetar_lean(row: &serde_json::Value) -> serde_json::Value {
    let mut o = serde_json::Map::with_capacity(3);
    for k in ["id", "lsn", "attrs"] {
        if let Some(v) = row.get(k).or_else(|| row.get("n").and_then(|n| n.get(k))) {
            o.insert(k.to_string(), v.clone());
        }
    }
    serde_json::Value::Object(o)
}

/// Sonda exponencial: devolve um limite superior do head (≥ head real). Para o
/// loop de janelas saber onde parar sem um RPC de stats no Client.
pub async fn descobrir_head(c: &mut Client) -> anyhow::Result<u64> {
    let mut hi: u64 = SCAN_WINDOW;
    loop {
        let v = c
            .query(&format!("MATCH (n) WHERE n.lsn >= {hi} RETURN n LIMIT 1"))
            .await
            .map_err(|e| anyhow::anyhow!("sonda head @ {hi}: {e}"))?;
        if conta_linhas(&v) == 0 {
            break;
        }
        if hi > 1_000_000_000 {
            break; // salvaguarda
        }
        hi = hi.saturating_mul(2);
    }
    Ok(hi)
}

/// Lê TODOS os nós de `kind` iterando janelas de `SCAN_WINDOW` eventos até
/// `head`. Devolve um `Value::Array` com todas as linhas (mesmo formato de uma
/// query normal), pronto a alimentar os index-builders existentes.
pub async fn coletar_kind(
    c: &mut Client,
    kind: &str,
    head: u64,
) -> anyhow::Result<serde_json::Value> {
    // o kind é interpolado na NQL — sanitiza aspas/barras (vem de dados/config).
    let safe = kind.replace(['"', '\\'], "");
    let mut linhas: Vec<serde_json::Value> = Vec::new();
    let mut lo: u64 = 0;
    while lo <= head {
        let hi = lo + SCAN_WINDOW;
        let gql = format!(
            "MATCH (n) WHERE n.lsn >= {lo} AND n.lsn < {hi} AND n.tipo = \"{safe}\" RETURN n"
        );
        let v = c
            .query(&gql)
            .await
            .map_err(|e| anyhow::anyhow!("coletar {kind} @ lsn {lo}: {e}"))?;
        if let Some(a) = v.as_array() {
            linhas.extend(a.iter().map(projetar_lean));
        } else if let Some(a) = v.get("rows").and_then(|x| x.as_array()) {
            linhas.extend(a.iter().map(projetar_lean));
        }
        lo = hi;
    }
    info!(
        "    {} nós '{}' (varredura por janelas)",
        linhas.len(),
        kind
    );
    Ok(serde_json::Value::Array(linhas))
}
