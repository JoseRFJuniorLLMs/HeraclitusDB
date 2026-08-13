//! Utilitários compartilhados entre os módulos de datasets.

use encoding_rs::WINDOWS_1252;
use std::path::Path;

/// Lê um arquivo CSV em Windows-1252/Latin-1 e devolve o conteúdo como String UTF-8.
pub fn ler_csv_latin1(path: &Path) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let bytes = std::fs::read(path)?;
    let (texto, _, teve_erros) = WINDOWS_1252.decode(&bytes);
    if teve_erros {
        tracing::warn!(
            "    Alguns caracteres não decodificáveis em {}",
            path.display()
        );
    }
    Ok(texto.into_owned())
}

/// Sanitiza um valor de campo para uso seguro como attr.
pub fn sanitizar(s: &str) -> String {
    s.trim().replace(['\0', '\r'], "").to_string()
}

/// Normaliza um nome próprio para comparação (entity resolution).
///
/// - maiúsculas, sem acentos, só letras A-Z e espaço, espaços colapsados.
/// Ex.: "José Uélisson Alves Leite" → "JOSE UELISSON ALVES LEITE".
pub fn normalizar_nome(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut ultimo_espaco = true; // evita espaço inicial
    for c in s.chars() {
        let c = match c {
            'á' | 'à' | 'â' | 'ã' | 'ä' | 'Á' | 'À' | 'Â' | 'Ã' | 'Ä' => 'A',
            'é' | 'è' | 'ê' | 'ë' | 'É' | 'È' | 'Ê' | 'Ë' => 'E',
            'í' | 'ì' | 'î' | 'ï' | 'Í' | 'Ì' | 'Î' | 'Ï' => 'I',
            'ó' | 'ò' | 'ô' | 'õ' | 'ö' | 'Ó' | 'Ò' | 'Ô' | 'Õ' | 'Ö' => 'O',
            'ú' | 'ù' | 'û' | 'ü' | 'Ú' | 'Ù' | 'Û' | 'Ü' => 'U',
            'ç' | 'Ç' => 'C',
            'ñ' | 'Ñ' => 'N',
            outro => outro.to_ascii_uppercase(),
        };
        if c.is_ascii_alphabetic() {
            out.push(c);
            ultimo_espaco = false;
        } else if !ultimo_espaco {
            out.push(' ');
            ultimo_espaco = true;
        }
    }
    out.trim_end().to_string()
}

/// Extrai os dígitos VISÍVEIS de um CPF mascarado como chave de blocking.
///
/// O Portal mascara `ABC.DEF.GHI-JK` como `***.DEF.GHI-**`, expondo só os 6
/// dígitos do meio. Esta função devolve esses 6 dígitos (ex.: `***.293.227-**`
/// → `"293227"`). Strings sem exatamente 6 dígitos visíveis devolvem "" (não
/// servem como bloco confiável). **Nunca reconstrói o CPF — só usa o fragmento
/// público já divulgado como chave de agrupamento.**
pub fn cpf_fragmento(mascarado: &str) -> String {
    let digitos: String = mascarado.chars().filter(|c| c.is_ascii_digit()).collect();
    if digitos.len() == 6 {
        digitos
    } else {
        String::new()
    }
}

/// Similaridade entre dois nomes normalizados via Jaccard de conjuntos de tokens.
/// Ignora partículas ("DE","DA","DO","DOS","DAS","E"). Retorna [0.0, 1.0].
pub fn similaridade_nome(a_norm: &str, b_norm: &str) -> f64 {
    fn tokens(s: &str) -> std::collections::BTreeSet<&str> {
        s.split_whitespace()
            .filter(|t| !matches!(*t, "DE" | "DA" | "DO" | "DOS" | "DAS" | "E"))
            .collect()
    }
    let (ta, tb) = (tokens(a_norm), tokens(b_norm));
    if ta.is_empty() || tb.is_empty() {
        return 0.0;
    }
    let inter = ta.intersection(&tb).count() as f64;
    let uniao = ta.union(&tb).count() as f64;
    inter / uniao
}

/// Converte valor monetário brasileiro (ex: "1.234,56") para string limpa.
pub fn sanitizar_valor(s: &str) -> String {
    let s = s.trim();
    // Remove aspas, espaços, converte vírgula decimal
    s.replace(['"', '\r'], "").trim().to_string()
}

/// Envia um lote de eventos para o HeraclitusDB via gRPC.
/// Retorna o número de eventos enviados com sucesso.
pub async fn enviar_lote(
    client: Option<&mut heraclitus_client::Client>,
    lote: &[(String, Vec<u8>, std::collections::HashMap<String, String>)],
    agent_id: &str,
) -> u64 {
    let Some(c) = client else {
        return lote.len() as u64; // dry-run
    };

    let mut ok = 0u64;
    for (kind, content, attrs) in lote {
        let opts = heraclitus_client::AppendOptions {
            kind: kind.clone(),
            attrs: attrs.clone(),
            ..Default::default()
        };
        match c.append(agent_id, content, opts).await {
            Ok(_lsn) => ok += 1,
            Err(e) => tracing::warn!("    gRPC append falhou: {e}"),
        }
    }
    ok
}
