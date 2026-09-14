//! Subconjunto estrito de YAML — só o suficiente para o documento de policy.
//!
//! # Porque um parser próprio e restrito
//!
//! A SPEC-0075 §31 é categórica sobre o ficheiro de policy:
//!
//! ```text
//! parse estrito
//! sem includes remotos
//! sem execução de shell
//! sem JavaScript/Lua embutido
//! sem template eval arbitrário
//! ```
//!
//! > Policy declarativa deve continuar dados, não virar mecanismo de RCE.
//!
//! YAML completo é uma linguagem grande: âncoras, aliases, tags, merge keys,
//! múltiplos documentos, escalares multi-linha com seis modos de dobragem. A
//! superfície que a policy precisa são mapas, listas e escalares. Aceitar só
//! isso — e **recusar explicitamente** o resto — é menos código e menos
//! superfície do que configurar um parser genérico para ser seguro.
//!
//! O mesmo documento pode ser escrito em JSON; os dois descem à mesma árvore e
//! produzem o mesmo `policy_hash`, porque o hash é do documento **interpretado**
//! e não dos bytes do ficheiro (ver [`super::AgentPolicyDocument::hash`]).
//!
//! # O que é recusado, e porquê
//!
//! | forma | motivo |
//! |---|---|
//! | tabulação na indentação | indentação ambígua entre editores |
//! | `&anchor`, `*alias`, `<<:` | expansão = amplificação (a "bomba YAML") |
//! | `!tag` | instanciação de tipos |
//! | `---` / `...` | um ficheiro, um documento |
//! | profundidade > 16 | pilha limitada, input hostil |
//! | > 1 MiB ou > 20k linhas | tecto de recursos |

use serde_json::{Map, Value};

pub const MAX_BYTES: usize = 1024 * 1024;
pub const MAX_LINES: usize = 20_000;
pub const MAX_DEPTH: usize = 16;

#[derive(Debug, thiserror::Error)]
#[error("policy inválida na linha {line}: {message}")]
pub struct YamlError {
    pub line: usize,
    pub message: String,
}

fn err(line: usize, message: impl Into<String>) -> YamlError {
    YamlError {
        line,
        message: message.into(),
    }
}

/// Lê um documento de policy. Aceita JSON (detectado pelo primeiro caractere
/// não-branco ser `{`) ou o subconjunto de YAML descrito acima.
pub fn parse_document(text: &str) -> Result<Value, YamlError> {
    if text.len() > MAX_BYTES {
        return Err(err(0, format!("documento maior do que {MAX_BYTES} bytes")));
    }
    if text.trim_start().starts_with('{') {
        return serde_json::from_str(text).map_err(|e| err(e.line(), e.to_string()));
    }
    parse_yaml(text)
}

struct Line {
    n: usize,
    indent: usize,
    content: String,
}

fn scan(text: &str) -> Result<Vec<Line>, YamlError> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        if n > MAX_LINES {
            return Err(err(n, "documento com demasiadas linhas"));
        }
        if raw.contains('\t') && raw.trim_start().len() != raw.len() {
            return Err(err(n, "tabulação na indentação: use espaços"));
        }
        let trimmed_start = raw.len() - raw.trim_start_matches(' ').len();
        let body = strip_comment(&raw[trimmed_start..]);
        let body = body.trim_end();
        if body.is_empty() {
            continue;
        }
        if body == "---" || body == "..." {
            return Err(err(n, "múltiplos documentos YAML não são aceites"));
        }
        if body.starts_with('%') {
            return Err(err(n, "directivas YAML não são aceites"));
        }
        out.push(Line {
            n,
            indent: trimmed_start,
            content: body.to_string(),
        });
    }
    Ok(out)
}

/// Remove um comentário `#`, respeitando aspas. Um `#` dentro de uma string é
/// conteúdo, não comentário.
fn strip_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut quote: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'#' && (i == 0 || bytes[i - 1] == b' ') => return &s[..i],
            None => {}
        }
    }
    s
}

pub fn parse_yaml(text: &str) -> Result<Value, YamlError> {
    let lines = scan(text)?;
    if lines.is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    let mut pos = 0usize;
    let value = parse_block(&lines, &mut pos, lines[0].indent, 0)?;
    if pos < lines.len() {
        return Err(err(
            lines[pos].n,
            "indentação inconsistente: a linha não pertence a nenhum bloco",
        ));
    }
    Ok(value)
}

fn parse_block(
    lines: &[Line],
    pos: &mut usize,
    indent: usize,
    depth: usize,
) -> Result<Value, YamlError> {
    if depth > MAX_DEPTH {
        return Err(err(lines[*pos].n, "aninhamento excessivo"));
    }
    if lines[*pos].content.starts_with("- ") || lines[*pos].content == "-" {
        parse_sequence(lines, pos, indent, depth)
    } else {
        parse_mapping(lines, pos, indent, depth)
    }
}

fn parse_sequence(
    lines: &[Line],
    pos: &mut usize,
    indent: usize,
    depth: usize,
) -> Result<Value, YamlError> {
    let mut items = Vec::new();
    while *pos < lines.len() {
        let line = &lines[*pos];
        if line.indent < indent {
            break;
        }
        if line.indent > indent {
            return Err(err(line.n, "indentação inesperada dentro de uma lista"));
        }
        let Some(rest) = line
            .content
            .strip_prefix("- ")
            .map(str::trim)
            .or_else(|| (line.content == "-").then_some(""))
        else {
            break;
        };
        let item_line = line.n;
        *pos += 1;
        if rest.is_empty() {
            // O item é um bloco nas linhas seguintes.
            if *pos < lines.len() && lines[*pos].indent > indent {
                let child = lines[*pos].indent;
                items.push(parse_block(lines, pos, child, depth + 1)?);
            } else {
                items.push(Value::Null);
            }
        } else if let Some((k, v)) = split_key(rest) {
            // `- id: x` abre um mapa cujas chaves seguintes estão indentadas ao
            // nível do `id`, dois espaços à frente do traço.
            let child_indent = indent + 2;
            let mut map = Map::new();
            insert_scalar_or_block(lines, pos, &mut map, k, v, child_indent, depth, item_line)?;
            while *pos < lines.len() && lines[*pos].indent >= child_indent {
                if lines[*pos].indent > child_indent {
                    return Err(err(lines[*pos].n, "indentação inesperada no item da lista"));
                }
                if lines[*pos].content.starts_with("- ") {
                    break;
                }
                let l = &lines[*pos];
                let Some((k2, v2)) = split_key(&l.content) else {
                    return Err(err(l.n, "esperava `chave: valor`"));
                };
                let (k2, v2) = (k2.to_string(), v2.to_string());
                let n2 = l.n;
                *pos += 1;
                insert_scalar_or_block(
                    lines,
                    pos,
                    &mut map,
                    &k2,
                    &v2,
                    child_indent + 2,
                    depth,
                    n2,
                )?;
            }
            items.push(Value::Object(map));
        } else {
            items.push(scalar(rest, item_line)?);
        }
    }
    Ok(Value::Array(items))
}

fn parse_mapping(
    lines: &[Line],
    pos: &mut usize,
    indent: usize,
    depth: usize,
) -> Result<Value, YamlError> {
    let mut map = Map::new();
    while *pos < lines.len() {
        let line = &lines[*pos];
        if line.indent < indent {
            break;
        }
        if line.indent > indent {
            return Err(err(line.n, "indentação inesperada"));
        }
        if line.content.starts_with("- ") {
            break;
        }
        let Some((k, v)) = split_key(&line.content) else {
            return Err(err(line.n, "esperava `chave: valor`"));
        };
        let (k, v, n) = (k.to_string(), v.to_string(), line.n);
        if map.contains_key(&k) {
            return Err(err(n, format!("chave duplicada: {k}")));
        }
        *pos += 1;
        insert_scalar_or_block(lines, pos, &mut map, &k, &v, indent + 1, depth, n)?;
    }
    Ok(Value::Object(map))
}

#[allow(clippy::too_many_arguments)]
fn insert_scalar_or_block(
    lines: &[Line],
    pos: &mut usize,
    map: &mut Map<String, Value>,
    key: &str,
    inline: &str,
    child_min_indent: usize,
    depth: usize,
    line_no: usize,
) -> Result<(), YamlError> {
    if inline.is_empty() {
        if *pos < lines.len() && lines[*pos].indent >= child_min_indent {
            let child = lines[*pos].indent;
            let v = parse_block(lines, pos, child, depth + 1)?;
            map.insert(key.to_string(), v);
        } else {
            map.insert(key.to_string(), Value::Null);
        }
    } else {
        map.insert(key.to_string(), scalar(inline, line_no)?);
    }
    Ok(())
}

/// `chave: valor` -> `("chave", "valor")`. Recusa chaves com aspas ou `#`.
fn split_key(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    let mut quote: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b':' => {
                let after_is_space = bytes.get(i + 1).map(|c| *c == b' ').unwrap_or(true);
                if !after_is_space {
                    continue;
                }
                let k = s[..i].trim();
                if k.is_empty() {
                    return None;
                }
                return Some((k, s[i + 1..].trim()));
            }
            None => {}
        }
    }
    None
}

/// Escalar: string (com ou sem aspas), inteiro, booleano, nulo, ou lista em
/// linha `[a, b]`.
fn scalar(s: &str, line: usize) -> Result<Value, YamlError> {
    let s = s.trim();
    if s.starts_with('&') || s.starts_with('*') || s.starts_with('!') {
        return Err(err(
            line,
            "âncoras, aliases e tags YAML não são aceites numa policy",
        ));
    }
    if s.starts_with('[') {
        let inner = s
            .strip_prefix('[')
            .and_then(|x| x.strip_suffix(']'))
            .ok_or_else(|| err(line, "lista em linha por fechar"))?;
        if inner.trim().is_empty() {
            return Ok(Value::Array(Vec::new()));
        }
        let items: Result<Vec<Value>, YamlError> =
            inner.split(',').map(|x| scalar(x.trim(), line)).collect();
        return Ok(Value::Array(items?));
    }
    if s.starts_with('{') {
        return Err(err(line, "mapas em linha não são aceites numa policy"));
    }
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        return Ok(Value::String(s[1..s.len() - 1].to_string()));
    }
    match s {
        "true" | "True" => return Ok(Value::Bool(true)),
        "false" | "False" => return Ok(Value::Bool(false)),
        "null" | "~" => return Ok(Value::Null),
        _ => {}
    }
    if let Ok(i) = s.parse::<i64>() {
        return Ok(Value::from(i));
    }
    // Decimais ficam STRING de propósito: um `f64` perderia precisão e a
    // SPEC-0075 §12 exige "decimal-safe representation". A comparação numérica
    // faz-se em `super::value`, sobre os dígitos.
    Ok(Value::String(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXEMPLO: &str = r#"
version: "agent-policy-v1"

defaults:
  decision: deny

rules:
  - id: finance-small
    match:
      server: finance
      tool: send_payment
      conditions:
        - field: amount
          op: lte
          value: 5000
    decision: require_approval
    approval:
      roles: ["finance-operator"]
      ttl_seconds: 300

  - id: destructive-shell        # comentário no fim da linha
    match:
      server: shell
      tool: exec
      conditions:
        - field: command_class
          op: eq
          value: destructive
    decision: deny
"#;

    #[test]
    fn le_o_exemplo_da_spec() {
        let v = parse_yaml(EXEMPLO).unwrap();
        assert_eq!(v["version"], "agent-policy-v1");
        assert_eq!(v["defaults"]["decision"], "deny");
        let rules = v["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["id"], "finance-small");
        assert_eq!(rules[0]["match"]["tool"], "send_payment");
        assert_eq!(rules[0]["match"]["conditions"][0]["op"], "lte");
        assert_eq!(rules[0]["match"]["conditions"][0]["value"], 5000);
        assert_eq!(rules[0]["approval"]["roles"][0], "finance-operator");
        assert_eq!(rules[0]["approval"]["ttl_seconds"], 300);
        assert_eq!(rules[1]["decision"], "deny");
    }

    #[test]
    fn json_tambem_e_aceite() {
        let v = parse_document(r#"{"version":"agent-policy-v1","rules":[]}"#).unwrap();
        assert_eq!(v["version"], "agent-policy-v1");
    }

    #[test]
    fn ancoras_sao_recusadas() {
        let e = parse_yaml("a: &x 1\nb: *x\n").unwrap_err();
        assert!(e.message.contains("âncoras"), "{}", e.message);
    }

    #[test]
    fn tags_sao_recusadas() {
        assert!(parse_yaml("a: !!python/object x\n").is_err());
    }

    #[test]
    fn tabulacao_na_indentacao_e_recusada() {
        assert!(parse_yaml("a:\n\tb: 1\n").is_err());
    }

    #[test]
    fn multiplos_documentos_sao_recusados() {
        assert!(parse_yaml("a: 1\n---\nb: 2\n").is_err());
    }

    #[test]
    fn chave_duplicada_e_recusada() {
        let e = parse_yaml("a: 1\na: 2\n").unwrap_err();
        assert!(e.message.contains("duplicada"), "{}", e.message);
    }

    #[test]
    fn cardinal_dentro_de_aspas_nao_e_comentario() {
        let v = parse_yaml("nota: \"vale #1\"\n").unwrap();
        assert_eq!(v["nota"], "vale #1");
    }

    #[test]
    fn decimal_fica_string_para_nao_perder_precisao() {
        let v = parse_yaml("valor: 0.1\n").unwrap();
        assert_eq!(v["valor"], "0.1");
    }

    #[test]
    fn aninhamento_excessivo_e_recusado() {
        let mut s = String::new();
        for i in 0..40 {
            s.push_str(&" ".repeat(i));
            s.push_str(&format!("k{i}:\n"));
        }
        assert!(parse_yaml(&s).is_err());
    }

    #[test]
    fn documento_grande_e_recusado() {
        let big = "a: 1\n".repeat(MAX_LINES + 10);
        assert!(parse_document(&big).is_err());
    }

    #[test]
    fn lixo_nao_entra_em_panico() {
        for s in ["::::", "- - - -", "a:\n  - \n", ":", "  \n  \n", "[", "]"] {
            let _ = parse_yaml(s);
        }
    }
}
