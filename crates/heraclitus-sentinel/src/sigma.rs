//! Strict, deliberately small Sigma frontend for the L1 detection IR.
//!
//! The project does not depend on a YAML runtime just to load a ruleset.  This
//! parser accepts the deterministic subset documented below and rejects every
//! construct it cannot represent in [`DetectionExpr`].  A rejected rule is
//! never weakened into a partial rule.

use crate::detection::{DetectionExpr, DetectionRule, Field, RuleCompileError, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Compile one Sigma YAML document into a Sentinel [`DetectionRule`].
///
/// Supported detection subset:
/// - scalar and list field selections;
/// - `and`, `or`, `not` and parentheses in `condition`;
/// - `1 of name*`, `any of name*` and `all of name*` condition forms.
///
/// Field modifiers (`contains`, `startswith`, `endswith`, `all`) and all
/// aggregation/near semantics are rejected with `UnsupportedFeature`.
pub fn compile_sigma(input: &str) -> Result<DetectionRule, RuleCompileError> {
    let root = parse_yaml(input)?;
    compile_document(&root)
}

/// Alias useful to callers that treat Sigma as a parser/compiler boundary.
pub fn parse_sigma(input: &str) -> Result<DetectionRule, RuleCompileError> {
    compile_sigma(input)
}

/// Compile a UTF-8 Sigma rule file.  Files are read only after the rule has
/// been explicitly selected by the host; the parser itself performs no path
/// expansion or directory traversal.
pub fn compile_sigma_file(path: impl AsRef<Path>) -> Result<DetectionRule, RuleCompileError> {
    let path = path.as_ref();
    let input = std::fs::read_to_string(path)
        .map_err(|error| RuleCompileError::InvalidSigma(format!("{}: {error}", path.display())))?;
    compile_sigma(&input)
}

/// Compile a file or a directory selected by configuration.  Directory
/// entries are sorted by their full path and only `.yml`/`.yaml` files are
/// considered; other files are ignored rather than interpreted as rules.
pub fn compile_sigma_path(path: impl AsRef<Path>) -> Result<Vec<DetectionRule>, RuleCompileError> {
    let path = path.as_ref();
    if path.is_file() {
        return Ok(vec![compile_sigma_file(path)?]);
    }
    if !path.is_dir() {
        return Err(RuleCompileError::InvalidSigma(format!(
            "Sigma rules path does not exist or is not a directory: {}",
            path.display()
        )));
    }
    let mut paths = std::fs::read_dir(path)
        .map_err(|error| RuleCompileError::InvalidSigma(format!("{}: {error}", path.display())))?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| RuleCompileError::InvalidSigma(format!("{}: {error}", path.display())))?;
    paths.sort();
    let mut inputs = Vec::new();
    for file in paths {
        let is_sigma = file
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "yml" | "yaml"));
        if is_sigma {
            inputs.push(std::fs::read_to_string(&file).map_err(|error| {
                RuleCompileError::InvalidSigma(format!("{}: {error}", file.display()))
            })?);
        }
    }
    if inputs.is_empty() {
        return Err(RuleCompileError::InvalidSigma(format!(
            "Sigma rules path contains no .yml/.yaml files: {}",
            path.display()
        )));
    }
    compile_sigma_rules(inputs.iter().map(String::as_str))
}

/// Compile a deterministic set of Sigma documents.  The caller owns ordering;
/// duplicate detector identities are rejected rather than silently replaced.
pub fn compile_sigma_rules(
    inputs: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Vec<DetectionRule>, RuleCompileError> {
    let mut rules = Vec::new();
    let mut identities = BTreeSet::new();
    for input in inputs {
        let rule = compile_sigma(input.as_ref())?;
        let identity = (rule.detector.id.clone(), rule.detector.version.clone());
        if !identities.insert(identity.clone()) {
            return Err(RuleCompileError::InvalidSigma(format!(
                "duplicate detector identity {}@{}",
                identity.0, identity.1
            )));
        }
        rules.push(rule);
    }
    rules.sort_by(|a, b| {
        a.detector
            .id
            .cmp(&b.detector.id)
            .then_with(|| a.detector.version.cmp(&b.detector.version))
    });
    Ok(rules)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum YamlNode {
    Map(BTreeMap<String, YamlNode>),
    Seq(Vec<YamlNode>),
    Scalar(String),
}

#[derive(Debug, Clone)]
struct YamlLine {
    number: usize,
    indent: usize,
    text: String,
}

fn parse_yaml(input: &str) -> Result<YamlNode, RuleCompileError> {
    let mut lines = Vec::new();
    for (index, raw) in input.lines().enumerate() {
        if raw.contains('\t') {
            return Err(invalid_yaml(
                index + 1,
                "tabs are not accepted for indentation",
            ));
        }
        let without_comment = strip_comment(raw);
        let trimmed = without_comment.trim_end();
        if trimmed.trim().is_empty() {
            continue;
        }
        let indent = trimmed.len() - trimmed.trim_start().len();
        let text = trimmed[indent..].trim_end().to_owned();
        if text == "---" {
            if !lines.is_empty() {
                return Err(invalid_yaml(
                    index + 1,
                    "multiple YAML documents are unsupported",
                ));
            }
            continue;
        }
        if text == "..." {
            continue;
        }
        lines.push(YamlLine {
            number: index + 1,
            indent,
            text,
        });
    }
    if lines.is_empty() {
        return Err(invalid_yaml(1, "empty YAML document"));
    }
    let indent = lines[0].indent;
    let mut position = 0;
    let node = parse_block(&lines, &mut position, indent)?;
    if position != lines.len() {
        return Err(invalid_yaml(
            lines[position].number,
            "unexpected indentation or trailing document content",
        ));
    }
    Ok(node)
}

fn parse_block(
    lines: &[YamlLine],
    position: &mut usize,
    indent: usize,
) -> Result<YamlNode, RuleCompileError> {
    let Some(first) = lines.get(*position) else {
        return Err(invalid_yaml(0, "missing nested value"));
    };
    if first.indent != indent {
        return Err(invalid_yaml(first.number, "invalid indentation"));
    }
    if first.text.starts_with('-') {
        parse_sequence(lines, position, indent)
    } else {
        parse_mapping(lines, position, indent)
    }
}

fn parse_mapping(
    lines: &[YamlLine],
    position: &mut usize,
    indent: usize,
) -> Result<YamlNode, RuleCompileError> {
    let mut map = BTreeMap::new();
    while let Some(line) = lines.get(*position) {
        if line.indent < indent {
            break;
        }
        if line.indent > indent || line.text.starts_with('-') {
            return Err(invalid_yaml(
                line.number,
                "mapping indentation is not a map entry",
            ));
        }
        let (raw_key, raw_value) = line
            .text
            .split_once(':')
            .ok_or_else(|| invalid_yaml(line.number, "expected `key: value`"))?;
        let key = parse_key(raw_key.trim(), line.number)?;
        if key.is_empty() {
            return Err(invalid_yaml(line.number, "empty map key"));
        }
        if map.contains_key(&key) {
            return Err(invalid_yaml(line.number, "duplicate map key"));
        }
        let raw_value = raw_value.trim();
        *position += 1;
        let value = if raw_value.is_empty() {
            if let Some(next) = lines.get(*position) {
                if next.indent > indent {
                    parse_block(lines, position, next.indent)?
                } else {
                    YamlNode::Scalar(String::new())
                }
            } else {
                YamlNode::Scalar(String::new())
            }
        } else if matches!(raw_value, "|" | ">" | "|-" | ">-") {
            let folded = raw_value.starts_with('>');
            let mut body = Vec::new();
            while let Some(next) = lines.get(*position) {
                if next.indent <= indent {
                    break;
                }
                body.push(next.text.clone());
                *position += 1;
            }
            if body.is_empty() {
                YamlNode::Scalar(String::new())
            } else if folded {
                YamlNode::Scalar(body.join(" "))
            } else {
                YamlNode::Scalar(body.join("\n"))
            }
        } else {
            parse_inline_value(raw_value, line.number)?
        };
        map.insert(key, value);
    }
    if map.is_empty() {
        return Err(invalid_yaml(0, "empty mapping"));
    }
    Ok(YamlNode::Map(map))
}

fn parse_sequence(
    lines: &[YamlLine],
    position: &mut usize,
    indent: usize,
) -> Result<YamlNode, RuleCompileError> {
    let mut values = Vec::new();
    while let Some(line) = lines.get(*position) {
        if line.indent < indent {
            break;
        }
        if line.indent != indent || !line.text.starts_with('-') {
            return Err(invalid_yaml(
                line.number,
                "sequence indentation is not a list item",
            ));
        }
        let rest = line.text[1..].trim();
        *position += 1;
        if rest.is_empty() {
            let Some(next) = lines.get(*position) else {
                return Err(invalid_yaml(line.number, "empty sequence item"));
            };
            if next.indent <= indent {
                return Err(invalid_yaml(line.number, "empty sequence item"));
            }
            values.push(parse_block(lines, position, next.indent)?);
        } else if rest.contains(':') {
            return Err(RuleCompileError::UnsupportedFeature(
                "sequence of mappings".into(),
            ));
        } else {
            values.push(parse_inline_value(rest, line.number)?);
        }
    }
    if values.is_empty() {
        return Err(invalid_yaml(0, "empty sequence"));
    }
    Ok(YamlNode::Seq(values))
}

fn parse_inline_value(value: &str, line: usize) -> Result<YamlNode, RuleCompileError> {
    if value == "|" || value == ">" || value.starts_with('&') || value.starts_with('*') {
        return Err(RuleCompileError::UnsupportedFeature(format!(
            "YAML scalar form at line {line}"
        )));
    }
    if value.starts_with('[') {
        if !value.ends_with(']') {
            return Err(invalid_yaml(line, "unterminated inline sequence"));
        }
        let body = &value[1..value.len() - 1];
        let items = split_inline(body, line)?;
        if items.is_empty() {
            return Err(invalid_yaml(line, "empty inline sequence"));
        }
        return Ok(YamlNode::Seq(
            items
                .into_iter()
                .map(|item| parse_inline_value(item.trim(), line))
                .collect::<Result<Vec<_>, _>>()?,
        ));
    }
    if value.starts_with('{') {
        return Err(RuleCompileError::UnsupportedFeature(
            "inline YAML mappings".into(),
        ));
    }
    Ok(YamlNode::Scalar(unquote(value, line)?))
}

fn split_inline(value: &str, line: usize) -> Result<Vec<&str>, RuleCompileError> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut quote = None;
    for (index, ch) in value.char_indices() {
        match (quote, ch) {
            (None, '\'' | '"') => quote = Some(ch),
            (Some(current), ch) if current == ch => quote = None,
            (None, ',') => {
                result.push(value[start..index].trim());
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    if quote.is_some() {
        return Err(invalid_yaml(line, "unterminated quoted scalar"));
    }
    result.push(value[start..].trim());
    Ok(result)
}

fn strip_comment(value: &str) -> String {
    let mut quote = None;
    for (index, ch) in value.char_indices() {
        match (quote, ch) {
            (None, '\'' | '"') => quote = Some(ch),
            (Some(current), ch) if current == ch => quote = None,
            (None, '#')
                if index == 0
                    || value[..index]
                        .chars()
                        .next_back()
                        .is_some_and(char::is_whitespace) =>
            {
                return value[..index].to_owned()
            }
            _ => {}
        }
    }
    value.to_owned()
}

fn parse_key(value: &str, line: usize) -> Result<String, RuleCompileError> {
    unquote(value, line)
}

fn unquote(value: &str, line: usize) -> Result<String, RuleCompileError> {
    if value.len() >= 2 {
        let first = value.as_bytes()[0] as char;
        let last = value.as_bytes()[value.len() - 1] as char;
        if first == '"' || first == '\'' {
            if last != first {
                return Err(invalid_yaml(line, "unterminated quoted scalar"));
            }
            let body = &value[1..value.len() - 1];
            return if first == '"' {
                serde_json::from_str::<String>(value)
                    .map_err(|error| invalid_yaml(line, &format!("invalid quoted scalar: {error}")))
            } else {
                Ok(body.replace("''", "'"))
            };
        }
    }
    Ok(value.to_owned())
}

fn compile_document(root: &YamlNode) -> Result<DetectionRule, RuleCompileError> {
    let map = as_map(root, "root")?;
    let id = scalar_required(map, "id")?;
    let version = map
        .get("version")
        .or_else(|| map.get("modified"))
        .map(|value| scalar(value, "version"))
        .transpose()?
        .unwrap_or_else(|| "1".into());
    let detection = as_map(
        map.get("detection")
            .ok_or_else(|| RuleCompileError::InvalidSigma("missing detection map".into()))?,
        "detection",
    )?;
    let condition = scalar(
        detection
            .get("condition")
            .ok_or_else(|| RuleCompileError::InvalidSigma("missing detection.condition".into()))?,
        "condition",
    )?;
    let mut selections = BTreeMap::new();
    for (name, node) in detection {
        if name == "condition" {
            continue;
        }
        if name.contains('|') {
            return Err(RuleCompileError::UnsupportedFeature(format!(
                "selection modifier `{name}`"
            )));
        }
        let expression = compile_selection(node)?;
        selections.insert(name.clone(), expression);
    }
    if selections.is_empty() {
        return Err(RuleCompileError::InvalidSigma(
            "detection has no selections".into(),
        ));
    }
    let expression = compile_condition(&condition, &selections)?;
    let severity = map
        .get("level")
        .or_else(|| map.get("severity"))
        .map(parse_severity)
        .transpose()?
        .unwrap_or(0);
    let mut rule = DetectionRule::new(id, version, expression, severity);
    if let Some(title) = map.get("title") {
        rule.labels
            .insert("sigma.title".into(), scalar(title, "title")?);
    }
    if let Some(status) = map.get("status") {
        rule.labels
            .insert("sigma.status".into(), scalar(status, "status")?);
    }
    rule.labels
        .insert("sigma.id".into(), rule.detector.id.clone());
    Ok(rule)
}

fn compile_selection(node: &YamlNode) -> Result<DetectionExpr, RuleCompileError> {
    let fields = as_map(node, "selection")?;
    let mut expressions = Vec::new();
    for (raw_field, value) in fields {
        let field = sigma_field(raw_field)?;
        let expression = match value {
            YamlNode::Scalar(_) => DetectionExpr::Eq(field, scalar_value(value)?),
            YamlNode::Seq(values) => {
                if values.is_empty() {
                    return Err(RuleCompileError::InvalidSigma(
                        "selection list cannot be empty".into(),
                    ));
                }
                let values = values
                    .iter()
                    .map(scalar_value)
                    .collect::<Result<Vec<_>, _>>()?;
                DetectionExpr::In(field, values)
            }
            YamlNode::Map(_) => {
                return Err(RuleCompileError::UnsupportedFeature(
                    "nested field maps in Sigma selections".into(),
                ))
            }
        };
        expressions.push(expression);
    }
    if expressions.is_empty() {
        return Err(RuleCompileError::InvalidSigma(
            "selection cannot be empty".into(),
        ));
    }
    if expressions.len() == 1 {
        Ok(expressions.remove(0))
    } else {
        Ok(DetectionExpr::And(expressions))
    }
}

fn sigma_field(name: &str) -> Result<Field, RuleCompileError> {
    if name.trim().is_empty() {
        return Err(RuleCompileError::InvalidSigma("empty Sigma field".into()));
    }
    if let Some((base, modifier)) = name.split_once('|') {
        return Err(RuleCompileError::UnsupportedFeature(format!(
            "field modifier `{modifier}` on `{base}`"
        )));
    }
    let normalized = name.to_ascii_lowercase();
    Ok(match normalized.as_str() {
        "source" | "security.source" => Field::Source,
        "category" | "security.category" => Field::Category,
        "activity" | "action" | "event.action" | "security.activity" => Field::Activity,
        "outcome" | "status" | "result" | "security.outcome" => Field::Outcome,
        "severity" | "severity_id" | "risk" | "security.severity" => Field::Severity,
        "principal" | "principal.id" => Field::PrincipalId,
        "user" | "user.id" | "username" => Field::UserId,
        "host" | "host.id" | "hostname" => Field::HostId,
        "process" | "process.id" => Field::ProcessId,
        "process.name" | "imagename" | "image" => Field::ProcessName,
        "src.ip" | "source.ip" | "sourceip" => Field::SrcIp,
        "dst.ip" | "destination.ip" | "destinationip" => Field::DstIp,
        _ if normalized.starts_with("event.") => Field::Attribute(name.to_owned()),
        _ => Field::Attribute(format!("event.{name}")),
    })
}

fn scalar_value(node: &YamlNode) -> Result<Value, RuleCompileError> {
    let text = scalar(node, "selection value")?;
    if text.eq_ignore_ascii_case("null") || text == "~" {
        return Err(RuleCompileError::InvalidSigma(
            "null selection values are unsupported".into(),
        ));
    }
    if text.contains('*') || text.contains('?') {
        return Err(RuleCompileError::UnsupportedFeature(
            "Sigma wildcard values require a contains/regex executor".into(),
        ));
    }
    if let Ok(value) = text.parse::<u64>() {
        Ok(Value::Number(value))
    } else {
        Ok(Value::String(text))
    }
}

fn parse_severity(node: &YamlNode) -> Result<u8, RuleCompileError> {
    let value = scalar(node, "level")?;
    if let Ok(number) = value.parse::<u8>() {
        return Ok(number);
    }
    match value.to_ascii_lowercase().as_str() {
        "informational" | "info" => Ok(1),
        "low" => Ok(3),
        "medium" => Ok(5),
        "high" => Ok(8),
        "critical" => Ok(10),
        _ => Err(RuleCompileError::InvalidSigma(format!(
            "invalid Sigma level `{value}`"
        ))),
    }
}

fn compile_condition(
    condition: &str,
    selections: &BTreeMap<String, DetectionExpr>,
) -> Result<DetectionExpr, RuleCompileError> {
    let tokens = tokenize_condition(condition)?;
    let mut parser = ConditionParser {
        tokens,
        position: 0,
        selections,
    };
    let expression = parser.parse_or()?;
    if parser.position != parser.tokens.len() {
        return Err(RuleCompileError::UnsupportedFeature(
            "trailing Sigma condition tokens".into(),
        ));
    }
    Ok(expression)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConditionToken {
    Name(String),
    And,
    Or,
    Not,
    All,
    Any,
    Of,
    LParen,
    RParen,
}

#[derive(Debug, Clone, Copy)]
enum SelectionQuantifier {
    Any,
    All,
    Count(u64),
}

fn tokenize_condition(condition: &str) -> Result<Vec<ConditionToken>, RuleCompileError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = condition.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index].is_whitespace() {
            index += 1;
            continue;
        }
        match chars[index] {
            '(' => {
                tokens.push(ConditionToken::LParen);
                index += 1;
            }
            ')' => {
                tokens.push(ConditionToken::RParen);
                index += 1;
            }
            ch if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '*' | '?' | '.') => {
                let start = index;
                index += 1;
                while index < chars.len()
                    && (chars[index].is_ascii_alphanumeric()
                        || matches!(chars[index], '_' | '-' | '*' | '?' | '.'))
                {
                    index += 1;
                }
                let word: String = chars[start..index].iter().collect();
                match word.to_ascii_lowercase().as_str() {
                    "and" => tokens.push(ConditionToken::And),
                    "or" => tokens.push(ConditionToken::Or),
                    "not" => tokens.push(ConditionToken::Not),
                    "all" => tokens.push(ConditionToken::All),
                    "any" => tokens.push(ConditionToken::Any),
                    "of" => tokens.push(ConditionToken::Of),
                    _ => tokens.push(ConditionToken::Name(word)),
                }
            }
            _ => {
                return Err(RuleCompileError::UnsupportedFeature(format!(
                    "condition character `{}`",
                    chars[index]
                )))
            }
        }
    }
    if tokens.is_empty() {
        return Err(RuleCompileError::InvalidSigma(
            "empty detection condition".into(),
        ));
    }
    Ok(tokens)
}

struct ConditionParser<'a> {
    tokens: Vec<ConditionToken>,
    position: usize,
    selections: &'a BTreeMap<String, DetectionExpr>,
}

impl<'a> ConditionParser<'a> {
    fn parse_or(&mut self) -> Result<DetectionExpr, RuleCompileError> {
        let mut values = vec![self.parse_and()?];
        while self.consume(&ConditionToken::Or) {
            values.push(self.parse_and()?);
        }
        if values.len() == 1 {
            Ok(values.remove(0))
        } else {
            Ok(DetectionExpr::Or(values))
        }
    }

    fn parse_and(&mut self) -> Result<DetectionExpr, RuleCompileError> {
        let mut values = vec![self.parse_unary()?];
        while self.consume(&ConditionToken::And) {
            values.push(self.parse_unary()?);
        }
        if values.len() == 1 {
            Ok(values.remove(0))
        } else {
            Ok(DetectionExpr::And(values))
        }
    }

    fn parse_unary(&mut self) -> Result<DetectionExpr, RuleCompileError> {
        if self.consume(&ConditionToken::Not) {
            return Ok(DetectionExpr::Not(Box::new(self.parse_unary()?)));
        }
        if self.consume(&ConditionToken::LParen) {
            let value = self.parse_or()?;
            if !self.consume(&ConditionToken::RParen) {
                return Err(RuleCompileError::InvalidSigma(
                    "unclosed condition parenthesis".into(),
                ));
            }
            return Ok(value);
        }
        self.parse_atom()
    }

    fn parse_atom(&mut self) -> Result<DetectionExpr, RuleCompileError> {
        if self.consume(&ConditionToken::Any) || self.consume(&ConditionToken::All) {
            let all = matches!(
                self.tokens.get(self.position.saturating_sub(1)),
                Some(ConditionToken::All)
            );
            return self.parse_of(if all {
                SelectionQuantifier::All
            } else {
                SelectionQuantifier::Any
            });
        }
        if let Some(ConditionToken::Name(number)) = self.tokens.get(self.position) {
            if let Ok(number) = number.parse::<u64>() {
                self.position += 1;
                return self.parse_of(SelectionQuantifier::Count(number));
            }
        }
        let Some(ConditionToken::Name(name)) = self.tokens.get(self.position).cloned() else {
            return Err(RuleCompileError::InvalidSigma(
                "expected Sigma selection name".into(),
            ));
        };
        self.position += 1;
        self.selection(&name)
    }

    fn parse_of(
        &mut self,
        quantifier: SelectionQuantifier,
    ) -> Result<DetectionExpr, RuleCompileError> {
        if !self.consume(&ConditionToken::Of) {
            return Err(RuleCompileError::InvalidSigma(
                "expected `of` in Sigma condition".into(),
            ));
        }
        let Some(ConditionToken::Name(pattern)) = self.tokens.get(self.position).cloned() else {
            return Err(RuleCompileError::InvalidSigma(
                "expected selection pattern after `of`".into(),
            ));
        };
        self.position += 1;
        let names = matching_names(&pattern, self.selections);
        if names.is_empty() {
            return Err(RuleCompileError::InvalidSigma(format!(
                "condition pattern `{pattern}` matched no selections"
            )));
        }
        let expressions = names
            .iter()
            .map(|name| self.selection(name))
            .collect::<Result<Vec<_>, _>>()?;
        match quantifier {
            SelectionQuantifier::All => Ok(DetectionExpr::And(expressions)),
            SelectionQuantifier::Any => Ok(DetectionExpr::Or(expressions)),
            SelectionQuantifier::Count(1) => Ok(DetectionExpr::Or(expressions)),
            SelectionQuantifier::Count(count) if count == names.len() as u64 => {
                Ok(DetectionExpr::And(expressions))
            }
            SelectionQuantifier::Count(count) => Err(RuleCompileError::UnsupportedFeature(
                format!("Sigma threshold `{count} of` cannot be represented by the detection IR"),
            )),
        }
    }

    fn selection(&self, name: &str) -> Result<DetectionExpr, RuleCompileError> {
        self.selections.get(name).cloned().ok_or_else(|| {
            RuleCompileError::InvalidSigma(format!(
                "condition references unknown selection `{name}`"
            ))
        })
    }

    fn consume(&mut self, expected: &ConditionToken) -> bool {
        if self.tokens.get(self.position) == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }
}

fn matching_names(pattern: &str, selections: &BTreeMap<String, DetectionExpr>) -> Vec<String> {
    selections
        .keys()
        .filter(|name| {
            if pattern == "them" || pattern == "*" {
                true
            } else if let Some(prefix) = pattern.strip_suffix('*') {
                name.starts_with(prefix)
            } else if let Some(prefix) = pattern.strip_suffix('?') {
                name.starts_with(prefix) && name.len() == prefix.len() + 1
            } else {
                name.as_str() == pattern
            }
        })
        .cloned()
        .collect()
}

fn as_map<'a>(
    node: &'a YamlNode,
    context: &str,
) -> Result<&'a BTreeMap<String, YamlNode>, RuleCompileError> {
    match node {
        YamlNode::Map(map) => Ok(map),
        _ => Err(RuleCompileError::InvalidSigma(format!(
            "{context} must be a map"
        ))),
    }
}

fn scalar(node: &YamlNode, context: &str) -> Result<String, RuleCompileError> {
    match node {
        YamlNode::Scalar(value) if !value.trim().is_empty() => Ok(value.clone()),
        _ => Err(RuleCompileError::InvalidSigma(format!(
            "{context} must be a scalar"
        ))),
    }
}

fn scalar_required(
    map: &BTreeMap<String, YamlNode>,
    key: &str,
) -> Result<String, RuleCompileError> {
    let node = map.get(key).ok_or_else(|| {
        if key == "id" {
            RuleCompileError::MissingIdentity
        } else {
            RuleCompileError::InvalidSigma(format!("missing {key}"))
        }
    })?;
    scalar(node, key)
}

fn invalid_yaml(line: usize, message: &str) -> RuleCompileError {
    if line == 0 {
        RuleCompileError::InvalidSigma(message.into())
    } else {
        RuleCompileError::InvalidSigma(format!("YAML line {line}: {message}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = r#"title: Failed SSH logins
id: 4d8a7d30-2b9a-4d0b-8f20-000000000001
status: experimental
level: high
logsource:
  product: linux
  service: sshd
detection:
  selection:
    EventID: 4625
    LogonType:
      - 3
      - 10
  condition: selection
"#;

    #[test]
    fn compiles_documented_subset_and_preserves_metadata() {
        let rule = compile_sigma(RULE).unwrap();
        assert_eq!(rule.detector.id, "4d8a7d30-2b9a-4d0b-8f20-000000000001");
        assert_eq!(rule.severity, 8);
        assert_eq!(rule.labels["sigma.title"], "Failed SSH logins");
        assert!(matches!(rule.expression, DetectionExpr::And(_)));
    }

    #[test]
    fn compiles_condition_grammar_and_wildcard_groups() {
        let input = r#"title: grouped
id: grouped-1
detection:
  selection_a:
    outcome: failure
  selection_b:
    outcome: blocked
  condition: 1 of selection_*
"#;
        let rule = compile_sigma(input).unwrap();
        assert!(matches!(rule.expression, DetectionExpr::Or(_)));
    }

    #[test]
    fn all_of_and_unrepresentable_thresholds_are_explicit() {
        let all = r#"title: all
id: all-1
detection:
  selection_a:
    outcome: failure
  selection_b:
    category: authentication
  condition: all of selection_*
"#;
        assert!(matches!(
            compile_sigma(all).unwrap().expression,
            DetectionExpr::And(_)
        ));
        let threshold = all.replace("all of", "3 of");
        assert!(matches!(
            compile_sigma(&threshold),
            Err(RuleCompileError::UnsupportedFeature(_))
        ));
    }

    #[test]
    fn unsupported_modifiers_fail_closed() {
        let input = r#"title: unsupported
id: unsupported-1
detection:
  selection:
    CommandLine|contains: powershell
  condition: selection
"#;
        assert!(matches!(
            compile_sigma(input),
            Err(RuleCompileError::UnsupportedFeature(_))
        ));
        let wildcard = r#"title: wildcard
id: wildcard-1
detection:
  selection:
    CommandLine: powershell*
  condition: selection
"#;
        assert!(matches!(
            compile_sigma(wildcard),
            Err(RuleCompileError::UnsupportedFeature(_))
        ));
    }

    #[test]
    fn malformed_yaml_and_unknown_selection_are_rejected() {
        assert!(compile_sigma("id: x\ndetection:\n  condition: missing\n").is_err());
        assert!(compile_sigma("id: x\ndetection: [broken").is_err());
    }
}
