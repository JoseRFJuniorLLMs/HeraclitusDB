use serde_json::Value;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(1_500);
const IO_TIMEOUT: Duration = Duration::from_millis(3_000);

#[derive(Debug)]
pub(super) struct HttpResponse {
    pub(super) status: u16,
    pub(super) body: Vec<u8>,
}

impl HttpResponse {
    pub(super) fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

pub(super) fn core_authorization(user: &str, pass: &str) -> String {
    if !user.is_empty() || !pass.is_empty() {
        return basic_authorization(&format!("{user}:{pass}"));
    }
    let token = env::var("HERACLITUS_ADMIN_TOKEN")
        .or_else(|_| env::var("HERACLITUS_TOKEN"))
        .unwrap_or_default();
    if token.trim().is_empty() {
        String::new()
    } else {
        basic_authorization(&format!("security-admin:{}", token.trim()))
    }
}

pub(super) fn agent_authorization() -> String {
    if let Ok(raw) = env::var("HERACLITUS_AGENT_AUTHORIZATION") {
        if !raw.trim().is_empty() {
            return raw.trim().to_string();
        }
    }
    env::var("HERACLITUS_AGENT_BASIC_AUTH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(|v| basic_authorization(v.trim()))
        .unwrap_or_default()
}

pub(super) fn agent_url(core_url: &str) -> String {
    if let Ok(value) = env::var("HERACLITUS_AGENT_URL") {
        if !value.trim().is_empty() {
            return value.trim().trim_end_matches('/').to_string();
        }
    }
    let host = target_host(core_url).unwrap_or_else(|_| "127.0.0.1".into());
    format!("http://{host}:8080")
}

pub(super) fn agent_explicitly_configured() -> bool {
    env::var("HERACLITUS_AGENT_URL")
        .ok()
        .is_some_and(|v| !v.trim().is_empty())
}

pub(super) fn fetch_json(
    target: &str,
    authorization: &str,
    path: &str,
    default_port: u16,
) -> Result<(Value, f64), String> {
    let started = Instant::now();
    let response = fetch_http(target, authorization, path, default_port)?;
    let latency_ms = started.elapsed().as_secs_f64() * 1000.0;
    if !response.is_success() {
        return Err(format!("HTTP {} em {path}", response.status));
    }
    let value = serde_json::from_slice(&response.body)
        .map_err(|e| format!("JSON inválido em {path}: {e}"))?;
    Ok((value, latency_ms))
}

pub(super) fn fetch_http(
    target: &str,
    authorization: &str,
    path: &str,
    default_port: u16,
) -> Result<HttpResponse, String> {
    if target.starts_with("https://") {
        return Err("https:// não suportado pelo cliente leve do heraclitus top".into());
    }

    let authority = authority(target)?;
    let socket_authority = authority_with_default_port(&authority, default_port);
    let socket = socket_authority
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "sem endereço resolvido".to_string())?;

    let mut stream = TcpStream::connect_timeout(&socket, CONNECT_TIMEOUT)
        .map_err(|e| format!("connect {socket_authority}: {e}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;

    let auth_header = if authorization.is_empty() {
        String::new()
    } else {
        format!("Authorization: {authorization}\r\n")
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\n{auth_header}Accept: application/json, text/plain\r\nUser-Agent: heraclitus-top/3\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;

    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    parse_http(&bytes)
}

pub(super) fn probe_tcp(target: &str, port: u16) -> Result<f64, String> {
    let host = target_host(target)?;
    let address = format!("{host}:{port}");
    let socket = address
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "sem endereço resolvido".to_string())?;
    let started = Instant::now();
    TcpStream::connect_timeout(&socket, Duration::from_millis(500))
        .map_err(|e| e.to_string())?;
    Ok(started.elapsed().as_secs_f64() * 1000.0)
}

fn parse_http(bytes: &[u8]) -> Result<HttpResponse, String> {
    let header_end = find_bytes(bytes, b"\r\n\r\n").ok_or("HTTP sem fim de headers")?;
    let header = String::from_utf8_lossy(&bytes[..header_end]);
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or("status HTTP inválido")?;
    let chunked = header.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });
    let raw = &bytes[header_end + 4..];
    let body = if chunked {
        decode_chunked(raw)?
    } else {
        raw.to_vec()
    };
    Ok(HttpResponse { status, body })
}

fn decode_chunked(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut cursor = 0usize;
    let mut output = Vec::new();
    loop {
        let rel_end = find_bytes(&input[cursor..], b"\r\n").ok_or("chunk sem tamanho")?;
        let line_end = cursor + rel_end;
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&input[cursor..line_end])
                .split(';')
                .next()
                .unwrap_or("")
                .trim(),
            16,
        )
        .map_err(|e| e.to_string())?;
        cursor = line_end + 2;
        if size == 0 {
            break;
        }
        let end = cursor.checked_add(size).ok_or("chunk overflow")?;
        if end > input.len() {
            return Err("chunk truncado".into());
        }
        output.extend_from_slice(&input[cursor..end]);
        cursor = end.checked_add(2).ok_or("chunk overflow")?;
        if cursor > input.len() {
            return Err("chunk sem terminador".into());
        }
    }
    Ok(output)
}

fn authority(url: &str) -> Result<String, String> {
    let clean = url
        .strip_prefix("http://")
        .unwrap_or(url)
        .trim_matches('/');
    let authority = clean.split('/').next().unwrap_or("");
    if authority.is_empty() {
        Err("URL inválida".into())
    } else {
        Ok(authority.to_string())
    }
}

fn target_host(url: &str) -> Result<String, String> {
    let authority = authority(url)?;
    if authority.starts_with('[') {
        if let Some(end) = authority.find(']') {
            return Ok(authority[1..end].to_string());
        }
    }
    Ok(authority
        .rsplit_once(':')
        .filter(|(_, p)| p.parse::<u16>().is_ok())
        .map(|(host, _)| host.to_string())
        .unwrap_or(authority))
}

fn authority_with_default_port(authority: &str, port: u16) -> String {
    if authority
        .rsplit_once(':')
        .and_then(|(_, value)| value.parse::<u16>().ok())
        .is_some()
    {
        authority.to_string()
    } else {
        format!("{authority}:{port}")
    }
}

fn basic_authorization(user_pass: &str) -> String {
    format!("Basic {}", base64_encode(user_pass.as_bytes()))
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0usize;
    while i < input.len() {
        let a = input[i];
        let b = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let c = if i + 2 < input.len() { input[i + 2] } else { 0 };
        out.push(TABLE[(a >> 2) as usize] as char);
        out.push(TABLE[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        if i + 1 < input.len() {
            out.push(TABLE[(((b & 15) << 2) | (c >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < input.len() {
            out.push(TABLE[(c & 63) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_basic() {
        assert_eq!(base64_encode(b"admin:secret"), "YWRtaW46c2VjcmV0");
    }

    #[test]
    fn derives_agent_url_from_core_host() {
        assert_eq!(agent_url("http://127.0.0.1:7475"), "http://127.0.0.1:8080");
    }
}
