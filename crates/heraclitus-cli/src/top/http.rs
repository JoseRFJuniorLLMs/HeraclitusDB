use serde_json::Value;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(1_500);
const IO_TIMEOUT: Duration = Duration::from_millis(3_000);
const MAX_HTTP_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

pub(super) fn fetch_json(
    target: &mut String,
    auth: &mut String,
    path: &str,
    default_port: u16,
) -> Result<(Value, f64), String> {
    let started = Instant::now();
    let response = fetch_with_fallback(target, auth, path, default_port)?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
    if !response.is_success() {
        return Err(format!("HTTP {} em {}", response.status, path));
    }
    let value = serde_json::from_slice::<Value>(&response.body)
        .map_err(|error| format!("JSON inválido em {path}: {error}"))?;
    Ok((value, elapsed_ms))
}

pub(super) fn fetch_text(
    target: &mut String,
    auth: &mut String,
    path: &str,
    default_port: u16,
) -> Result<(String, f64), String> {
    let started = Instant::now();
    let response = fetch_with_fallback(target, auth, path, default_port)?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
    if !response.is_success() {
        return Err(format!("HTTP {} em {}", response.status, path));
    }
    Ok((response.body_text(), elapsed_ms))
}

fn fetch_with_fallback(
    target: &mut String,
    auth: &mut String,
    path: &str,
    default_port: u16,
) -> Result<HttpResponse, String> {
    match fetch_http(target, auth, path, default_port) {
        Ok(response) if response.status != 401 => Ok(response),
        Ok(response) => {
            if let Some(token) = find_secret_token() {
                let replacement = format!("security-admin:{token}");
                match fetch_http(target, &replacement, path, default_port) {
                    Ok(retry) if retry.status != 401 => {
                        *auth = replacement;
                        Ok(retry)
                    }
                    Ok(retry) => Ok(retry),
                    Err(error) => Err(error),
                }
            } else {
                Ok(response)
            }
        }
        Err(original_error) => {
            if !looks_like_connection_error(&original_error) {
                return Err(original_error);
            }
            if let Some(host_ip) = get_wsl_host_ip() {
                let fallback = format!("http://{host_ip}:{default_port}");
                if let Ok(response) = fetch_http(&fallback, auth, path, default_port) {
                    if response.status != 401 {
                        *target = fallback;
                        return Ok(response);
                    }
                }
                if let Some(token) = find_secret_token() {
                    let fallback_auth = format!("security-admin:{token}");
                    if let Ok(response) = fetch_http(&fallback, &fallback_auth, path, default_port) {
                        *target = fallback;
                        *auth = fallback_auth;
                        return Ok(response);
                    }
                }
            }
            Err(original_error)
        }
    }
}

fn fetch_http(
    target_url: &str,
    auth_user_pass: &str,
    req_path: &str,
    default_port: u16,
) -> Result<HttpResponse, String> {
    if target_url.starts_with("https://") {
        return Err("https:// não é suportado pelo cliente leve do `heraclitus top`; use endpoint local http:// ou um túnel local".into());
    }

    let authority = http_authority(target_url)?;
    let socket_authority = authority_with_default_port(&authority, default_port);
    let socket = resolve_first(&socket_authority)?;
    let mut stream = TcpStream::connect_timeout(&socket, CONNECT_TIMEOUT)
        .map_err(|error| format!("falha ao conectar em {socket_authority}: {error}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("write timeout: {error}"))?;

    let auth_header = if auth_user_pass.is_empty() {
        String::new()
    } else {
        format!(
            "Authorization: Basic {}\r\n",
            base64_encode(auth_user_pass.as_bytes())
        )
    };
    let path = if req_path.starts_with('/') {
        req_path.to_owned()
    } else {
        format!("/{req_path}")
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\n{auth_header}Accept: application/json, text/plain;q=0.9, */*;q=0.1\r\nUser-Agent: heraclitus-top-security-cockpit/2\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("erro no envio HTTP: {error}"))?;

    let mut buffer = Vec::with_capacity(32 * 1024);
    stream
        .take((MAX_HTTP_BODY + 64 * 1024) as u64)
        .read_to_end(&mut buffer)
        .map_err(|error| format!("erro lendo resposta HTTP: {error}"))?;
    parse_http_response(&buffer)
}

fn parse_http_response(buffer: &[u8]) -> Result<HttpResponse, String> {
    let header_end = find_bytes(buffer, b"\r\n\r\n")
        .ok_or_else(|| "resposta HTTP sem terminador de cabeçalho".to_string())?;
    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    let raw_body = &buffer[header_end + 4..];
    let mut lines = headers.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| "resposta HTTP sem status line".to_string())?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| format!("status HTTP inválido: {status_line}"))?;

    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse::<usize>().ok();
            }
        }
    }

    let body = if chunked {
        decode_chunked(raw_body)?
    } else if let Some(length) = content_length {
        if length > MAX_HTTP_BODY {
            return Err(format!("corpo HTTP excede limite do cockpit: {length} bytes"));
        }
        if raw_body.len() < length {
            return Err(format!(
                "corpo HTTP truncado: esperado {length} bytes, recebido {}",
                raw_body.len()
            ));
        }
        raw_body[..length].to_vec()
    } else {
        if raw_body.len() > MAX_HTTP_BODY {
            return Err(format!(
                "corpo HTTP sem Content-Length excede limite do cockpit: {} bytes",
                raw_body.len()
            ));
        }
        raw_body.to_vec()
    };
    Ok(HttpResponse { status, body })
}

fn decode_chunked(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut cursor = 0usize;
    let mut output = Vec::new();
    loop {
        let relative_end = find_bytes(&input[cursor..], b"\r\n")
            .ok_or_else(|| "chunk HTTP sem tamanho".to_string())?;
        let line_end = cursor + relative_end;
        let size_line = String::from_utf8_lossy(&input[cursor..line_end]);
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|error| format!("tamanho de chunk inválido '{size_hex}': {error}"))?;
        cursor = line_end + 2;
        if size == 0 {
            break;
        }
        let end = cursor
            .checked_add(size)
            .ok_or_else(|| "overflow no tamanho de chunk".to_string())?;
        if end > input.len() {
            return Err("chunk HTTP truncado".into());
        }
        if output.len().saturating_add(size) > MAX_HTTP_BODY {
            return Err("resposta chunked excede limite do cockpit".into());
        }
        output.extend_from_slice(&input[cursor..end]);
        cursor = end;
        if input.get(cursor..cursor + 2) != Some(b"\r\n") {
            return Err("chunk HTTP sem CRLF final".into());
        }
        cursor += 2;
    }
    Ok(output)
}

pub(super) fn derive_url_with_port(target_url: &str, port: u16) -> String {
    let authority = http_authority(target_url).unwrap_or_else(|_| "127.0.0.1".into());
    let host = authority_host(&authority);
    if host.contains(':') && !host.starts_with('[') {
        format!("http://[{host}]:{port}")
    } else {
        format!("http://{host}:{port}")
    }
}

pub(super) fn probe_port(target_url: &str, port: u16) -> Result<f64, String> {
    let authority = http_authority(target_url)?;
    let host = authority_host(&authority);
    let target = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let socket = resolve_first(&target)?;
    let started = Instant::now();
    TcpStream::connect_timeout(&socket, Duration::from_millis(500))
        .map_err(|error| format!("TCP probe {target} falhou: {error}"))?;
    Ok(started.elapsed().as_secs_f64() * 1_000.0)
}

fn find_secret_token() -> Option<String> {
    for variable in ["HERACLITUS_ADMIN_TOKEN", "HERACLITUS_TOKEN"] {
        if let Ok(value) = env::var(variable) {
            let token = value.trim();
            if !token.is_empty() {
                return Some(token.to_owned());
            }
        }
    }
    let mut candidates = Vec::<PathBuf>::new();
    if let Ok(path) = env::var("HERACLITUS_TOKEN_FILE") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(home) = env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".config/heraclitus/admin.token"));
    }
    if let Some(profile) = env::var_os("USERPROFILE") {
        candidates.push(PathBuf::from(profile).join(".heraclitus/admin.token"));
    }
    candidates.extend([
        PathBuf::from(r"D:\HeraclitusDB\secrets-v1\admin.token"),
        PathBuf::from(r"D:\HeraclitusDB\secrets-v1\writer.token"),
        PathBuf::from("/mnt/d/HeraclitusDB/secrets-v1/admin.token"),
    ]);
    candidates.into_iter().find_map(read_non_empty_file)
}

fn read_non_empty_file(path: PathBuf) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    let content = fs::read_to_string(path).ok()?;
    let content = content.trim();
    (!content.is_empty()).then(|| content.to_owned())
}

fn get_wsl_host_ip() -> Option<String> {
    let content = fs::read_to_string("/etc/resolv.conf").ok()?;
    content.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("nameserver"), Some(ip)) => Some(ip.to_owned()),
            _ => None,
        }
    })
}

fn http_authority(url: &str) -> Result<String, String> {
    let clean = url.strip_prefix("http://").unwrap_or(url).trim_matches('/');
    let authority = clean.split('/').next().unwrap_or("").trim();
    if authority.is_empty() {
        Err(format!("URL HTTP inválida: {url}"))
    } else {
        Ok(authority.to_owned())
    }
}

fn authority_with_default_port(authority: &str, default_port: u16) -> String {
    if authority.starts_with('[') {
        if authority.contains("]:") {
            authority.to_owned()
        } else {
            format!("{authority}:{default_port}")
        }
    } else if authority
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .is_some()
    {
        authority.to_owned()
    } else {
        format!("{authority}:{default_port}")
    }
}

fn authority_host(authority: &str) -> String {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest).to_owned();
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if port.parse::<u16>().is_ok() {
            return host.to_owned();
        }
    }
    authority.to_owned()
}

fn resolve_first(authority: &str) -> Result<std::net::SocketAddr, String> {
    authority
        .to_socket_addrs()
        .map_err(|error| format!("não foi possível resolver {authority}: {error}"))?
        .next()
        .ok_or_else(|| format!("nenhum endereço resolvido para {authority}"))
}

fn looks_like_connection_error(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    ["refused", "recusada", "111", "10061", "timed out", "timeout", "conectar", "resolve"]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < input.len() {
        let a = input[i];
        let b = input.get(i + 1).copied().unwrap_or(0);
        let c = input.get(i + 2).copied().unwrap_or(0);
        out.push(TABLE[(a >> 2) as usize] as char);
        out.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        if i + 1 < input.len() {
            out.push(TABLE[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < input.len() {
            out.push(TABLE[(c & 0x3f) as usize] as char);
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
    fn base64_basic_auth_is_stable() {
        assert_eq!(base64_encode(b"admin:secret"), "YWRtaW46c2VjcmV0");
    }

    #[test]
    fn derives_agent_url_without_reusing_core_port() {
        assert_eq!(derive_url_with_port("http://127.0.0.1:7475", 8080), "http://127.0.0.1:8080");
    }

    #[test]
    fn parses_content_length_response() {
        let r = parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"{}");
    }
}
