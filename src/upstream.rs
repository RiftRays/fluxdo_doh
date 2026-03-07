use crate::error::{DohProxyError, Result};
use crate::UpstreamProxyConfig;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

impl UpstreamProxyConfig {
    pub fn proxy_url(&self) -> String {
        format!("{}://{}:{}", self.protocol(), self.host, self.port)
    }

    pub fn basic_auth_header(&self) -> Option<String> {
        let username = self.username.as_deref()?.trim();
        let password = self.password.as_deref()?.trim();
        if username.is_empty() || password.is_empty() {
            return None;
        }
        let encoded = STANDARD.encode(format!("{}:{}", username, password));
        Some(format!("Basic {}", encoded))
    }
}

pub async fn connect_http_tunnel(
    proxy: &UpstreamProxyConfig,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    if proxy.protocol() != "http" {
        return Err(DohProxyError::Proxy(format!(
            "Unsupported upstream proxy protocol: {}",
            proxy.protocol()
        )));
    }

    if !proxy.is_valid() {
        return Err(DohProxyError::Proxy(
            "Invalid upstream proxy configuration".to_string(),
        ));
    }

    let authority = format!("{}:{}", target_host, target_port);
    info!(
        "Connecting to upstream proxy {} for {}",
        proxy.proxy_url(),
        authority
    );

    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port)).await?;
    let mut request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: Keep-Alive\r\n",
        authority, authority
    );
    if let Some(auth_header) = proxy.basic_auth_header() {
        request.push_str(&format!("Proxy-Authorization: {}\r\n", auth_header));
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;

    if status_line.trim().is_empty() {
        return Err(DohProxyError::Proxy(
            "Empty response from upstream proxy".to_string(),
        ));
    }

    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            DohProxyError::Proxy(format!(
                "Invalid upstream proxy response status line: {}",
                status_line.trim()
            ))
        })?;

    let mut proxy_authenticate = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }

        if trimmed.to_ascii_lowercase().starts_with("proxy-authenticate:") {
            proxy_authenticate = Some(trimmed.to_string());
        }
    }

    let stream = reader.into_inner();
    match status_code {
        200 => {
            debug!("Upstream proxy tunnel established for {}", authority);
            Ok(stream)
        }
        407 => {
            if let Some(header) = proxy_authenticate {
                warn!("Upstream proxy auth challenge: {}", header);
            }
            Err(DohProxyError::Proxy(
                "Upstream proxy authentication failed (407)".to_string(),
            ))
        }
        status => Err(DohProxyError::Proxy(format!(
            "Upstream proxy CONNECT failed with status {}",
            status
        ))),
    }
}
