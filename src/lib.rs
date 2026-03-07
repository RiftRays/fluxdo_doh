//! DOH Proxy - DNS over HTTPS proxy with ECH support
//!
//! This library provides a local HTTP/HTTPS proxy that uses DOH for DNS
//! resolution and supports ECH to encrypt the SNI field in TLS handshakes.

use serde::{Deserialize, Serialize};

pub mod cert;
pub mod dns;
pub mod ech;
pub mod error;
pub mod ffi;
pub mod proxy;
pub mod tls_crypto;
pub mod upstream;

pub use error::DohProxyError;
pub use proxy::DohProxyServer;

/// Upstream proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamProxyConfig {
    /// Upstream proxy protocol. V1 only supports `http`.
    #[serde(default = "default_upstream_protocol")]
    pub protocol: String,
    /// Upstream proxy host
    pub host: String,
    /// Upstream proxy port
    pub port: u16,
    /// Optional username
    #[serde(default)]
    pub username: Option<String>,
    /// Optional password
    #[serde(default)]
    pub password: Option<String>,
}

impl UpstreamProxyConfig {
    pub fn is_valid(&self) -> bool {
        !self.host.trim().is_empty() && self.port > 0
    }

    pub fn protocol(&self) -> &str {
        let protocol = self.protocol.trim();
        if protocol.is_empty() {
            "http"
        } else {
            protocol
        }
    }
}

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Local address to bind (default: 127.0.0.1)
    pub bind_addr: String,
    /// Local port to bind (default: 0 for auto-select)
    pub bind_port: u16,
    /// DOH server URL for DNS queries
    pub doh_server: String,
    /// Whether to prefer IPv6
    pub prefer_ipv6: bool,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Optional upstream proxy configuration
    #[serde(default)]
    pub upstream_proxy: Option<UpstreamProxyConfig>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1".to_string(),
            bind_port: 0,
            doh_server: "https://cloudflare-dns.com/dns-query".to_string(),
            prefer_ipv6: false,
            timeout_secs: 30,
            upstream_proxy: None,
        }
    }
}

fn default_upstream_protocol() -> String {
    "http".to_string()
}
