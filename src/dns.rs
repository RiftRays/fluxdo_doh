//! DNS resolver with DOH and HTTPS record support for ECH config retrieval

use crate::error::{DohProxyError, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    proto::rr::rdata::HTTPS,
    TokioAsyncResolver,
};
use http::Uri;
use parking_lot::RwLock;
use reqwest::Client;
use rustls::pki_types::EchConfigListBytes;
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};
use tokio::net::lookup_host;
use tokio::sync::{Mutex, Notify};
use tracing::{debug, info, warn};

const MAX_HTTPS_ALIAS_DEPTH: usize = 4;

/// DNS resolver with ECH config caching
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
    doh_uri: Option<Uri>,
    doh_client: Option<Client>,
    force_doh_get: bool,
    /// Cache for ECH configs (domain -> ECHConfigList)
    ech_cache: Arc<RwLock<HashMap<String, CachedEchConfig>>>,
    /// Cache for resolved HTTPS/SVCB bindings
    https_binding_cache: Arc<RwLock<HashMap<String, CachedHttpsBinding>>>,
    /// Cache for IP addresses
    ip_cache: Arc<RwLock<HashMap<String, CachedIpAddrs>>>,
    ech_inflight: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    ip_inflight: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    ip_rtt_cache: Arc<RwLock<HashMap<IpAddr, CachedIpRtt>>>,
    prefer_ipv6: bool,
    resolve_timeout: Duration,
}

struct CachedEchConfig {
    config: EchConfigListBytes<'static>,
    expires_at: std::time::Instant,
}

struct CachedHttpsBinding {
    binding: Option<HttpsServiceBinding>,
    expires_at: std::time::Instant,
}

struct CachedIpAddrs {
    addrs: Vec<IpAddr>,
    expires_at: std::time::Instant,
}

struct CachedIpRtt {
    rtt_ms: u128,
    expires_at: std::time::Instant,
}

#[derive(Clone)]
struct HttpsServiceBinding {
    effective_name: String,
    ip_hints: Vec<IpAddr>,
    ech_config: Option<EchConfigListBytes<'static>>,
}

enum HttpsResolution {
    Alias(String),
    Service(HttpsServiceBinding),
}

impl DnsResolver {
    /// Create a new DNS resolver using Cloudflare DOH
    pub async fn new_cloudflare(prefer_ipv6: bool) -> Result<Self> {
        Self::with_resolver_config(ResolverConfig::cloudflare_https(), prefer_ipv6).await
    }

    /// Create a new DNS resolver with custom DOH server URL
    ///
    /// Supported URL formats:
    /// - `https://dns.example.com/dns-query` - Custom DOH server
    /// - `cloudflare` - Use Cloudflare DOH
    /// - `google` - Use Google DOH
    /// - `quad9` - Use Quad9 DOH
    pub async fn new(doh_url: &str, prefer_ipv6: bool) -> Result<Self> {
        let (config, doh_uri) = Self::parse_doh_url(doh_url, prefer_ipv6).await?;
        let mut resolver = Self::with_resolver_config(config, prefer_ipv6).await?;
        if let Some(uri) = doh_uri {
            resolver.doh_uri = Some(uri);
            resolver.doh_client = Some(Self::build_doh_client(resolver.resolve_timeout)?);
            resolver.force_doh_get = true;
        }
        Ok(resolver)
    }

    /// Parse DOH URL to ResolverConfig
    async fn parse_doh_url(
        doh_url: &str,
        prefer_ipv6: bool,
    ) -> Result<(ResolverConfig, Option<Uri>)> {
        use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup, Protocol};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        // Handle built-in providers
        let url_lower = doh_url.to_lowercase();

        // Cloudflare
        if url_lower == "cloudflare" || url_lower.contains("cloudflare-dns.com") {
            info!("Using Cloudflare DOH");
            return Ok((
                ResolverConfig::cloudflare_https(),
                Some("https://cloudflare-dns.com/dns-query".parse().unwrap()),
            ));
        }

        // Google
        if url_lower == "google" || url_lower.contains("dns.google") {
            info!("Using Google DOH");
            return Ok((
                ResolverConfig::google_https(),
                Some("https://dns.google/dns-query".parse().unwrap()),
            ));
        }

        // Quad9
        if url_lower == "quad9" || url_lower.contains("dns.quad9.net") {
            info!("Using Quad9 DOH");
            return Ok((
                ResolverConfig::quad9_https(),
                Some("https://dns.quad9.net/dns-query".parse().unwrap()),
            ));
        }

        // DNSPod (doh.pub)
        if url_lower.contains("doh.pub") {
            info!("Using DNSPod DOH");
            // DNSPod DOH: 1.12.12.12, 120.53.53.53
            let mut group = NameServerConfigGroup::new();
            for ip in &["1.12.12.12", "120.53.53.53"] {
                if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                    group.push(NameServerConfig {
                        socket_addr: SocketAddr::new(IpAddr::V4(addr), 443),
                        protocol: Protocol::Https,
                        tls_dns_name: Some("doh.pub".to_string()),
                        trust_negative_responses: true,
                        tls_config: None,
                        bind_addr: None,
                    });
                }
            }
            return Ok((
                ResolverConfig::from_parts(None, vec![], group),
                Some("https://doh.pub/dns-query".parse().unwrap()),
            ));
        }

        // Tencent DNS (dns.pub)
        if url_lower.contains("dns.pub") {
            info!("Using Tencent DOH");
            // Tencent DOH: 119.29.29.29, 119.28.28.28
            let mut group = NameServerConfigGroup::new();
            for ip in &["119.29.29.29", "119.28.28.28"] {
                if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                    group.push(NameServerConfig {
                        socket_addr: SocketAddr::new(IpAddr::V4(addr), 443),
                        protocol: Protocol::Https,
                        tls_dns_name: Some("dns.pub".to_string()),
                        trust_negative_responses: true,
                        tls_config: None,
                        bind_addr: None,
                    });
                }
            }
            return Ok((
                ResolverConfig::from_parts(None, vec![], group),
                Some("https://dns.pub/dns-query".parse().unwrap()),
            ));
        }

        // Alibaba DNS (dns.alidns.com)
        if url_lower.contains("alidns.com") {
            info!("Using Alibaba DOH");
            // Alibaba DOH: 223.5.5.5, 223.6.6.6
            let mut group = NameServerConfigGroup::new();
            for ip in &["223.5.5.5", "223.6.6.6"] {
                if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                    group.push(NameServerConfig {
                        socket_addr: SocketAddr::new(IpAddr::V4(addr), 443),
                        protocol: Protocol::Https,
                        tls_dns_name: Some("dns.alidns.com".to_string()),
                        trust_negative_responses: true,
                        tls_config: None,
                        bind_addr: None,
                    });
                }
            }
            return Ok((
                ResolverConfig::from_parts(None, vec![], group),
                Some("https://dns.alidns.com/dns-query".parse().unwrap()),
            ));
        }

        let uri: Uri = doh_url.parse().map_err(|e| {
            DohProxyError::InvalidUrl(format!("Invalid DOH URL '{}': {}", doh_url, e))
        })?;

        let scheme = uri
            .scheme_str()
            .ok_or_else(|| DohProxyError::InvalidUrl(format!("Missing URL scheme: {}", doh_url)))?;
        if scheme != "https" {
            return Err(DohProxyError::InvalidUrl(format!(
                "Unsupported DOH URL scheme '{}': {}",
                scheme, doh_url
            )));
        }

        let host = uri.host().ok_or_else(|| {
            DohProxyError::InvalidUrl(format!("Missing host in DOH URL: {}", doh_url))
        })?;
        let port = uri.port_u16().unwrap_or(443);
        let mut path = uri.path();
        if path.is_empty() {
            path = "/dns-query";
        }
        if !path.is_empty() && path != "/dns-query" {
            warn!(
                "Custom DOH path '{}' is not supported; hickory uses /dns-query",
                path
            );
        }

        let mut ips = Vec::new();
        if let Ok(ip) = host.parse::<IpAddr>() {
            ips.push(ip);
        } else {
            let addrs = lookup_host((host, port))
                .await
                .map_err(|e| DohProxyError::Dns(format!("Failed to resolve DOH host {}: {}", host, e)))?;
            ips.extend(addrs.map(|addr| addr.ip()));
        }

        if ips.is_empty() {
            return Err(DohProxyError::Dns(format!(
                "No IP addresses resolved for DOH host: {}",
                host
            )));
        }

        if prefer_ipv6 {
            ips.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
        } else {
            ips.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        }

        let group = NameServerConfigGroup::from_ips_https(&ips, port, host.to_string(), true);
        Ok((ResolverConfig::from_parts(None, vec![], group), Some(uri)))
    }

    /// Create a new DNS resolver with ResolverConfig
    pub async fn with_resolver_config(config: ResolverConfig, prefer_ipv6: bool) -> Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.use_hosts_file = false;
        let resolve_timeout = Duration::from_secs(5);
        opts.timeout = resolve_timeout;
        opts.attempts = 2;

        let resolver = TokioAsyncResolver::tokio(config, opts);

        Ok(Self {
            resolver,
            doh_uri: None,
            doh_client: None,
            force_doh_get: false,
            ech_cache: Arc::new(RwLock::new(HashMap::new())),
            https_binding_cache: Arc::new(RwLock::new(HashMap::new())),
            ip_cache: Arc::new(RwLock::new(HashMap::new())),
            ech_inflight: Arc::new(Mutex::new(HashMap::new())),
            ip_inflight: Arc::new(Mutex::new(HashMap::new())),
            ip_rtt_cache: Arc::new(RwLock::new(HashMap::new())),
            prefer_ipv6,
            resolve_timeout,
        })
    }

    /// Lookup ECH config for a domain via HTTPS DNS record
    pub async fn lookup_ech_config(&self, domain: &str) -> Result<Option<EchConfigListBytes<'static>>> {
        // Check cache first
        {
            let cache = self.ech_cache.read();
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > std::time::Instant::now() {
                    debug!("ECH config cache hit for {}", domain);
                    return Ok(Some(cached.config.clone()));
                }
            }
        }

        info!("Looking up HTTPS record for ECH config: {}", domain);

        let (notify, is_leader) = {
            let mut inflight = self.ech_inflight.lock().await;
            if let Some(existing) = inflight.get(domain) {
                (existing.clone(), false)
            } else {
                let notify = Arc::new(Notify::new());
                inflight.insert(domain.to_string(), notify.clone());
                (notify, true)
            }
        };

        if !is_leader {
            notify.notified().await;
            let cache = self.ech_cache.read();
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > std::time::Instant::now() {
                    debug!("ECH config cache hit for {}", domain);
                    return Ok(Some(cached.config.clone()));
                }
            }
            return Ok(None);
        }

        let start = std::time::Instant::now();
        let binding_result = if self.force_doh_get {
            self.resolve_https_binding_via_doh_get_cached(domain).await
        } else {
            self.resolve_https_binding_via_lookup_cached(domain).await
        };

        match binding_result {
            Ok(Some(binding)) => {
                if let Some(ech_config) = binding.ech_config {
                    info!(
                        "Found ECH config for {} via {} ({} bytes)",
                        domain,
                        binding.effective_name,
                        ech_config.len()
                    );

                    let cached = CachedEchConfig {
                        config: ech_config.clone(),
                        expires_at: std::time::Instant::now() + Duration::from_secs(600),
                    };
                    self.ech_cache.write().insert(domain.to_string(), cached);

                    debug!(
                        "ECH HTTPS lookup succeeded for {} in {} ms",
                        domain,
                        start.elapsed().as_millis()
                    );
                    let mut inflight = self.ech_inflight.lock().await;
                    inflight.remove(domain);
                    notify.notify_waiters();
                    return Ok(Some(ech_config));
                }
            }
            Ok(None) => {}
            Err(e) => {
                if self.force_doh_get {
                    warn!("ECH HTTPS lookup failed for {}: {}", domain, e);
                } else {
                    warn!(
                        "ECH HTTPS lookup failed for {}, falling back to DoH GET: {}",
                        domain, e
                    );
                    let result = self.lookup_ech_config_via_doh_get(domain).await;
                    let mut inflight = self.ech_inflight.lock().await;
                    inflight.remove(domain);
                    notify.notify_waiters();
                    return result;
                }
            }
        }

        warn!("No ECH config found in HTTPS record for {}", domain);
        let result = self.lookup_ech_config_via_doh_get(domain).await;
        let mut inflight = self.ech_inflight.lock().await;
        inflight.remove(domain);
        notify.notify_waiters();
        result
    }

    /// Extract ECH config from HTTPS/SVCB record
    fn extract_ech_from_https(&self, https: &HTTPS) -> Option<EchConfigListBytes<'static>> {
        use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};

        // HTTPS record contains SVCB parameters
        // ECH config is in the "ech" parameter (key = 5)
        for (key, value) in https.svc_params().iter() {
            // Check if this is the ECH parameter (key 5)
            if let SvcParamKey::EchConfig = key {
                // Extract ECH config bytes from the value
                if let SvcParamValue::EchConfig(ech_config) = value {
                    // EchConfig contains the raw bytes in its inner field
                    let bytes = Self::ensure_ech_config_list_len_prefix(ech_config.0.clone());
                    return Some(EchConfigListBytes::from(bytes));
                }
            }
        }

        None
    }

    /// Extract address hints from HTTPS/SVCB record.
    ///
    /// `ipv4hint` / `ipv6hint` are only hints, so callers should still
    /// fall back to A/AAAA lookups when they are absent.
    fn extract_ip_hints_from_https(&self, https: &HTTPS) -> Vec<IpAddr> {
        use hickory_resolver::proto::rr::rdata::svcb::SvcParamValue;

        let mut addrs = Vec::new();

        for (_, value) in https.svc_params().iter() {
            match value {
                SvcParamValue::Ipv4Hint(hints) => {
                    for addr in hints.0.iter().copied() {
                        let ip = IpAddr::V4(addr.0);
                        if !addrs.contains(&ip) {
                            addrs.push(ip);
                        }
                    }
                }
                SvcParamValue::Ipv6Hint(hints) => {
                    for addr in hints.0.iter().copied() {
                        let ip = IpAddr::V6(addr.0);
                        if !addrs.contains(&ip) {
                            addrs.push(ip);
                        }
                    }
                }
                _ => {}
            }
        }

        addrs
    }

    fn normalize_name(&self, name: &hickory_resolver::proto::rr::Name) -> String {
        let ascii = name.to_ascii();
        ascii.trim_end_matches('.').to_string()
    }

    fn resolve_https_rrset<'a, I>(&self, owner_domain: &str, records: I) -> Option<HttpsResolution>
    where
        I: IntoIterator<Item = &'a HTTPS>,
    {
        let mut alias_target: Option<String> = None;
        let mut service_records: Vec<&HTTPS> = Vec::new();

        for https in records {
            if https.svc_priority() == 0 {
                if !https.target_name().is_root() && alias_target.is_none() {
                    alias_target = Some(self.normalize_name(https.target_name()));
                }
            } else {
                service_records.push(https);
            }
        }

        if let Some(target) = alias_target {
            return Some(HttpsResolution::Alias(target));
        }

        let service = service_records
            .into_iter()
            .min_by_key(|https| https.svc_priority())?;

        let effective_name = if service.target_name().is_root() {
            owner_domain.to_string()
        } else {
            self.normalize_name(service.target_name())
        };

        Some(HttpsResolution::Service(HttpsServiceBinding {
            effective_name,
            ip_hints: self.extract_ip_hints_from_https(service),
            ech_config: self.extract_ech_from_https(service),
        }))
    }

    async fn resolve_https_binding_via_lookup(
        &self,
        domain: &str,
    ) -> Result<Option<HttpsServiceBinding>> {
        let mut current = domain.to_string();

        for _ in 0..MAX_HTTPS_ALIAS_DEPTH {
            let lookup = tokio::time::timeout(
                self.resolve_timeout,
                self.resolver
                    .lookup(&current, hickory_resolver::proto::rr::RecordType::HTTPS),
            )
            .await
            .map_err(|_| DohProxyError::Dns(format!("HTTPS lookup timed out for {}", current)))?
            .map_err(|e| DohProxyError::Dns(format!("HTTPS lookup failed for {}: {}", current, e)))?;

            let resolution = self.resolve_https_rrset(
                &current,
                lookup.iter().filter_map(|record| record.as_https()),
            );

            match resolution {
                Some(HttpsResolution::Alias(next)) => {
                    if next.is_empty() || next == current {
                        warn!("Ignoring invalid HTTPS alias target for {}", current);
                        return Ok(None);
                    }
                    debug!("Following HTTPS alias: {} -> {}", current, next);
                    current = next;
                }
                Some(HttpsResolution::Service(binding)) => return Ok(Some(binding)),
                None => return Ok(None),
            }
        }

        warn!(
            "HTTPS alias chain exceeded {} hops for {}",
            MAX_HTTPS_ALIAS_DEPTH,
            domain
        );
        Ok(None)
    }

    async fn resolve_https_binding_via_doh_get(
        &self,
        domain: &str,
    ) -> Result<Option<HttpsServiceBinding>> {
        let mut current = domain.to_string();

        for _ in 0..MAX_HTTPS_ALIAS_DEPTH {
            let Some(message) = self
                .doh_get_message(&current, hickory_resolver::proto::rr::RecordType::HTTPS)
                .await?
            else {
                return Ok(None);
            };

            let resolution = self.resolve_https_rrset(
                &current,
                message.answers().iter().filter_map(|record| match record.data() {
                    Some(hickory_resolver::proto::rr::RData::HTTPS(https)) => Some(https),
                    _ => None,
                }),
            );

            match resolution {
                Some(HttpsResolution::Alias(next)) => {
                    if next.is_empty() || next == current {
                        warn!("Ignoring invalid HTTPS alias target for {}", current);
                        return Ok(None);
                    }
                    debug!("Following HTTPS alias via DoH GET: {} -> {}", current, next);
                    current = next;
                }
                Some(HttpsResolution::Service(binding)) => return Ok(Some(binding)),
                None => return Ok(None),
            }
        }

        warn!(
            "HTTPS alias chain exceeded {} hops for {}",
            MAX_HTTPS_ALIAS_DEPTH,
            domain
        );
        Ok(None)
    }

    fn get_cached_https_binding(&self, domain: &str) -> Option<Option<HttpsServiceBinding>> {
        let cache = self.https_binding_cache.read();
        cache.get(domain).and_then(|cached| {
            if cached.expires_at > std::time::Instant::now() {
                Some(cached.binding.clone())
            } else {
                None
            }
        })
    }

    fn cache_https_binding(&self, domain: &str, binding: Option<HttpsServiceBinding>) {
        let cached = CachedHttpsBinding {
            binding,
            expires_at: std::time::Instant::now() + Duration::from_secs(600),
        };
        self.https_binding_cache
            .write()
            .insert(domain.to_string(), cached);
    }

    async fn resolve_https_binding_via_lookup_cached(
        &self,
        domain: &str,
    ) -> Result<Option<HttpsServiceBinding>> {
        if let Some(cached) = self.get_cached_https_binding(domain) {
            debug!("HTTPS binding cache hit for {}", domain);
            return Ok(cached);
        }

        let binding = self.resolve_https_binding_via_lookup(domain).await?;
        self.cache_https_binding(domain, binding.clone());
        Ok(binding)
    }

    async fn resolve_https_binding_via_doh_get_cached(
        &self,
        domain: &str,
    ) -> Result<Option<HttpsServiceBinding>> {
        if let Some(cached) = self.get_cached_https_binding(domain) {
            debug!("HTTPS binding cache hit for {}", domain);
            return Ok(cached);
        }

        let binding = self.resolve_https_binding_via_doh_get(domain).await?;
        self.cache_https_binding(domain, binding.clone());
        Ok(binding)
    }

    fn sort_ip_addrs_by_preference(&self, addrs: &mut Vec<IpAddr>) {
        if self.prefer_ipv6 {
            addrs.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
        } else {
            addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        }
    }

    fn cache_ip_addrs(&self, domain: &str, addrs: &[IpAddr]) {
        let cached = CachedIpAddrs {
            addrs: addrs.to_vec(),
            expires_at: std::time::Instant::now() + Duration::from_secs(600),
        };
        self.ip_cache.write().insert(domain.to_string(), cached);
    }

    fn ensure_ech_config_list_len_prefix(bytes: Vec<u8>) -> Vec<u8> {
        if bytes.len() >= 2 {
            let declared = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
            if declared == bytes.len().saturating_sub(2) {
                return bytes;
            }
        }

        if bytes.len() > u16::MAX as usize {
            warn!(
                "ECH config list too large ({} bytes), returning as-is",
                bytes.len()
            );
            return bytes;
        }

        let mut prefixed = Vec::with_capacity(bytes.len() + 2);
        let len = bytes.len() as u16;
        prefixed.extend_from_slice(&len.to_be_bytes());
        prefixed.extend_from_slice(&bytes);
        prefixed
    }

    /// Lookup IP addresses for a domain
    pub async fn lookup_ip(&self, domain: &str) -> Result<Vec<IpAddr>> {
        // Check cache first
        {
            let cache = self.ip_cache.read();
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > std::time::Instant::now() {
                    debug!("IP cache hit for {}", domain);
                    return Ok(cached.addrs.clone());
                }
            }
        }

        debug!("Looking up IP for {}", domain);

        let (notify, is_leader) = {
            let mut inflight = self.ip_inflight.lock().await;
            if let Some(existing) = inflight.get(domain) {
                (existing.clone(), false)
            } else {
                let notify = Arc::new(Notify::new());
                inflight.insert(domain.to_string(), notify.clone());
                (notify, true)
            }
        };

        if !is_leader {
            notify.notified().await;
            let cache = self.ip_cache.read();
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > std::time::Instant::now() {
                    debug!("IP cache hit for {}", domain);
                    return Ok(cached.addrs.clone());
                }
            }
            return Err(DohProxyError::Dns(format!("No IP found for {}", domain)));
        }

        if self.force_doh_get {
            let result = self.lookup_ip_via_doh_get(domain).await;
            let mut inflight = self.ip_inflight.lock().await;
            inflight.remove(domain);
            notify.notify_waiters();
            return result;
        }

        let https_start = std::time::Instant::now();
        let mut ip_domain = domain.to_string();
        match self.resolve_https_binding_via_lookup_cached(domain).await {
            Ok(Some(binding)) => {
                ip_domain = binding.effective_name;
                if !binding.ip_hints.is_empty() {
                    let mut https_addrs = binding.ip_hints;
                    self.sort_ip_addrs_by_preference(&mut https_addrs);
                    self.cache_ip_addrs(domain, &https_addrs);
                    debug!(
                        "IP HTTPS hint lookup succeeded for {} in {} ms",
                        domain,
                        https_start.elapsed().as_millis()
                    );
                    let mut inflight = self.ip_inflight.lock().await;
                    inflight.remove(domain);
                    notify.notify_waiters();
                    return Ok(https_addrs);
                }
            }
            Ok(None) => {}
            Err(e) => {
                warn!(
                    "IP HTTPS hint lookup failed for {}, falling back to A/AAAA: {}",
                    domain, e
                );
            }
        }

        let start = std::time::Instant::now();
        let lookup =
            match tokio::time::timeout(self.resolve_timeout, self.resolver.lookup_ip(&ip_domain)).await
            {
                Ok(result) => match result {
                    Ok(lookup) => lookup,
                    Err(e) => {
                        warn!(
                            "IP lookup failed for {} (effective host {}), falling back to DoH GET: {}",
                            domain, ip_domain, e
                        );
                        let result = self.lookup_ip_via_doh_get(domain).await;
                        let mut inflight = self.ip_inflight.lock().await;
                        inflight.remove(domain);
                        notify.notify_waiters();
                        return result;
                    }
                },
                Err(_) => {
                    warn!(
                        "IP lookup timed out for {} (effective host {}), falling back to DoH GET",
                        domain, ip_domain
                    );
                    let result = self.lookup_ip_via_doh_get(domain).await;
                    let mut inflight = self.ip_inflight.lock().await;
                    inflight.remove(domain);
                    notify.notify_waiters();
                    return result;
                }
            };

        let mut addrs: Vec<IpAddr> = lookup.iter().collect();
        self.sort_ip_addrs_by_preference(&mut addrs);
        self.cache_ip_addrs(domain, &addrs);

        debug!(
            "IP lookup succeeded for {} via {} in {} ms",
            domain,
            ip_domain,
            start.elapsed().as_millis()
        );
        let mut inflight = self.ip_inflight.lock().await;
        inflight.remove(domain);
        notify.notify_waiters();
        Ok(addrs)
    }

    /// Set IPv6 preference
    pub fn set_prefer_ipv6(&mut self, prefer: bool) {
        self.prefer_ipv6 = prefer;
        // Clear IP cache when preference changes
        self.ip_cache.write().clear();
    }

    pub fn prefer_ipv6(&self) -> bool {
        self.prefer_ipv6
    }

    pub fn record_ip_rtt(&self, addr: IpAddr, rtt: Duration) {
        let cached = CachedIpRtt {
            rtt_ms: rtt.as_millis(),
            expires_at: std::time::Instant::now() + Duration::from_secs(600),
        };
        self.ip_rtt_cache.write().insert(addr, cached);
    }

    pub fn order_addrs_by_rtt(&self, mut addrs: Vec<IpAddr>) -> Vec<IpAddr> {
        let now = std::time::Instant::now();
        let cache = self.ip_rtt_cache.read();
        addrs.sort_by_key(|addr| {
            let rtt = cache
                .get(addr)
                .filter(|entry| entry.expires_at > now)
                .map(|entry| entry.rtt_ms)
                .unwrap_or(u128::MAX);
            let family_bias = if self.prefer_ipv6 {
                if addr.is_ipv6() { 0 } else { 1 }
            } else {
                if addr.is_ipv4() { 0 } else { 1 }
            };
            (rtt, family_bias)
        });
        addrs
    }

    fn build_doh_client(timeout: Duration) -> Result<Client> {
        Client::builder()
            .timeout(timeout)
            // Keep connections alive to reuse TLS/HTTP2 sessions.
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(8)
            .tcp_keepalive(Duration::from_secs(60))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true)
            .build()
            .map_err(|e| DohProxyError::Proxy(format!("Failed to build DoH client: {}", e)))
    }

    async fn lookup_ech_config_via_doh_get(
        &self,
        domain: &str,
    ) -> Result<Option<EchConfigListBytes<'static>>> {
        let start = std::time::Instant::now();
        if let Some(binding) = self.resolve_https_binding_via_doh_get_cached(domain).await? {
            if let Some(ech_config) = binding.ech_config {
                let cached = CachedEchConfig {
                    config: ech_config.clone(),
                    expires_at: std::time::Instant::now() + Duration::from_secs(600),
                };
                self.ech_cache.write().insert(domain.to_string(), cached);
                debug!(
                    "ECH DoH GET lookup succeeded for {} via {} in {} ms",
                    domain,
                    binding.effective_name,
                    start.elapsed().as_millis()
                );
                return Ok(Some(ech_config));
            }
        }

        Ok(None)
    }

    async fn lookup_ip_via_doh_get(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let start = std::time::Instant::now();
        let mut ip_domain = domain.to_string();

        if let Some(binding) = self.resolve_https_binding_via_doh_get_cached(domain).await? {
            ip_domain = binding.effective_name;
            if !binding.ip_hints.is_empty() {
                let mut https_addrs = binding.ip_hints;
                self.sort_ip_addrs_by_preference(&mut https_addrs);
                self.cache_ip_addrs(domain, &https_addrs);
                debug!(
                    "IP HTTPS hint DoH GET lookup succeeded for {} in {} ms",
                    domain,
                    start.elapsed().as_millis()
                );
                return Ok(https_addrs);
            }
        }

        let mut addrs = Vec::new();

        let (a_result, aaaa_result) = tokio::join!(
            self.doh_get_message(&ip_domain, hickory_resolver::proto::rr::RecordType::A),
            self.doh_get_message(&ip_domain, hickory_resolver::proto::rr::RecordType::AAAA),
        );

        if let Ok(Some(message)) = a_result {
            for record in message.answers() {
                if let Some(hickory_resolver::proto::rr::RData::A(a)) = record.data() {
                    addrs.push(IpAddr::V4(a.0));
                }
            }
        }

        if let Ok(Some(message)) = aaaa_result {
            for record in message.answers() {
                if let Some(hickory_resolver::proto::rr::RData::AAAA(aaaa)) = record.data() {
                    addrs.push(IpAddr::V6(aaaa.0));
                }
            }
        }

        if addrs.is_empty() {
            return Err(DohProxyError::Dns(format!("No IP found for {}", domain)));
        }

        self.sort_ip_addrs_by_preference(&mut addrs);
        self.cache_ip_addrs(domain, &addrs);

        debug!(
            "IP DoH GET lookup succeeded for {} via {} in {} ms",
            domain,
            ip_domain,
            start.elapsed().as_millis()
        );
        Ok(addrs)
    }

    async fn doh_get_message(
        &self,
        domain: &str,
        record_type: hickory_resolver::proto::rr::RecordType,
    ) -> Result<Option<hickory_resolver::proto::op::Message>> {
        let Some(client) = self.doh_client.as_ref() else {
            return Ok(None);
        };
        let Some(uri) = self.doh_uri.as_ref() else {
            return Ok(None);
        };
        let start = std::time::Instant::now();

        use hickory_resolver::proto::op::{Edns, Message, Query};
        use hickory_resolver::proto::rr::Name;
        use std::str::FromStr;

        let fqdn = if domain.ends_with('.') {
            domain.to_string()
        } else {
            format!("{}.", domain)
        };
        let name = Name::from_str(&fqdn)
            .map_err(|e| DohProxyError::Dns(format!("Invalid domain {}: {}", domain, e)))?;

        let mut request = Message::new();
        request.add_query(Query::query(name, record_type));
        request.set_recursion_desired(true);
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        *request.extensions_mut() = Some(edns);

        let bytes = request
            .to_vec()
            .map_err(|e| DohProxyError::Dns(format!("Failed to encode DNS query: {}", e)))?;
        let encoded = URL_SAFE_NO_PAD.encode(bytes);

        let scheme = uri.scheme_str().unwrap_or("https");
        let authority = uri
            .authority()
            .ok_or_else(|| DohProxyError::InvalidUrl("Missing DOH authority".to_string()))?;
        let path = uri.path();
        let url = format!("{}://{}{}?dns={}", scheme, authority, path, encoded);

        let response = client
            .get(url)
            .header("accept", "application/dns-message")
            .send()
            .await
            .map_err(|e| DohProxyError::Dns(format!("DoH GET failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(DohProxyError::Dns(format!(
                "DoH GET http error: {}",
                response.status()
            )));
        }

        if let Some(content_type) = response.headers().get(reqwest::header::CONTENT_TYPE) {
            let content_type = content_type
                .to_str()
                .map_err(|e| DohProxyError::Dns(format!("Bad Content-Type: {}", e)))?;
            if !content_type.starts_with("application/dns-message") {
                return Err(DohProxyError::Dns(format!(
                    "Unsupported Content-Type: {}",
                    content_type
                )));
            }
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| DohProxyError::Dns(format!("DoH GET read failed: {}", e)))?;
        let message = hickory_resolver::proto::op::Message::from_vec(&body)
            .map_err(|e| DohProxyError::Dns(format!("Invalid DNS response: {}", e)))?;

        debug!(
            "DoH GET {} {} completed in {} ms",
            domain,
            record_type,
            start.elapsed().as_millis()
        );
        Ok(Some(message))
    }
}
