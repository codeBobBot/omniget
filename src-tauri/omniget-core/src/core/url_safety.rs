//! URL safety helpers shared across the download engine.

use anyhow::anyhow;

/// Returns true if the absolute URL points at a non-public address
/// (loopback, private RFC1918, link-local, or cloud metadata endpoints).
///
/// Used to block blind SSRF from untrusted content such as malicious HLS
/// playlists or thumbnail/metadata URLs supplied via the API. Only triggers
/// for http(s) URLs with a parseable host; anything unparseable is treated as
/// public so we never accidentally block legitimate CDN content.
pub fn is_private_host(url: &str) -> bool {
    let host = match url::Url::parse(url).ok().and_then(|u| u.host_str().map(|h| h.to_string())) {
        Some(h) => h,
        None => return false,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');

    // cloud metadata endpoints
    if host == "169.254.169.254" {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => return v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified(),
            std::net::IpAddr::V6(v6) => return v6.is_loopback() || v6.is_unspecified(),
        }
    }
    // hostnames that resolve to private ranges (defense in depth)
    host == "localhost"
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".svc")
        || host.ends_with(".svc.cluster.local")
}

/// Perform a DNS lookup and verify the host resolves ONLY to public IP
/// addresses. This closes the TOCTOU/DNS-rebinding gap: `is_private_host`
/// validates the URL string statically, but a hostname can later resolve to a
/// private IP via a short-TTL record swapped after the static check. Returns an
/// error if any resolved address is private/loopback/link-local/reserved.
pub async fn assert_public_host(url: &str) -> anyhow::Result<()> {
    let host = match url::Url::parse(url).ok().and_then(|u| u.host_str().map(|h| h.to_string())) {
        Some(h) => h,
        None => return Err(anyhow!("invalid url host: {}", url)),
    };
    // IP-literal hosts are checked directly.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_private_ip(&ip) {
            return Err(anyhow!("refusing to connect to private host: {}", ip));
        }
        return Ok(());
    }
    let addrs = tokio::net::lookup_host((host.as_str(), 0)).await?;
    for addr in addrs {
        if is_private_ip(&addr.ip()) {
            return Err(anyhow!("refusing to connect to private host: {}", addr.ip()));
        }
    }
    Ok(())
}

fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || is_reserved_v4(v4)
                || is_shared_address(v4)
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || is_ipv4_mapped_private(v6)
        }
    }
}

/// `Ipv4Addr::is_reserved()` is unstable; replicate its semantics with the
/// stable `is_special()` plus explicit reserved-range checks.
fn is_reserved_v4(v4: &std::net::Ipv4Addr) -> bool {
    if v4.is_special() {
        return true;
    }
    let o = v4.octets();
    // 192.0.0.0/24 (incl. 192.0.2.0/24 documentation handled above),
    // 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4, 0.0.0.0/8
    (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 240
        || o[0] == 0
}

fn is_shared_address(ip: &std::net::Ipv4Addr) -> bool {
    // 100.64.0.0/10 (CGNAT / shared address space)
    ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 0x40
}

fn is_ipv4_mapped_private(ip: &std::net::Ipv6Addr) -> bool {
    match ip.to_ipv4_mapped() {
        Some(v4) => {
            let mapped: std::net::IpAddr = v4.into();
            is_private_ip(&mapped)
        }
        None => false,
    }
}
