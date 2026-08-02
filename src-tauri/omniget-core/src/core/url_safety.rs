//! URL safety helpers shared across the download engine.

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
