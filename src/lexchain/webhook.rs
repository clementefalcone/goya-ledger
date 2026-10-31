use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub fn validate_webhook_url(raw: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(raw).map_err(|e| format!("webhook_url {raw:?}: {e}"))?;
    if url.scheme() != "https" {
        return Err(format!("webhook_url {raw:?} must use https"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| format!("webhook_url {raw:?} has no host"))?;
    let literal_address = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>();
    if literal_address.is_ok_and(|ip| !is_public_address(ip)) {
        return Err(format!(
            "webhook_url {raw:?} points to a non-public address"
        ));
    }
    Ok(url)
}

pub async fn resolve_public_address(url: &reqwest::Url) -> Result<SocketAddr, String> {
    let host = url
        .host_str()
        .ok_or_else(|| format!("webhook_url {url} has no host"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("webhook host {host} did not resolve: {e}"))?
        .collect();
    if addresses.is_empty() {
        return Err(format!("webhook host {host} resolved to no address"));
    }
    if let Some(blocked) = addresses.iter().find(|a| !is_public_address(a.ip())) {
        return Err(format!(
            "webhook host {host} resolves to non-public address {}",
            blocked.ip()
        ));
    }
    Ok(addresses[0])
}

pub fn is_public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_ipv4(v4),
            None => is_public_ipv6(v6),
        },
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    let is_shared_carrier_nat = first == 100 && (64..128).contains(&second);
    let is_benchmarking = first == 198 && (18..20).contains(&second);
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || is_shared_carrier_nat
        || is_benchmarking
        || first == 0
        || first >= 240)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let first_segment = ip.segments()[0];
    let is_unique_local = (first_segment & 0xfe00) == 0xfc00;
    let is_link_local = (first_segment & 0xffc0) == 0xfe80;
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_unique_local
        || is_link_local)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_public_https_url() {
        assert!(validate_webhook_url("https://hooks.example.com/lexchain").is_ok());
    }

    #[test]
    fn rejects_plain_http() {
        assert!(validate_webhook_url("http://hooks.example.com/lexchain").is_err());
    }

    #[test]
    fn rejects_internal_address_literals() {
        let internal_urls = [
            "https://127.0.0.1/",
            "https://10.0.0.5/",
            "https://169.254.169.254/latest/meta-data",
            "https://192.168.1.1/",
            "https://100.64.0.1/",
            "https://[::1]/",
            "https://[fd00::1]/",
            "https://[fe80::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://0.0.0.0/",
        ];
        for url in internal_urls {
            assert!(validate_webhook_url(url).is_err(), "{url} must be rejected");
        }
    }

    #[test]
    fn treats_public_addresses_as_public() {
        assert!(is_public_address("8.8.8.8".parse().unwrap()));
        assert!(is_public_address("2606:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn refuses_a_host_that_resolves_to_loopback() {
        let url = reqwest::Url::parse("https://localhost/hook").unwrap();
        assert!(resolve_public_address(&url).await.is_err());
    }
}
