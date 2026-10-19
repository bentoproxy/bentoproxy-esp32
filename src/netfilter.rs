//! Target filtering for relay connections.
//!
//! This node sits inside a volunteer's home network, so an unfiltered relay
//! would let any proxy user reach the router's admin page, a NAS, a printer,
//! or anything else on the LAN. Resolve the target first, then refuse every
//! address that is not publicly routable.
//!
//! Mirrors the filter in bentoproxy-agent's relay.rs; keep the two in sync.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// Resolve `host:port` and keep only publicly routable addresses.
///
/// Returns an empty vec when the target resolves exclusively to blocked
/// addresses, which the caller must treat as a refusal rather than a miss.
pub fn resolve_allowed(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    let addrs = (host, port).to_socket_addrs()?;
    Ok(addrs.filter(|sa| !is_blocked(&sa.ip())).collect())
}

/// Is this address off-limits for relayed traffic?
pub fn is_blocked(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()                    // 127.0.0.0/8
                || v4.is_private()              // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()           // 169.254.0.0/16
                || v4.is_unspecified()          // 0.0.0.0
                || v4.is_broadcast()            // 255.255.255.255
                || v4.is_multicast()            // 224.0.0.0/4
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64 // 100.64/10 CGNAT
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()                    // ::1
                || v6.is_unspecified()          // ::
                || v6.is_multicast()            // ff00::/8
                || (v6.segments()[0] & 0xfe00) == 0xfc00  // fc00::/7 unique local
                || (v6.segments()[0] & 0xffc0) == 0xfe80  // fe80::/10 link local
                || match v6.to_ipv4_mapped() {
                    // ::ffff:192.168.1.1 must not slip past the v4 rules.
                    Some(v4) => is_blocked(&IpAddr::V4(v4)),
                    None => false,
                }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_the_home_lan() {
        assert!(is_blocked(&"192.168.1.1".parse().unwrap()));
        assert!(is_blocked(&"10.0.0.1".parse().unwrap()));
        assert!(is_blocked(&"172.16.0.1".parse().unwrap()));
        assert!(is_blocked(&"127.0.0.1".parse().unwrap()));
        assert!(is_blocked(&"169.254.1.1".parse().unwrap()));
        assert!(is_blocked(&"100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv6_private_and_mapped() {
        assert!(is_blocked(&"::1".parse().unwrap()));
        assert!(is_blocked(&"fe80::1".parse().unwrap()));
        assert!(is_blocked(&"fd00::1".parse().unwrap()));
        assert!(is_blocked(&"::ffff:192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn allows_public_targets() {
        assert!(!is_blocked(&"8.8.8.8".parse().unwrap()));
        assert!(!is_blocked(&"104.16.132.229".parse().unwrap()));
        assert!(!is_blocked(&"2606:4700::6812:1092".parse().unwrap()));
        assert!(!is_blocked(&"100.128.0.1".parse().unwrap()));
    }
}
