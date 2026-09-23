// Where a request came from -- and, just as importantly, how much that
// answer is worth.
//
// Two things need this: the login throttle keys on it (M-02, so that a
// remote caller can only ever throttle themselves), and the audit log
// records it (M-01, so that a login failure names an address). Both are
// worthless -- worse than worthless, actively misleading -- if the value can
// be set by the caller. So the trust rule is spelled out here once rather
// than re-derived at each call site.
//
// What nginx actually sends was checked against the nixpkgs this repo pins,
// not recalled. `services.nginx.recommendedProxySettings = true` (set in
// modules/proxy/nginx.nix) emits, from nixpkgs'
// nixos/modules/services/web-servers/nginx/default.nix:
//
//     proxy_set_header  X-Real-IP $remote_addr;
//     proxy_set_header  X-Forwarded-For $proxy_add_x_forwarded_for;
//
// Those two differ in exactly the way that matters. `X-Real-IP` is SET from
// nginx's own view of the peer, so whatever the caller sent under that name
// is overwritten and cannot survive. `X-Forwarded-For` is APPENDED to what
// the caller sent, so its left-hand entries are attacker-chosen. This file
// therefore uses X-Real-IP and deliberately never reads X-Forwarded-For.
//
// The second half of the rule is that X-Real-IP is only meaningful if nginx
// really is what produced it. modules/core/daemon.nix asserts at eval time
// that ferrum.daemon.listenAddress is a loopback address, so nginx is the
// only thing that can reach ferrumd at all -- which makes "the socket peer
// is loopback" a real proxy check rather than a guess. If that assertion
// ever stops holding, a request arriving from somewhere else is Direct and
// its X-Real-IP is ignored, automatically, with no second place to update.
//
// Note for the D4 scan in main.rs: X-Real-IP is not a forward-auth identity
// header and is not on that forbid-list. Nothing here influences WHO the
// caller is -- require_session answers that from the session cookie alone.
// This decides only what address gets written in a log line and counted by
// a throttle.
use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

/// The header nginx sets from its own view of the peer.
const REAL_IP_HEADER: &str = "x-real-ip";

/// A request's origin, carrying how it was determined.
///
/// The provenance is part of the value rather than dropped on the floor,
/// because a log line that prints an address without saying where the
/// address came from reads as authoritative whether or not it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientAddr {
    /// nginx's `X-Real-IP`, trusted because the request arrived over
    /// loopback and so came through the proxy.
    Proxied(IpAddr),
    /// The socket peer itself -- either a direct loopback caller, or a
    /// request that reached ferrumd without passing through nginx.
    Direct(IpAddr),
    /// No peer address was available. In production this does not happen;
    /// it is what the test harness sees, since it drives the router with no
    /// socket underneath it.
    Unknown,
}

impl ClientAddr {
    /// Resolves the origin of one request.
    ///
    /// # Arguments
    /// * `peer` - the real socket peer, or `None` when there is no socket.
    /// * `headers` - the request headers, read only for `X-Real-IP`.
    ///
    /// A header that does not parse as an IP address is discarded rather
    /// than passed through: an unparsed string is not an address, and
    /// putting one in a log line is how a caller writes their own content
    /// into the journal.
    pub fn resolve(peer: Option<SocketAddr>, headers: &HeaderMap) -> Self {
        let Some(peer) = peer else {
            return ClientAddr::Unknown;
        };
        let peer_ip = peer.ip();
        if peer_ip.is_loopback() {
            if let Some(real) = headers
                .get(REAL_IP_HEADER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<IpAddr>().ok())
            {
                return ClientAddr::Proxied(real);
            }
        }
        ClientAddr::Direct(peer_ip)
    }

    /// The address itself, for a log field.
    pub fn address(&self) -> String {
        match self {
            ClientAddr::Proxied(ip) | ClientAddr::Direct(ip) => ip.to_string(),
            ClientAddr::Unknown => "unknown".to_string(),
        }
    }

    /// How `address` was determined, logged beside it so an operator reading
    /// the journal can tell a proxied address from a direct one rather than
    /// having to assume.
    pub fn source(&self) -> &'static str {
        match self {
            ClientAddr::Proxied(_) => "x-real-ip",
            ClientAddr::Direct(_) => "peer",
            ClientAddr::Unknown => "none",
        }
    }

    /// The key the login throttle counts against.
    ///
    /// Deliberately the same string for every `Unknown` caller. That case
    /// does not arise on a real host (there is always a socket), and making
    /// it one shared bucket keeps an unattributable request throttled
    /// rather than exempt.
    pub fn throttle_key(&self) -> String {
        format!("{}:{}", self.source(), self.address())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    fn peer(addr: &str) -> Option<SocketAddr> {
        Some(addr.parse().unwrap())
    }

    #[test]
    fn a_loopback_peer_with_a_real_ip_header_is_the_proxied_client() {
        let resolved =
            ClientAddr::resolve(peer("127.0.0.1:53124"), &headers(&[("x-real-ip", "203.0.113.7")]));
        assert_eq!(resolved, ClientAddr::Proxied("203.0.113.7".parse().unwrap()));
        assert_eq!(resolved.address(), "203.0.113.7");
        assert_eq!(resolved.source(), "x-real-ip");
    }

    /// The whole point of the loopback condition. A request that did NOT
    /// come through nginx carries whatever header its sender chose, so the
    /// header must not be believed -- otherwise the throttle key and every
    /// audit line become caller-controlled.
    #[test]
    fn a_non_loopback_peer_does_not_get_to_name_its_own_address() {
        let resolved = ClientAddr::resolve(
            peer("198.51.100.4:41000"),
            &headers(&[("x-real-ip", "127.0.0.1")]),
        );
        assert_eq!(resolved, ClientAddr::Direct("198.51.100.4".parse().unwrap()));
        assert_eq!(resolved.address(), "198.51.100.4");
        assert_eq!(resolved.source(), "peer");
    }

    /// X-Forwarded-For is appended to by nginx rather than set, so its
    /// left-hand entries are whatever the caller sent. It must never be the
    /// source of an address, even from loopback.
    #[test]
    fn a_forwarded_for_header_is_never_consulted() {
        let resolved = ClientAddr::resolve(
            peer("127.0.0.1:53124"),
            &headers(&[("x-forwarded-for", "203.0.113.9, 127.0.0.1")]),
        );
        assert_eq!(
            resolved,
            ClientAddr::Direct("127.0.0.1".parse().unwrap()),
            "an address taken from X-Forwarded-For would be attacker-chosen"
        );
    }

    /// A header that is not an address is not an address, and must not reach
    /// a log line as if it were one.
    ///
    /// Worth recording what this test can and cannot reach: the nastiest
    /// version of this -- a value carrying a newline, to forge a second
    /// audit line -- turns out to be unrepresentable. `HeaderValue` refuses
    /// control characters, so the fixture below panicked when it was first
    /// written with an embedded newline. That is a real defence living in
    /// the http layer rather than here, so this asserts the part that IS
    /// reachable: ordinary junk is discarded rather than passed through.
    #[test]
    fn an_unparseable_real_ip_header_is_discarded_rather_than_logged() {
        let resolved = ClientAddr::resolve(
            peer("127.0.0.1:53124"),
            &headers(&[("x-real-ip", "not-an-ip event=login outcome=success")]),
        );
        assert_eq!(resolved, ClientAddr::Direct("127.0.0.1".parse().unwrap()));
        assert_eq!(resolved.address(), "127.0.0.1");
    }

    /// The companion to the above, pinning the http-layer defence itself so
    /// a future change that starts accepting raw bytes cannot quietly
    /// reintroduce log forging.
    #[test]
    fn a_header_value_cannot_carry_a_newline_at_all() {
        assert!(
            "203.0.113.7\nevent=login".parse::<axum::http::HeaderValue>().is_err(),
            "if a header value could carry a newline, an address field could forge a log line"
        );
    }

    #[test]
    fn no_socket_is_unknown_rather_than_a_fabricated_address() {
        let resolved = ClientAddr::resolve(None, &headers(&[("x-real-ip", "203.0.113.7")]));
        assert_eq!(resolved, ClientAddr::Unknown);
        assert_eq!(resolved.address(), "unknown");
        assert_eq!(resolved.source(), "none");
    }

    /// Two different proxied clients must not share a throttle bucket, or
    /// one of them could lock out the other -- which is the defect M-02
    /// exists to fix, reintroduced one level down.
    #[test]
    fn different_clients_get_different_throttle_keys() {
        let a = ClientAddr::Proxied("203.0.113.7".parse().unwrap());
        let b = ClientAddr::Proxied("203.0.113.8".parse().unwrap());
        assert_ne!(a.throttle_key(), b.throttle_key());
    }
}
