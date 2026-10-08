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
// nginx's own view of the peer, so whatever a REMOTE caller sent under that
// name is overwritten and cannot survive. `X-Forwarded-For` is APPENDED to
// what the caller sent, so its left-hand entries are attacker-chosen. This
// file therefore uses X-Real-IP and deliberately never reads
// X-Forwarded-For.
//
// WHAT THE LOOPBACK CHECK DOES NOT PROVE (SEC-03).
//
// This file used to say that a loopback socket peer proved a request "came
// through nginx". It does not, and the claim was the defect. ferrumd binds
// an AF_INET loopback port and catalog apps run in no network namespace of
// their own, so ANY process on this host -- including a compromised sibling
// app, which the spec's own threat model enumerates -- can open
// 127.0.0.1:7788 and send whatever X-Real-IP it likes.
// modules/proxy/nginx.nix:170-178 already reaches exactly this conclusion
// for `Remote-User`; the same reasoning applies three files away and had
// not been carried across.
//
// There is no distinguisher available inside this crate. nginx and a local
// process present the identical socket peer, and every address in
// 127.0.0.0/8 is bindable by an unprivileged local process, so the peer
// cannot separate them even in principle. A shared secret that nginx sets
// and a sibling app cannot read would be a real distinguisher, but it lives
// in the proxy configuration, not here.
//
// So this file does two things instead, and neither pretends otherwise:
//
//   1. It reports the CLAIM as a claim. `source()` says
//      `x-real-ip-claimed`, and the audit line carries the real socket peer
//      beside it. An operator reading the journal sees what ferrumd knows
//      rather than what it hoped.
//
//   2. It gives the throttle a second axis the caller cannot choose.
//      `peer_key` folds the whole of 127.0.0.0/8 into ONE identity, because
//      "something on this box" is the finest distinction that is actually
//      true. A local caller rotating X-Real-IP to escape its own throttle
//      bucket cannot rotate out of that one -- see auth.rs's
//      distinct-claim rule, which turns the rotation itself into the
//      signal.
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

/// The one throttle identity every on-box caller shares.
///
/// Deliberately coarse. `127.0.0.0/8` is routed entirely to `lo`, so an
/// unprivileged local process can bind `127.0.0.2`, `127.0.0.3`, and so on
/// at will; keying anything on the specific loopback address would hand that
/// process a fresh bucket per connection. Folding the range into a single
/// identity is the honest statement of what ferrumd can tell apart: on-box
/// from off-box, and nothing finer.
const LOOPBACK_TRUST_DOMAIN: &str = "loopback";

/// A request's origin, carrying how it was determined.
///
/// The provenance is part of the value rather than dropped on the floor,
/// because a log line that prints an address without saying where the
/// address came from reads as authoritative whether or not it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientAddr {
    /// An `X-Real-IP` sent by an on-box caller.
    ///
    /// Both halves are kept. `claimed` is nginx's view of the remote client
    /// when nginx really is the sender -- useful, and the only way to tell
    /// two remote clients apart. `peer` is the socket peer, which is all
    /// ferrumd genuinely observed. The variant carries both so no caller has
    /// to choose between useful and true: the audit line prints both, and
    /// the throttle counts against both.
    Proxied { claimed: IpAddr, peer: IpAddr },
    /// The socket peer itself -- either an on-box caller that sent no usable
    /// `X-Real-IP`, or a request that reached ferrumd from off-box.
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
            if let Some(claimed) = headers
                .get(REAL_IP_HEADER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<IpAddr>().ok())
            {
                return ClientAddr::Proxied { claimed, peer: peer_ip };
            }
        }
        ClientAddr::Direct(peer_ip)
    }

    /// The address itself, for a log field.
    pub fn address(&self) -> String {
        match self {
            ClientAddr::Proxied { claimed, .. } => claimed.to_string(),
            ClientAddr::Direct(ip) => ip.to_string(),
            ClientAddr::Unknown => "unknown".to_string(),
        }
    }

    /// How `address` was determined, logged beside it so an operator reading
    /// the journal can tell a claimed address from an observed one rather
    /// than having to assume.
    ///
    /// `x-real-ip-claimed` rather than `x-real-ip`, because the suffix IS
    /// the finding: any local process can send that header, so the value is
    /// an assertion by its sender and the journal must not read as though
    /// ferrumd verified it.
    pub fn source(&self) -> &'static str {
        match self {
            ClientAddr::Proxied { .. } => "x-real-ip-claimed",
            ClientAddr::Direct(_) => "peer",
            ClientAddr::Unknown => "none",
        }
    }

    /// The socket peer ferrumd actually observed, for the audit line.
    ///
    /// Always printed beside `address`, including when the two are the same,
    /// so a claimed address never appears in the journal without the thing
    /// that would contradict it sitting next to it.
    pub fn peer(&self) -> String {
        match self {
            ClientAddr::Proxied { peer, .. } => peer.to_string(),
            ClientAddr::Direct(ip) => ip.to_string(),
            ClientAddr::Unknown => "none".to_string(),
        }
    }

    /// The key the login throttle counts against.
    ///
    /// Claim-derived on purpose: it is what keeps two remote clients in
    /// separate buckets, which is the whole of M-02's fix. It is therefore
    /// also rotatable by an on-box caller, which is why it is never the only
    /// axis -- see `peer_key`.
    ///
    /// Deliberately the same string for every `Unknown` caller. That case
    /// does not arise on a real host (there is always a socket), and making
    /// it one shared bucket keeps an unattributable request throttled
    /// rather than exempt.
    pub fn throttle_key(&self) -> String {
        format!("{}:{}", self.source(), self.address())
    }

    /// The trust domain the request arrived from, which the caller cannot
    /// choose.
    ///
    /// Every on-box peer collapses to one value (see
    /// `LOOPBACK_TRUST_DOMAIN`), so a local process gains nothing by binding
    /// a different `127.x` source address or by rewriting `X-Real-IP`. An
    /// off-box peer is its own domain, so the coarse key never lumps the
    /// whole internet into one bucket.
    pub fn peer_key(&self) -> String {
        match self {
            ClientAddr::Proxied { .. } => LOOPBACK_TRUST_DOMAIN.to_string(),
            ClientAddr::Direct(ip) if ip.is_loopback() => LOOPBACK_TRUST_DOMAIN.to_string(),
            ClientAddr::Direct(ip) => format!("peer:{ip}"),
            ClientAddr::Unknown => "none".to_string(),
        }
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
        assert_eq!(
            resolved,
            ClientAddr::Proxied {
                claimed: "203.0.113.7".parse().unwrap(),
                peer: "127.0.0.1".parse().unwrap(),
            }
        );
        assert_eq!(resolved.address(), "203.0.113.7");
        assert_eq!(resolved.source(), "x-real-ip-claimed");
    }

    /// SEC-03. The claim must never erase the thing that would contradict
    /// it: whatever `X-Real-IP` says, the socket peer is still recorded.
    #[test]
    fn a_proxied_client_still_carries_the_socket_peer_it_actually_came_from() {
        let resolved =
            ClientAddr::resolve(peer("127.0.0.1:53124"), &headers(&[("x-real-ip", "203.0.113.7")]));
        assert_eq!(resolved.address(), "203.0.113.7");
        assert_eq!(
            resolved.peer(),
            "127.0.0.1",
            "a claimed address must not replace the peer ferrumd really observed"
        );
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
        assert_eq!(resolved.peer(), "none");
    }

    /// Two different proxied clients must not share a throttle bucket, or
    /// one of them could lock out the other -- which is the defect M-02
    /// exists to fix, reintroduced one level down.
    #[test]
    fn different_clients_get_different_throttle_keys() {
        let a = ClientAddr::resolve(peer("127.0.0.1:1"), &headers(&[("x-real-ip", "203.0.113.7")]));
        let b = ClientAddr::resolve(peer("127.0.0.1:2"), &headers(&[("x-real-ip", "203.0.113.8")]));
        assert_ne!(a.throttle_key(), b.throttle_key());
    }

    /// SEC-03's unforgeable axis, at this level.
    ///
    /// Every route onto the box -- a different claimed address, a different
    /// loopback source address, no header at all -- resolves to the SAME
    /// peer key, because on-box versus off-box is the only distinction
    /// ferrumd can actually make. If this ever starts returning different
    /// values for these, auth.rs's distinct-claim rule stops binding and an
    /// on-box caller can rotate out of its own throttle again.
    #[test]
    fn every_on_box_caller_shares_one_peer_key_however_it_dresses_itself_up() {
        let rotated_claim =
            ClientAddr::resolve(peer("127.0.0.1:1"), &headers(&[("x-real-ip", "203.0.113.7")]));
        let other_claim =
            ClientAddr::resolve(peer("127.0.0.1:2"), &headers(&[("x-real-ip", "198.51.100.9")]));
        // 127.0.0.0/8 is routed entirely to lo, so an unprivileged process
        // can bind any of it: a different loopback source is not a different
        // caller.
        let rotated_peer =
            ClientAddr::resolve(peer("127.0.0.9:3"), &headers(&[("x-real-ip", "203.0.113.7")]));
        let no_header = ClientAddr::resolve(peer("127.0.0.5:4"), &headers(&[]));

        for other in [&other_claim, &rotated_peer, &no_header] {
            assert_eq!(
                rotated_claim.peer_key(),
                other.peer_key(),
                "an on-box caller must not be able to change its peer key: {other:?}"
            );
        }
    }

    /// The converse: an off-box caller is genuinely a distinct domain, so
    /// the coarse key does not lump the whole internet together.
    #[test]
    fn an_off_box_peer_is_its_own_trust_domain() {
        let remote = ClientAddr::Direct("198.51.100.4".parse().unwrap());
        let other_remote = ClientAddr::Direct("198.51.100.5".parse().unwrap());
        let local = ClientAddr::Direct("127.0.0.1".parse().unwrap());
        assert_ne!(remote.peer_key(), other_remote.peer_key());
        assert_ne!(remote.peer_key(), local.peer_key());
    }
}
