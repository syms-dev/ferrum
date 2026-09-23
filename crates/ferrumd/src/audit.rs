// One line per security-relevant thing that happens, to the journal.
//
// Before this, none of it was recorded: not a login success, not a login
// failure, not a logout, not a settings write, not a secret write, not an
// apply or a rollback, and no client address anywhere in the crate. An
// operator asking "did somebody get in, and from where?" had nothing to read
// -- which is the question that matters most on the day it is asked, and the
// one you cannot answer retroactively.
//
// `eprintln!` rather than a logging framework, deliberately. ferrumd runs
// under systemd, which captures stderr into the journal with the unit,
// timestamp and boot id already attached; the crate logs this way in seven
// other places; and a framework would be a new dependency for no gain here.
//
// TWO RULES, and they are the whole of the security review this file needs.
//
// 1. A SECRET NEVER REACHES THIS FILE. No password, no secret value, no
//    session token, no CSRF token -- this project treats a secret in a log
//    as an auto-Critical finding. Note what the callers pass instead: the
//    secret-write path logs the NAME of the secret, never the body, and
//    nothing here takes a token at all. `SessionToken` exists as its own
//    type in main.rs partly so it is visible when one is being handled.
//
// 2. EVERY UNTRUSTED FIELD IS ESCAPED. The username on a login line is
//    whatever the caller put in the JSON body, and serde will happily hand
//    back a String containing a newline -- so an attacker could log in as
//    "x\nferrumd audit: event=login outcome=success" and write a second,
//    fabricated audit line. `{:?}` escapes it to \n inside quotes, which is
//    why every caller-influenced field below is formatted that way and not
//    with `{}`.
use crate::client_addr::ClientAddr;

/// Records one security-relevant event.
///
/// # Arguments
/// * `event` - the event name, a fixed identifier from the call site
///   (`login`, `logout`, `password-change`, `settings-write`,
///   `secret-write`, `job-dispatch`). Never caller-derived.
/// * `outcome` - `success`, `failure`, `denied`, or `error`.
/// * `user` - the account involved, or `None` where there is not one (an
///   unauthenticated login attempt for an unknown account still records the
///   name that was submitted, via `user`).
/// * `client` - where the request came from, and how confidently.
/// * `detail` - free-text context. Callers keep this to non-secret facts:
///   a job kind, a secret's name, a settings path.
pub fn record(event: &str, outcome: &str, user: &str, client: &ClientAddr, detail: &str) {
    eprintln!("{}", format_line(event, outcome, user, client, detail));
}

/// Builds the line `record` prints.
///
/// Split out for one reason: stderr is not capturable from a unit test here,
/// so the tests below would otherwise have to assert against their own copy
/// of the format string -- and a copy that drifts from the real one turns
/// the escaping proof in rule 2 into a test of nothing. With the formatting
/// here, the tests exercise the code that actually runs.
///
/// Arguments are as [`record`]; returns the formatted line without a
/// trailing newline.
fn format_line(event: &str, outcome: &str, user: &str, client: &ClientAddr, detail: &str) -> String {
    format!(
        "ferrumd audit: event={event} outcome={outcome} user={user:?} client={} \
         client_source={} detail={detail:?}",
        client.address(),
        client.source(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line's shape, so a caller reading the journal (or grepping it)
    /// can rely on the field names.
    #[test]
    fn the_line_names_every_field_it_promises() {
        let line = format_line("login", "success", "admin", &loopback(), "");
        for field in ["event=", "outcome=", "user=", "client=", "client_source=", "detail="] {
            assert!(line.contains(field), "missing {field} in: {line}");
        }
    }

    /// Rule 2, and the reason this file escapes at all. A username is
    /// whatever arrived in the JSON body; unescaped, a newline in it forges
    /// a second audit line and the log stops being evidence.
    #[test]
    fn a_username_cannot_forge_a_second_audit_line() {
        let forged = "x\nferrumd audit: event=login outcome=success user=\"root\"";
        let line = format_line("login", "failure", forged, &loopback(), "");
        assert!(
            !line.contains('\n'),
            "an audit line must stay one line no matter what the caller submitted: {line}"
        );
        assert!(line.contains("\\n"), "the newline must be escaped, not dropped: {line}");
    }

    /// The untrusted-detail half of the same rule.
    #[test]
    fn a_detail_field_cannot_forge_a_second_audit_line() {
        let line = format_line("secret-write", "success", "admin", &loopback(), "a\nb");
        assert!(!line.contains('\n'), "{line}");
    }

    #[test]
    fn a_proxied_client_is_labelled_as_proxied_and_a_direct_one_is_not() {
        let proxied = ClientAddr::Proxied("203.0.113.7".parse().unwrap());
        let line = format_line("login", "success", "admin", &proxied, "");
        assert!(line.contains("client=203.0.113.7"), "{line}");
        assert!(line.contains("client_source=x-real-ip"), "{line}");

        let line = format_line("login", "success", "admin", &loopback(), "");
        assert!(line.contains("client_source=peer"), "{line}");
    }

    /// An address that is not known must say so rather than print something
    /// that reads as authoritative.
    #[test]
    fn an_unknown_client_is_not_dressed_up_as_an_address() {
        let line = format_line("login", "failure", "admin", &ClientAddr::Unknown, "");
        assert!(line.contains("client=unknown"), "{line}");
        assert!(line.contains("client_source=none"), "{line}");
    }

    fn loopback() -> ClientAddr {
        ClientAddr::Direct("127.0.0.1".parse().unwrap())
    }

}
