// The gate that stops an apply whose RESULTING generation would leave the
// operator with no way back into their own machine (ROAD-TO-PUBLIC 26).
//
// Why this is worth doing here and not where the switch is flipped. The
// idea is Silo's: refuse to turn off the last authentication method at the
// moment it is turned off. Silo can only check the instant a switch moves,
// because the switch IS the system's state. ferrum evaluates the whole
// configuration that is about to exist before any of it exists -- so the
// question "could anyone get in to the host this apply would produce?" can
// be asked while nothing has been built, nothing stopped, nothing
// snapshotted and rollback is still a no-op. That is a check only a
// declarative system can write.
//
// WHAT COUNTS AS A LOCKOUT, AND WHAT DELIBERATELY DOES NOT. A ferrum host
// has three documented ways in (README): the root console password, SSH
// (and through it the loopback tunnel to ferrumd), and the dashboard. Only
// the first two are routes this gate reasons about, and it refuses ONLY
// when BOTH are closed at once:
//
//   * The dashboard is not a rescue route and counting it would make this
//     gate wrong in both directions. It cannot restore SSH or a console
//     password -- those live in /etc/ferrum/custom/*.nix, which the
//     dashboard does not write -- and a dashboard that is merely broken
//     (Authelia will not start, a bad certificate) is the exact case the
//     SSH tunnel is documented as the answer to. A host whose dashboard is
//     down but whose SSH works is degraded, not locked out, and refusing
//     it would be a false positive.
//   * A closed console with working SSH is not a lockout, and a disabled
//     SSH with a working console password is not a lockout either. Each
//     alone is a legitimate, deliberate configuration.
//
// CLOSED IS NOT THE SAME AS UNKNOWN, and the pin gate's reasoning carries
// over unchanged: a predicate this check cannot evaluate has not failed.
// Every fact here comes from one `nix eval` of the resulting
// configuration, and if that evaluation does not happen, does not parse,
// or does not answer, the whole gate is `Unknown` and the apply proceeds.
// Within it, each route reports `Open`, `Closed` or `Unknown`
// individually, and only two `Closed` verdicts together refuse. A firewall
// carrying hand-written rules this code cannot read, an
// `AuthorizedKeysCommand` that could hand sshd a key from anywhere, an
// authorized-keys file that could not be read -- all are `Unknown`, which
// proceeds.
//
// PASSABLE, DELIBERATELY. Same shape as `pin_gate`, for the same reason:
// the job is to make the decision visible, not impossible. An operator who
// means it acknowledges the refusal's token and the identical apply runs.
// The token names WHICH routes were found closed, so an acknowledgement
// given for "SSH is disabled" does not silently pass a later, different
// lockout -- exactly as `accept_pin_change` names a revision so it cannot
// outlive the revision it was given for.
//
// The decision is a pure function of a value, so the whole of it is
// exercised below without a flake, a host, or a nix on PATH.
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The attribute-set-producing function handed to `nix eval --apply`.
///
/// Reads the FINAL, merged configuration -- so `services.openssh.openFirewall`
/// has already contributed its ports to `networking.firewall.allowedTCPPorts`
/// and a `custom/` module's `mkForce` has already won or lost. Reading the
/// merged answer rather than any one module's intent is the whole advantage
/// of asking the question here.
///
/// Options that always exist in NixOS (`services.openssh.enable`,
/// `networking.firewall.enable`, `users.mutableUsers`) are read WITHOUT an
/// `or` fallback on purpose: if one of them is missing, this is not a host
/// shape this check understands, and an evaluation error becomes `Unknown`,
/// which proceeds. A fallback would instead manufacture a confident answer
/// out of an absence.
const EVAL_APPLY: &str = r#"c:
let
  o = c.services.openssh;
  s = o.settings or {};
  fw = c.networking.firewall;
  nft = c.networking.nftables or {};
  str = v: if v == null then "" else toString v;
  # `toString` on a shell PACKAGE yields the store directory
  # (`/nix/store/...-shadow-4.18.0`), not the interpreter -- which is what
  # a first version of this did, so every system user looked like it had a
  # login shell called "shadow-4.18.0". NixOS resolves the real path by
  # appending the package's own `shellPath`, and so does this.
  shellOf = u:
    let sh = u.shell or null;
    in if sh == null then ""
       else if builtins.isAttrs sh && (sh ? shellPath) then (toString sh) + sh.shellPath
       else toString sh;
  # `networking.firewall.extraCommands` is NOT empty on a stock NixOS host:
  # nixpkgs' own nat module appends a block of teardown `-D`/`-F`/`-X`
  # commands for the nixos-nat-* and nixos-filter-forward chains to it.
  # Treating "extraCommands is non-empty" as "rules this check cannot read"
  # -- which a first version of this did -- therefore made the firewall arm
  # permanently unknown on EVERY host, which is a dead predicate dressed as
  # a careful one. What actually matters is whether the hand-written rules
  # could ADMIT traffic: `ACCEPT` is iptables' only verb for that, and
  # `nixos-fw` is the input chain whose contents the allow lists describe,
  # so a rule touching either could contradict them. The nat teardown block
  # names neither.
  flatten = v: builtins.replaceStrings [ "\n" ] [ " " ] (str v);
  couldAdmit = v: (builtins.match ".*(ACCEPT|nixos-fw).*" (flatten v)) != null;
  pwOf = u:
    let
      cand = builtins.filter (v: v != null) [
        (u.hashedPassword or null)
        (u.hashedPasswordFile or null)
        (u.initialHashedPassword or null)
        (u.initialPassword or null)
        (u.password or null)
      ];
    in if cand == [ ] then null else str (builtins.head cand);
in {
  mutableUsers = c.users.mutableUsers;
  sshEnabled = o.enable;
  sshPorts = o.ports or [ ];
  permitRootLogin = str (s.PermitRootLogin or "prohibit-password");
  passwordAuthentication = s.PasswordAuthentication or true;
  authorizedKeysCommand = str (o.authorizedKeysCommand or "none");
  authorizedKeysFiles = map str (o.authorizedKeysFiles or [ ]);
  firewallEnabled = fw.enable;
  allowedTcpPorts = fw.allowedTCPPorts or [ ];
  allowedTcpPortRanges = fw.allowedTCPPortRanges or [ ];
  firewallOpaque =
    couldAdmit (fw.extraCommands or "")
    || (str (fw.extraInputRules or "")) != ""
    || (str (nft.ruleset or "")) != ""
    || (builtins.attrNames (nft.tables or { })) != [ ];
  users = map (u: {
    name = u.name;
    home = str (u.home or "");
    shell = shellOf u;
    password = pwOf u;
    keys = u.openssh.authorizedKeys.keys or [ ];
    keyFiles = map str (u.openssh.authorizedKeys.keyFiles or [ ]);
  }) (builtins.attrValues c.users.users);
}"#;

/// One user, as the resulting generation describes them.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// The login name.
    pub name: String,
    /// The home directory, or `""` when the configuration names none.
    pub home: String,
    /// The login shell's path, or `""`.
    pub shell: String,
    /// The first password-ish field the configuration sets, as a string, or
    /// `None` when it sets none of them.
    pub password: Option<String>,
    /// `users.users.<name>.openssh.authorizedKeys.keys`.
    pub keys: Vec<String>,
    /// `users.users.<name>.openssh.authorizedKeys.keyFiles`, as paths.
    pub key_files: Vec<String>,
    /// Whether a file sshd would actually read already holds a key on THIS
    /// machine, filled in by `read_live_keys` rather than by nix: a key
    /// added at runtime with `ssh-copy-id` is a real way in that no
    /// configuration describes. `None` means it could not be determined,
    /// which is never a reason to refuse.
    #[serde(skip)]
    pub live_keys: Option<bool>,
}

/// An inclusive TCP port range from `networking.firewall.allowedTCPPortRanges`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct PortRange {
    /// The first port in the range.
    pub from: u16,
    /// The last port in the range, inclusive.
    pub to: u16,
}

/// Everything about the resulting generation this gate reasons over.
///
/// One struct, filled by one evaluation: either the whole picture is
/// available or none of it is. A per-field "unknown" would let the gate
/// compose a refusal out of facts that came from different places and
/// different moments.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Facts {
    /// `users.mutableUsers`. False means activation rewrites the shadow
    /// file from the configuration, so a password set at the console does
    /// not survive the next apply.
    pub mutable_users: bool,
    /// `services.openssh.enable`.
    pub ssh_enabled: bool,
    /// `services.openssh.ports`.
    pub ssh_ports: Vec<u16>,
    /// `services.openssh.settings.PermitRootLogin`.
    pub permit_root_login: String,
    /// `services.openssh.settings.PasswordAuthentication`.
    pub password_authentication: bool,
    /// `services.openssh.authorizedKeysCommand`, `"none"` when unset.
    pub authorized_keys_command: String,
    /// `services.openssh.authorizedKeysFiles` -- the patterns sshd expands
    /// per user. Read from the configuration rather than hardcoded so this
    /// check looks exactly where the host's own sshd will look.
    pub authorized_keys_files: Vec<String>,
    /// `networking.firewall.enable`.
    pub firewall_enabled: bool,
    /// `networking.firewall.allowedTCPPorts`, already including whatever
    /// `services.openssh.openFirewall` contributed.
    pub allowed_tcp_ports: Vec<u16>,
    /// `networking.firewall.allowedTCPPortRanges`.
    pub allowed_tcp_port_ranges: Vec<PortRange>,
    /// True when the firewall carries hand-written rules (`extraCommands`,
    /// `extraInputRules`, an nftables ruleset) that could open or close a
    /// port this check cannot see. It makes a "blocked" verdict `Unknown`;
    /// it never makes an open port closed.
    pub firewall_opaque: bool,
    /// Every user the resulting generation declares.
    pub users: Vec<User>,
}

/// Why one route is shut, in the three forms the refusal needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closure {
    /// A stable token naming this closure. Joined into the refusal's
    /// acknowledgement, so an acknowledgement is bound to the specific
    /// lockout it was given for.
    pub code: &'static str,
    /// What is shut, for the operator.
    pub why: String,
    /// The smallest change that would reopen it.
    pub reopen: String,
}

/// Whether one way into the host survives the resulting generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Usable. Nothing to say.
    Open,
    /// Provably shut, by a predicate read off the resulting configuration.
    Closed(Closure),
    /// Not determinable, with the reason. Never contributes to a refusal --
    /// a predicate that could not be evaluated has not failed.
    Unknown(String),
}

/// What an apply should do about the routes it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Build and switch.
    Proceed,
    /// Refuse before anything is built, with the operator-facing text.
    Refuse(Refusal),
}

/// A refusal, with the token an acknowledgement would have to name.
///
/// Two fields rather than one string, for the reason `pin_gate::Refusal`
/// has two: `message` is prose for a person and `accept_token` is the exact
/// value a retry must carry, and formatting them together would make the
/// UI parse prose to find the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The closed routes' codes, joined with `+` in a fixed order. An
    /// acknowledgement of THIS value passes; an acknowledgement of a
    /// different lockout does not.
    pub accept_token: String,
    /// What the operator is told.
    pub message: String,
}

/// Whether a password field the configuration sets would actually let
/// someone log in.
///
/// # Arguments
/// * `password` - the field as the configuration sets it, or `None`.
///
/// # Returns
/// False when nothing is set and when the value is one of shadow(5)'s lock
/// markers (`!`, `!!`, `*`, or any `!`-prefixed hash), which are precisely
/// how an account is spelled "this password matches nothing". True
/// otherwise -- including for the empty string, which means "log in with no
/// password at all" and is a way in, not the absence of one.
fn usable_password(password: Option<&str>) -> bool {
    let Some(p) = password else { return false };
    !(p == "*" || p.starts_with('!'))
}

/// Whether a shell would give someone who authenticated an actual session.
///
/// # Arguments
/// * `shell` - the shell's path, possibly a store path, possibly empty.
///
/// # Returns
/// True when the shell is `nologin` or `false`, the two spellings NixOS
/// uses for an account that may exist but may not be logged into.
fn shell_refuses_login(shell: &str) -> bool {
    let name = Path::new(shell).file_name().and_then(|n| n.to_str()).unwrap_or("");
    name == "nologin" || name == "false"
}

/// Whether sshd would accept a PUBLIC KEY for this user.
///
/// # Arguments
/// * `user` - the user.
/// * `facts` - the resulting configuration.
///
/// # Returns
/// True for any non-root user, and for root only under a `PermitRootLogin`
/// that permits a key AND yields a shell. `forced-commands-only` is
/// deliberately false: it authenticates, but it runs the command the key
/// names and nothing else, which is not a way back into a broken machine.
fn key_login_permitted(user: &User, facts: &Facts) -> bool {
    if user.name != "root" {
        return true;
    }
    matches!(facts.permit_root_login.as_str(), "yes" | "prohibit-password" | "without-password")
}

/// Whether sshd would accept a PASSWORD for this user.
///
/// # Arguments
/// * `user` - the user.
/// * `facts` - the resulting configuration.
///
/// # Returns
/// True when `PasswordAuthentication` is on and, for root, only under
/// `PermitRootLogin = "yes"` -- every other setting refuses root's password
/// specifically.
fn password_login_permitted(user: &User, facts: &Facts) -> bool {
    facts.password_authentication && (user.name != "root" || facts.permit_root_login == "yes")
}

/// Can anyone reach a shell on this host over the console?
///
/// # Arguments
/// * `facts` - the resulting configuration.
///
/// # Returns
/// `Open` when root carries a usable password in the resulting
/// configuration, and `Open` when `users.mutableUsers` is true -- because
/// then a password set at runtime SURVIVES activation, and `ferrum-apply`
/// itself guarantees one exists (`secrets::ensure_root_password` gives root
/// a random console password on any apply where `passwd -S root` says it
/// has none, and writes it once to
/// `/var/lib/ferrum/root-console-password`).
///
/// `Closed` only for the conjunction that is genuinely fatal: immutable
/// users AND no declared root password. That combination is the real
/// incident `checks.a-host-always-has-a-way-in` was written for -- a
/// machine that reached `ferrum login:` and accepted nothing -- and this is
/// the same property asked about the generation that is about to exist
/// rather than about an example host at build time.
pub fn console_route(facts: &Facts) -> Route {
    let Some(root) = facts.users.iter().find(|u| u.name == "root") else {
        return Route::Unknown(
            "the resulting configuration describes no root user, so this check cannot say \
             whether the console would accept one"
                .to_string(),
        );
    };
    if usable_password(root.password.as_deref()) || facts.mutable_users {
        return Route::Open;
    }
    Route::Closed(Closure {
        code: "console-locked",
        why: "the console would accept nobody: the resulting configuration sets no password \
              for root, and users.mutableUsers is false, so the password ferrum-apply writes \
              to /var/lib/ferrum/root-console-password would be erased by this activation"
            .to_string(),
        reopen: "Set users.users.root.hashedPassword (or hashedPasswordFile) in \
                 /etc/ferrum/custom/, or leave users.mutableUsers at its default of true."
            .to_string(),
    })
}

/// Would sshd be listening on a port the operator could reach?
///
/// Split from `ssh_route` because it is the one part with a real third
/// answer: a firewall carrying hand-written rules can open a port that is
/// in no `allowedTCPPorts` list, so "the port is not listed" is only a
/// closure when there are no such rules.
///
/// # Arguments
/// * `facts` - the resulting configuration.
///
/// # Returns
/// `Open` with no firewall or with any sshd port allowed, `Unknown` when
/// sshd names no port at all or when hand-written rules could contradict
/// the lists, `Closed` otherwise.
fn ssh_port_route(facts: &Facts) -> Route {
    if !facts.firewall_enabled {
        return Route::Open;
    }
    if facts.ssh_ports.is_empty() {
        return Route::Unknown(
            "the resulting configuration names no sshd port, so this check cannot say whether \
             the firewall would admit one"
                .to_string(),
        );
    }
    let allowed = |port: &u16| {
        facts.allowed_tcp_ports.contains(port)
            || facts.allowed_tcp_port_ranges.iter().any(|r| r.from <= *port && *port <= r.to)
    };
    if facts.ssh_ports.iter().any(allowed) {
        return Route::Open;
    }
    if facts.firewall_opaque {
        return Route::Unknown(
            "no sshd port is in the firewall's allow lists, but the firewall also carries \
             hand-written rules this check cannot read, which could admit one"
                .to_string(),
        );
    }
    let ports: Vec<String> = facts.ssh_ports.iter().map(u16::to_string).collect();
    Route::Closed(Closure {
        code: "ssh-firewalled",
        why: format!(
            "the firewall would admit nothing on sshd's port{} ({}): \
             networking.firewall.enable is true and no allowedTCPPorts entry or port range \
             covers {}",
            if ports.len() == 1 { "" } else { "s" },
            ports.join(", "),
            if ports.len() == 1 { "it" } else { "any of them" },
        ),
        reopen: format!(
            "Add {} to networking.firewall.allowedTCPPorts in /etc/ferrum/custom/, or set \
             services.openssh.openFirewall = true.",
            ports.join(" and "),
        ),
    })
}

/// Would sshd accept anybody's credential?
///
/// # Arguments
/// * `facts` - the resulting configuration.
///
/// # Returns
/// `Open` as soon as one user is found who could authenticate and reach a
/// shell. `Unknown` when the answer depends on something this check cannot
/// read -- an `AuthorizedKeysCommand` (which can produce a key from
/// anywhere), an empty `authorizedKeysFiles` list (far more likely a
/// reading failure than a host whose sshd consults no key file), or a
/// user whose on-disk key files could not be examined. `Closed` only when
/// every user was examined and none of them has either route.
fn ssh_credential_route(facts: &Facts) -> Route {
    if facts.authorized_keys_command != "none" {
        return Route::Unknown(format!(
            "sshd is configured with an AuthorizedKeysCommand ({}), which can supply a key this \
             check cannot see",
            facts.authorized_keys_command,
        ));
    }
    if facts.authorized_keys_files.is_empty() {
        return Route::Unknown(
            "the resulting configuration lists no services.openssh.authorizedKeysFiles \
             patterns, so this check does not know where sshd would look for a key"
                .to_string(),
        );
    }
    let mut undetermined: Option<String> = None;
    for user in &facts.users {
        if shell_refuses_login(&user.shell) {
            continue;
        }
        if key_login_permitted(user, facts) {
            if !user.keys.is_empty() || !user.key_files.is_empty() {
                return Route::Open;
            }
            match user.live_keys {
                Some(true) => return Route::Open,
                Some(false) => {}
                None => {
                    undetermined.get_or_insert_with(|| {
                        format!(
                            "the files sshd would read for {}'s authorized keys could not be \
                             examined, so this check cannot say whether a key is already there",
                            user.name,
                        )
                    });
                }
            }
        }
        if password_login_permitted(user, facts) && usable_password(user.password.as_deref()) {
            return Route::Open;
        }
    }
    if let Some(why) = undetermined {
        return Route::Unknown(why);
    }
    Route::Closed(Closure {
        code: "ssh-no-credential",
        why: format!(
            "sshd would accept nobody: no account that can reach a shell has an authorized key \
             (declared or already on disk), and password authentication is {} \
             (PermitRootLogin = {})",
            if facts.password_authentication { "on but no such account has a password" } else { "off" },
            facts.permit_root_login,
        ),
        reopen: "Put your public key in users.users.root.openssh.authorizedKeys.keys in \
                 /etc/ferrum/custom/, or give an account that can log in a password."
            .to_string(),
    })
}

/// Can anyone reach a shell on this host over SSH?
///
/// The three predicates are checked in the order that makes the refusal
/// name the most specific true thing: a host with sshd switched off is told
/// that, not that its firewall blocks a port no daemon is listening on.
///
/// # Arguments
/// * `facts` - the resulting configuration.
///
/// # Returns
/// `Closed` with the first predicate that is provably shut, otherwise the
/// first `Unknown` encountered, otherwise `Open`.
pub fn ssh_route(facts: &Facts) -> Route {
    if !facts.ssh_enabled {
        return Route::Closed(Closure {
            code: "ssh-disabled",
            why: "sshd would not run at all: services.openssh.enable is false in the resulting \
                  configuration"
                .to_string(),
            reopen: "Remove the services.openssh.enable = false from /etc/ferrum/custom/."
                .to_string(),
        });
    }
    match ssh_port_route(facts) {
        Route::Open => {}
        other => return other,
    }
    ssh_credential_route(facts)
}

/// Decide whether an apply may proceed.
///
/// # Arguments
/// * `facts` - the resulting generation's relevant configuration, or `None`
///   when it could not be evaluated at all.
/// * `accepted` - the token the operator acknowledged on this attempt, from
///   the request file. Compared for EQUALITY against the token this
///   refusal would issue and used for nothing else, so a hostile value can
///   only fail to match.
///
/// # Returns
/// `Refuse` only when the console route AND the SSH route are both
/// provably closed and the operator has not acknowledged that exact pair.
/// Everything else -- either route open, either route unknown, no facts at
/// all -- proceeds.
pub fn decide(facts: Option<&Facts>, accepted: Option<&str>) -> Decision {
    let Some(facts) = facts else { return Decision::Proceed };
    let (Route::Closed(console), Route::Closed(ssh)) = (console_route(facts), ssh_route(facts))
    else {
        return Decision::Proceed;
    };

    let accept_token = format!("{}+{}", console.code, ssh.code);
    if accepted == Some(accept_token.as_str()) {
        return Decision::Proceed;
    }
    Decision::Refuse(Refusal {
        message: format!(
            "this apply would leave no way back into this machine. {}. And {}. Nothing has been \
             built and nothing has changed -- this host is still running the generation it was. \
             {} {} Or apply again accepting this exact lockout, if you have another way in that \
             ferrum cannot see.",
            console.why, ssh.why, console.reopen, ssh.reopen,
        ),
        accept_token,
    })
}

/// The argv for the one `nix eval` this gate runs.
///
/// A function returning a value rather than a `Command` built inline, for
/// the reason `update_deltas::candidate_eval_argv` is one: the flags are
/// the entire guarantee that asking this question changes nothing, so they
/// are asserted in a test rather than read in a review.
///
/// `--impure` is required for the same reason `apply::run`'s own build
/// needs it (see its comment): `sops.secrets.<name>.sopsFile` is a Nix path
/// pointing outside any flake's hermetic source, and the identical eval
/// fails without it. Using a different purity here than the build uses
/// would mean this gate evaluated a configuration the apply could not
/// build, or the reverse.
///
/// `--no-write-lock-file` is what makes this read-only: `nix eval` against
/// a local-path flake will otherwise write `flake.lock`, and a preflight
/// check that modifies the pin it is asked about would be a defect of
/// exactly the kind `pin_gate` exists to catch.
///
/// # Arguments
/// * `flake_ref` - the reference the apply would build.
///
/// # Returns
/// The argv after `nix`.
pub fn eval_argv(flake_ref: &str) -> Vec<String> {
    let (flake_dir, config_attr) = crate::update_check::split_flake_ref(flake_ref);
    vec![
        "eval".to_string(),
        "--json".to_string(),
        "--impure".to_string(),
        "--no-write-lock-file".to_string(),
        format!("{flake_dir}#{config_attr}"),
        "--apply".to_string(),
        EVAL_APPLY.to_string(),
    ]
}

/// Where sshd would look for one user's authorized keys, for one pattern.
///
/// # Arguments
/// * `pattern` - one `services.openssh.authorizedKeysFiles` entry.
/// * `name` - the user's login name, for `%u`.
/// * `home` - the user's home directory, for `%h` and for resolving a
///   relative pattern.
///
/// # Returns
/// The absolute path, or `None` when the pattern carries a `%` token this
/// check does not understand or is relative with no home to resolve it
/// against. `None` is what makes the whole credential verdict `Unknown`
/// rather than letting an unexpanded pattern read as "no key here".
fn expand_key_path(pattern: &str, name: &str, home: &str) -> Option<PathBuf> {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('u') => out.push_str(name),
            Some('h') => out.push_str(home),
            Some('%') => out.push('%'),
            _ => return None,
        }
    }
    let path = Path::new(&out);
    if path.is_absolute() {
        Some(path.to_path_buf())
    } else if home.is_empty() {
        None
    } else {
        Some(Path::new(home).join(path))
    }
}

/// Whether a file holds at least one authorized key.
///
/// # Arguments
/// * `contents` - the file's text.
///
/// # Returns
/// True when any line is neither blank nor a comment. Separated from the
/// read so the parsing is testable without a filesystem.
fn holds_a_key(contents: &str) -> bool {
    contents.lines().any(|l| {
        let l = l.trim();
        !l.is_empty() && !l.starts_with('#')
    })
}

/// Fill in each user's `live_keys` from the files sshd would actually read.
///
/// A key added with `ssh-copy-id` is a real way in that no configuration
/// describes, so declaring SSH closed without looking for one would be a
/// false positive on any host whose operator did that. This runs on the
/// machine the apply is about, so the files are right there.
///
/// # Arguments
/// * `facts` - the evaluated configuration, mutated in place.
///
/// # Returns
/// Nothing. A user whose files could not all be resolved and read is left
/// `None`, which proceeds.
pub fn read_live_keys(facts: &mut Facts) {
    let patterns = facts.authorized_keys_files.clone();
    for user in &mut facts.users {
        user.live_keys = live_keys_for(user, &patterns, |p: &Path| std::fs::read_to_string(p));
    }
}

/// `read_live_keys` for one user, with the read injected.
///
/// # Arguments
/// * `user` - the user.
/// * `patterns` - `services.openssh.authorizedKeysFiles`.
/// * `read` - reads a file, as `std::fs::read_to_string` does. A
///   `NotFound` error means "no key here"; any other error means this check
///   could not look, which is not the same answer.
///
/// # Returns
/// `Some(true)` on the first file holding a key, `Some(false)` when every
/// pattern resolved and no file held one, `None` when any pattern could not
/// be resolved or any file could not be read for a reason other than its
/// absence.
fn live_keys_for(
    user: &User,
    patterns: &[String],
    read: impl Fn(&Path) -> std::io::Result<String>,
) -> Option<bool> {
    for pattern in patterns {
        let path = expand_key_path(pattern, &user.name, &user.home)?;
        match read(&path) {
            Ok(contents) if holds_a_key(&contents) => return Some(true),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    Some(false)
}

/// Evaluate the resulting generation's way-in facts.
///
/// # Arguments
/// * `flake_ref` - the reference the apply would build.
///
/// # Returns
/// The facts, or `None` when `nix` could not be run, the evaluation failed,
/// or its output was not the document this check expects. Every one of
/// those is an UNKNOWN, not a finding: `decide(None, _)` proceeds. Failing
/// an apply because a read-only probe could not run would be a far worse
/// outcome than this gate not firing.
pub fn evaluate(flake_ref: &str) -> Option<Facts> {
    let output = std::process::Command::new("nix").args(eval_argv(flake_ref)).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let mut facts: Facts = serde_json::from_slice(&output.stdout).ok()?;
    read_live_keys(&mut facts);
    Some(facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host shaped like `examples/hosts/template`: sshd on, root's key
    /// declared, passwords off, console password generated at runtime
    /// because `mutableUsers` is NixOS's default true.
    fn healthy() -> Facts {
        Facts {
            mutable_users: true,
            ssh_enabled: true,
            ssh_ports: vec![22],
            permit_root_login: "prohibit-password".to_string(),
            password_authentication: false,
            authorized_keys_command: "none".to_string(),
            authorized_keys_files: vec![
                ".ssh/authorized_keys".to_string(),
                "/etc/ssh/authorized_keys.d/%u".to_string(),
            ],
            firewall_enabled: true,
            allowed_tcp_ports: vec![22, 80, 443],
            allowed_tcp_port_ranges: vec![],
            firewall_opaque: false,
            users: vec![
                User {
                    name: "root".to_string(),
                    home: "/root".to_string(),
                    shell: "/run/current-system/sw/bin/bash".to_string(),
                    password: None,
                    keys: vec!["ssh-ed25519 AAAA operator".to_string()],
                    key_files: vec![],
                    live_keys: Some(false),
                },
                User {
                    name: "nginx".to_string(),
                    home: "/var/empty".to_string(),
                    shell: "/run/current-system/sw/bin/nologin".to_string(),
                    password: None,
                    keys: vec![],
                    key_files: vec![],
                    live_keys: Some(false),
                },
            ],
        }
    }

    /// The configuration this gate exists for: immutable users with no
    /// declared root password (so the console accepts nothing after
    /// activation) AND sshd switched off. Neither half alone is a lockout;
    /// together there is no way back in.
    fn locked_out() -> Facts {
        let mut f = healthy();
        f.mutable_users = false;
        f.ssh_enabled = false;
        f
    }

    #[test]
    fn a_healthy_host_has_both_routes_open() {
        let f = healthy();
        assert_eq!(console_route(&f), Route::Open);
        assert_eq!(ssh_route(&f), Route::Open);
        assert_eq!(decide(Some(&f), None), Decision::Proceed);
    }

    /// The RED case, stated as the gate's whole purpose: a configuration
    /// from which there is genuinely no way back in is refused, before
    /// anything is built, and the refusal names BOTH closed routes and what
    /// would reopen each.
    #[test]
    fn a_genuinely_locked_out_configuration_is_refused() {
        let Decision::Refuse(refusal) = decide(Some(&locked_out()), None) else {
            panic!("a configuration with no way back in must be refused");
        };
        assert_eq!(refusal.accept_token, "console-locked+ssh-disabled");
        assert!(
            refusal.message.contains("no way back into this machine"),
            "{}",
            refusal.message
        );
        assert!(refusal.message.contains("users.mutableUsers"), "names the console closure: {}", refusal.message);
        assert!(
            refusal.message.contains("services.openssh.enable is false"),
            "names the SSH closure: {}",
            refusal.message
        );
        assert!(
            refusal.message.contains("hashedPassword"),
            "says what would reopen the console: {}",
            refusal.message
        );
        assert!(
            refusal.message.contains("Nothing has been built"),
            "the operator must know this cost them nothing: {}",
            refusal.message
        );
    }

    /// The anti-vacuity half, and the one that decides whether this gate is
    /// usable at all: every configuration that is merely DEGRADED proceeds
    /// in silence. A gate that fires on everything is as broken as one that
    /// fires on nothing, and this one sits in front of every apply.
    #[test]
    fn nothing_but_a_real_lockout_is_gated() {
        let locked_console = || {
            let mut f = healthy();
            f.mutable_users = false;
            f
        };
        for (label, facts) in [
            ("the template host", healthy()),
            // Each single closed route, with the other open.
            ("sshd off but the console password survives", {
                let mut f = healthy();
                f.ssh_enabled = false;
                f
            }),
            ("the console locked but SSH works", locked_console()),
            ("the console locked but the port is open and a key is declared", {
                let mut f = locked_console();
                f.ssh_ports = vec![2222];
                f.allowed_tcp_ports = vec![2222];
                f
            }),
            // The console locked, but root has a declared password after
            // all -- which is exactly what an operator who sets
            // mutableUsers = false is expected to do.
            ("immutable users WITH a declared root password", {
                let mut f = locked_out();
                f.users[0].password = Some("$6$real$hash".to_string());
                f
            }),
            // The console locked and sshd's declared key gone, but a key
            // the operator added by hand is sitting on disk.
            ("no declared key but a live authorized_keys on disk", {
                let mut f = locked_out();
                f.ssh_enabled = true;
                f.users[0].keys = vec![];
                f.users[0].live_keys = Some(true);
                f
            }),
            // Password authentication reaching a non-root account that can
            // actually get a shell.
            ("a non-root account that can log in with a password", {
                let mut f = locked_out();
                f.ssh_enabled = true;
                f.users[0].keys = vec![];
                f.password_authentication = true;
                f.users.push(User {
                    name: "operator".to_string(),
                    home: "/home/operator".to_string(),
                    shell: "/run/current-system/sw/bin/bash".to_string(),
                    password: Some("$6$x$y".to_string()),
                    keys: vec![],
                    key_files: vec![],
                    live_keys: Some(false),
                });
                f
            }),
        ] {
            assert_eq!(
                decide(Some(&facts), None),
                Decision::Proceed,
                "{label} must not gate an apply"
            );
        }
    }

    /// The dashboard, named explicitly because it is the case most likely
    /// to be mistaken for a lockout. Authelia broken, the proxy down, the
    /// certificate wrong -- none of it is visible here and none of it
    /// matters while SSH answers, because the SSH tunnel to ferrumd on
    /// loopback is the documented answer to exactly that failure.
    #[test]
    fn a_broken_dashboard_is_not_a_lockout() {
        let mut f = healthy();
        // The console locked, so SSH is the ONLY route left -- and then
        // nothing but 22 reachable: no 80, no 443, so the published
        // dashboard is unreachable from anywhere and Authelia could be in
        // any state at all. The apply still proceeds.
        f.mutable_users = false;
        f.allowed_tcp_ports = vec![22];
        assert!(matches!(console_route(&f), Route::Closed(_)));
        assert_eq!(ssh_route(&f), Route::Open);
        assert_eq!(decide(Some(&f), None), Decision::Proceed);
    }

    /// The firewall arm, which is a real lockout on its own terms: sshd
    /// runs and would accept the operator's key, but nothing can reach it.
    #[test]
    fn a_firewalled_ssh_port_closes_the_ssh_route() {
        let mut f = locked_out();
        f.ssh_enabled = true;
        f.ssh_ports = vec![2222];
        f.allowed_tcp_ports = vec![80, 443];
        let Decision::Refuse(refusal) = decide(Some(&f), None) else {
            panic!("a port nothing can reach closes the SSH route");
        };
        assert_eq!(refusal.accept_token, "console-locked+ssh-firewalled");
        assert!(refusal.message.contains("2222"), "names the port: {}", refusal.message);
        assert!(
            refusal.message.contains("openFirewall"),
            "says what would reopen it: {}",
            refusal.message
        );
    }

    /// The credential arm: sshd runs, the port is open, and nobody can
    /// authenticate. This is Silo's own case -- the last authentication
    /// method being switched off -- asked of the generation about to exist.
    #[test]
    fn an_ssh_daemon_nobody_can_authenticate_to_closes_the_ssh_route() {
        let mut f = locked_out();
        f.ssh_enabled = true;
        f.users[0].keys = vec![];
        let Decision::Refuse(refusal) = decide(Some(&f), None) else {
            panic!("an sshd that would accept nobody closes the SSH route");
        };
        assert_eq!(refusal.accept_token, "console-locked+ssh-no-credential");
        assert!(
            refusal.message.contains("authorizedKeys"),
            "says what would reopen it: {}",
            refusal.message
        );
    }

    /// `PermitRootLogin = "no"` with root as the only account that has a
    /// key is the same closure by a different route, and the one an
    /// operator hardening their host is most likely to reach for.
    #[test]
    fn permit_root_login_no_closes_the_route_when_root_is_the_only_key_holder() {
        let mut f = locked_out();
        f.ssh_enabled = true;
        f.permit_root_login = "no".to_string();
        assert!(matches!(ssh_route(&f), Route::Closed(c) if c.code == "ssh-no-credential"));
        // ...and `forced-commands-only` too: it authenticates but it never
        // yields a session, which is not a way back into a broken machine.
        f.permit_root_login = "forced-commands-only".to_string();
        assert!(matches!(ssh_route(&f), Route::Closed(c) if c.code == "ssh-no-credential"));
    }

    /// Closed is not unknown. Each of these would be a refusal if the check
    /// guessed, and each must proceed instead.
    #[test]
    fn an_undeterminable_predicate_never_refuses() {
        for (label, facts) in [
            // No facts at all -- nix missing, eval failed, output unparsable.
            ("no evaluation at all", None),
            // The firewall carries rules this check cannot read, so "not in
            // the allow list" does not mean "unreachable".
            ("hand-written firewall rules", {
                let mut f = locked_out();
                f.ssh_enabled = true;
                f.ssh_ports = vec![2222];
                f.allowed_tcp_ports = vec![];
                f.firewall_opaque = true;
                Some(f)
            }),
            // sshd can be handed a key from anywhere.
            ("an AuthorizedKeysCommand", {
                let mut f = locked_out();
                f.ssh_enabled = true;
                f.users[0].keys = vec![];
                f.authorized_keys_command = "/run/current-system/sw/bin/fetch-keys".to_string();
                Some(f)
            }),
            // The files sshd reads could not be examined.
            ("unreadable authorized-keys files", {
                let mut f = locked_out();
                f.ssh_enabled = true;
                f.users[0].keys = vec![];
                f.users[0].live_keys = None;
                Some(f)
            }),
            // No patterns to look at -- far likelier a reading failure than
            // a real sshd that consults no key file.
            ("no authorizedKeysFiles patterns", {
                let mut f = locked_out();
                f.ssh_enabled = true;
                f.users[0].keys = vec![];
                f.authorized_keys_files = vec![];
                Some(f)
            }),
            // sshd names no port, so the firewall lists answer nothing.
            ("no sshd port", {
                let mut f = locked_out();
                f.ssh_enabled = true;
                f.ssh_ports = vec![];
                Some(f)
            }),
            // No root user in the document at all.
            ("no root user", {
                let mut f = locked_out();
                f.users.retain(|u| u.name != "root");
                Some(f)
            }),
        ] {
            assert_eq!(
                decide(facts.as_ref(), None),
                Decision::Proceed,
                "{label} is unknown, not closed, and must not gate an apply"
            );
        }
    }

    /// The gate is passable: acknowledging the exact token lets the same
    /// apply through, because the job is to make the decision visible, not
    /// to prevent it.
    #[test]
    fn acknowledging_the_exact_token_passes_the_gate() {
        assert_eq!(
            decide(Some(&locked_out()), Some("console-locked+ssh-disabled")),
            Decision::Proceed
        );
    }

    /// And only that token. An acknowledgement given for one lockout must
    /// not pass a different one -- the same property `accept_pin_change`
    /// gets by naming a revision.
    #[test]
    fn an_acknowledgement_of_a_different_lockout_does_not_pass() {
        let mut firewalled = locked_out();
        firewalled.ssh_enabled = true;
        firewalled.ssh_ports = vec![2222];
        firewalled.allowed_tcp_ports = vec![80];

        for other in ["", "console-locked", "ssh-disabled", "console-locked+ssh-disabled", "yes"] {
            assert!(
                matches!(decide(Some(&firewalled), Some(other)), Decision::Refuse(_)),
                "{other:?} must not pass a firewall lockout",
            );
        }
        // The control: its OWN token does pass, so the loop above is
        // measuring the token and not a gate that refuses everything.
        assert_eq!(
            decide(Some(&firewalled), Some("console-locked+ssh-firewalled")),
            Decision::Proceed
        );
    }

    /// shadow(5)'s lock markers are not passwords. A root account whose
    /// hash is `!` accepts nothing at the console, and reading it as "root
    /// has a password" would make this gate silent on a real lockout.
    #[test]
    fn a_locked_password_hash_is_not_a_password() {
        for locked in ["!", "!!", "*", "!$6$real$hash"] {
            assert!(!usable_password(Some(locked)), "{locked} is a lock marker");
        }
        assert!(!usable_password(None));
        // The empty string is NixOS's "log in with no password at all",
        // which is a way in, however unwise.
        assert!(usable_password(Some("")));
        assert!(usable_password(Some("$6$real$hash")));
    }

    #[test]
    fn a_nologin_shell_is_not_a_way_in() {
        assert!(shell_refuses_login("/run/current-system/sw/bin/nologin"));
        assert!(shell_refuses_login("/nix/store/abc-shadow/bin/nologin"));
        assert!(shell_refuses_login("/run/current-system/sw/bin/false"));
        assert!(!shell_refuses_login("/run/current-system/sw/bin/bash"));
        // An absent shell is not evidence of refusal.
        assert!(!shell_refuses_login(""));
    }

    #[test]
    fn authorized_key_patterns_expand_the_way_sshd_expands_them() {
        assert_eq!(
            expand_key_path("/etc/ssh/authorized_keys.d/%u", "root", "/root"),
            Some(PathBuf::from("/etc/ssh/authorized_keys.d/root")),
        );
        assert_eq!(
            expand_key_path("%h/.ssh/authorized_keys", "root", "/root"),
            Some(PathBuf::from("/root/.ssh/authorized_keys")),
        );
        // A relative pattern is relative to the home directory.
        assert_eq!(
            expand_key_path(".ssh/authorized_keys", "root", "/root"),
            Some(PathBuf::from("/root/.ssh/authorized_keys")),
        );
        // A token this check does not understand, and a relative pattern
        // with no home: both are "cannot answer", not "no key here".
        assert_eq!(expand_key_path("%D/keys", "root", "/root"), None);
        assert_eq!(expand_key_path(".ssh/authorized_keys", "root", ""), None);
        // `%%` is a literal percent, not a token.
        assert_eq!(expand_key_path("/k/100%%", "root", "/root"), Some(PathBuf::from("/k/100%")));
    }

    #[test]
    fn a_key_file_holds_a_key_only_when_it_has_a_real_line() {
        assert!(holds_a_key("ssh-ed25519 AAAA operator\n"));
        assert!(holds_a_key("# a comment\n\nssh-rsa AAAA\n"));
        assert!(!holds_a_key(""));
        assert!(!holds_a_key("\n\n   \n"));
        assert!(!holds_a_key("# only a comment\n"));
    }

    /// The live read distinguishes the three answers it must: a key found,
    /// every file absent, and a file that could not be read.
    #[test]
    fn the_live_key_read_separates_absent_from_unreadable() {
        let user = User {
            name: "root".to_string(),
            home: "/root".to_string(),
            shell: "/bin/bash".to_string(),
            password: None,
            keys: vec![],
            key_files: vec![],
            live_keys: None,
        };
        let patterns = vec![".ssh/authorized_keys".to_string()];

        assert_eq!(
            live_keys_for(&user, &patterns, |_| Ok("ssh-ed25519 AAAA\n".to_string())),
            Some(true),
        );
        assert_eq!(
            live_keys_for(&user, &patterns, |_| Err(std::io::Error::from(
                std::io::ErrorKind::NotFound
            ))),
            Some(false),
            "an absent file means no key there, which is a real answer",
        );
        assert_eq!(
            live_keys_for(&user, &patterns, |_| Err(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied
            ))),
            None,
            "a file this check could not read is not a file with no key in it",
        );
        // The path really is the expanded one, not the raw pattern.
        assert_eq!(
            live_keys_for(&user, &patterns, |p| {
                assert_eq!(p, Path::new("/root/.ssh/authorized_keys"));
                Ok(String::new())
            }),
            Some(false),
        );
        // An unexpandable pattern poisons the whole answer rather than
        // being skipped.
        assert_eq!(
            live_keys_for(&user, &["%D/keys".to_string()], |_| Ok("ssh-rsa AAAA".to_string())),
            None,
        );
    }

    /// The argv is the entire guarantee that this gate changes nothing. It
    /// must evaluate, never build; it must not write the lock file; and it
    /// must use the same purity the apply's own build uses, or it would be
    /// answering about a configuration the apply could not build.
    #[test]
    fn the_eval_is_read_only_and_matches_the_builds_purity() {
        let argv = eval_argv(
            "/etc/ferrum#nixosConfigurations.default.config.system.build.toplevel",
        );
        assert_eq!(argv[0], "eval", "this probe must never build: {argv:?}");
        assert!(argv.contains(&"--no-write-lock-file".to_string()), "{argv:?}");
        assert!(argv.contains(&"--impure".to_string()), "{argv:?}");
        assert!(argv.contains(&"--json".to_string()), "{argv:?}");
        assert!(
            argv.contains(&"/etc/ferrum#nixosConfigurations.default.config".to_string()),
            "the attribute is the resulting configuration, not the toplevel: {argv:?}",
        );
        assert!(
            !argv.iter().any(|a| a == "--override-input" || a == "--recreate-lock-file"),
            "nothing here may move an input: {argv:?}",
        );
    }

    /// The parse is asserted against a document shaped exactly like the one
    /// `EVAL_APPLY` produces, so a renamed field fails here rather than
    /// turning every real host's gate silently into `Unknown`.
    #[test]
    fn the_evaluated_document_parses_into_facts() {
        let json = r#"{
          "mutableUsers": false,
          "sshEnabled": true,
          "sshPorts": [22],
          "permitRootLogin": "prohibit-password",
          "passwordAuthentication": false,
          "authorizedKeysCommand": "none",
          "authorizedKeysFiles": [".ssh/authorized_keys", "/etc/ssh/authorized_keys.d/%u"],
          "firewallEnabled": true,
          "allowedTcpPorts": [22, 443],
          "allowedTcpPortRanges": [{"from": 8000, "to": 8010}],
          "firewallOpaque": false,
          "users": [
            {"name": "root", "home": "/root", "shell": "/bin/bash",
             "password": null, "keys": [], "keyFiles": []}
          ]
        }"#;
        let facts: Facts = serde_json::from_str(json).unwrap();
        assert!(!facts.mutable_users);
        assert_eq!(facts.ssh_ports, vec![22]);
        assert_eq!(facts.allowed_tcp_port_ranges, vec![PortRange { from: 8000, to: 8010 }]);
        assert_eq!(facts.users[0].name, "root");
        assert_eq!(facts.users[0].password, None);
        assert_eq!(
            facts.users[0].live_keys, None,
            "the live read is not part of the evaluated document",
        );
        // A port inside a declared range counts as allowed.
        let mut ranged = facts.clone();
        ranged.ssh_ports = vec![8005];
        ranged.allowed_tcp_ports = vec![];
        assert_eq!(ssh_port_route(&ranged), Route::Open);
    }

    /// The three documents below are REAL output: `EVAL_APPLY`, verbatim,
    /// applied by `nix eval` to a really-evaluated NixOS configuration
    /// (`exampleHosts.minimal` from `nix/modules/flake/checks.nix`, plus
    /// one overlay each for the two lockouts). They are the only thing in
    /// this file that can catch an expression which parses, type-checks and
    /// unit-tests perfectly while answering nothing about a real host --
    /// and that is not hypothetical: the first version of `EVAL_APPLY`
    /// produced exactly that, twice.
    ///
    ///   * `shell` was `toString u.shell`, which on a real host yields the
    ///     shell PACKAGE's store directory, so all fifty-odd system users
    ///     looked like they had a login shell called `shadow-4.18.0`.
    ///   * `firewallOpaque` was `extraCommands != ""`, and nixpkgs' own nat
    ///     module appends a teardown block to `extraCommands` on every
    ///     stock host -- so the firewall arm was permanently `Unknown`,
    ///     i.e. dead, on every machine ferrum will ever run on.
    ///
    /// Both passed every hand-written test above. Only real output found
    /// them. Regenerate these by applying `EVAL_APPLY` to a host config
    /// with `nix eval` if the expression changes.
    const HEALTHY_HOST: &str = include_str!("way_in_fixtures/healthy.json");
    const LOCKED_OUT_HOST: &str = include_str!("way_in_fixtures/locked-out.json");
    const FIREWALLED_HOST: &str = include_str!("way_in_fixtures/firewalled.json");
    const KEY_ONLY_HOST: &str = include_str!("way_in_fixtures/key-only.json");

    /// Parse one of the captured documents and fill in the live-key answer
    /// a real preflight would read off the machine.
    ///
    /// # Arguments
    /// * `json` - one captured document.
    /// * `live` - what the on-disk authorized-keys read would have said.
    ///   Explicit rather than defaulted, because `Facts`' `#[serde(skip)]`
    ///   leaves it `None`, which means "could not tell" and would make
    ///   every assertion below vacuously `Proceed`.
    ///
    /// # Returns
    /// The parsed facts.
    fn evaluated(json: &str, live: Option<bool>) -> Facts {
        let mut facts: Facts = serde_json::from_str(json).expect("real eval output must parse");
        for user in &mut facts.users {
            user.live_keys = live;
        }
        facts
    }

    /// The RED case against a really-evaluated configuration: a host with
    /// `users.mutableUsers = false` (so the console password ferrum-apply
    /// writes is erased by activation) and `services.openssh.enable =
    /// mkForce false`. There is no way back into that machine, and the gate
    /// says so before anything is built.
    #[test]
    fn a_really_evaluated_locked_out_host_is_refused() {
        let facts = evaluated(LOCKED_OUT_HOST, Some(false));
        assert!(!facts.mutable_users);
        assert!(!facts.ssh_enabled);
        assert!(
            facts.users.iter().any(|u| u.name == "root"),
            "the probe must really describe root, or this proves nothing",
        );

        let Decision::Refuse(refusal) = decide(Some(&facts), None) else {
            panic!("a really-evaluated host with no way in must be refused");
        };
        assert_eq!(refusal.accept_token, "console-locked+ssh-disabled");
        assert_eq!(decide(Some(&facts), Some(&refusal.accept_token)), Decision::Proceed);
    }

    /// The firewall arm against a really-evaluated configuration:
    /// `services.openssh.openFirewall = mkForce false` with the firewall
    /// on, so sshd runs and would take the operator's key and nothing can
    /// reach port 22. This is the case the first `firewallOpaque` got
    /// wrong -- it answered `Unknown` here, on a host carrying no
    /// hand-written firewall rule at all.
    #[test]
    fn a_really_evaluated_firewalled_host_is_refused() {
        let facts = evaluated(FIREWALLED_HOST, Some(false));
        assert!(facts.ssh_enabled, "sshd really is running on this host");
        assert_eq!(facts.ssh_ports, vec![22]);
        assert!(
            !facts.allowed_tcp_ports.contains(&22),
            "openFirewall = false really did keep 22 out of the allow list: {:?}",
            facts.allowed_tcp_ports,
        );
        assert!(
            !facts.firewall_opaque,
            "a stock NixOS firewall must not read as carrying hand-written rules -- nixpkgs' \
             nat module puts a teardown block in extraCommands on every host",
        );

        let Decision::Refuse(refusal) = decide(Some(&facts), None) else {
            panic!("an sshd nothing can reach, with the console locked, must be refused");
        };
        assert_eq!(refusal.accept_token, "console-locked+ssh-firewalled");
    }

    /// The anti-vacuity half, against two really-evaluated hosts that are
    /// NOT lockouts -- and they are not lockouts for two different reasons,
    /// which is the point. The gate needs both routes shut, so each of
    /// these shuts one and keeps the other.
    ///
    /// The unmodified example host keeps the CONSOLE: it is eval-only and
    /// declares no root key at all, so its SSH route genuinely reads
    /// closed -- and `users.mutableUsers` is NixOS's default true, so the
    /// console password ferrum-apply writes survives and the operator can
    /// walk up to the machine. (That asymmetry is real output, not a
    /// contrivance: this test first asserted both routes open and failed.)
    ///
    /// The template-shaped host keeps SSH: `users.mutableUsers = false`
    /// with no declared root password closes the console, and one declared
    /// `authorizedKeys` entry -- with passwords off and
    /// `PermitRootLogin = prohibit-password` -- is the only thing holding
    /// the door. Remove that single line and it becomes the lockout the
    /// template's own comment warns about.
    #[test]
    fn really_evaluated_hosts_that_keep_one_route_proceed() {
        let example = evaluated(HEALTHY_HOST, Some(false));
        assert_eq!(console_route(&example), Route::Open, "mutableUsers is true here");
        assert_eq!(decide(Some(&example), None), Decision::Proceed);

        let keyed = evaluated(KEY_ONLY_HOST, Some(false));
        assert!(!keyed.mutable_users);
        assert!(!keyed.password_authentication);
        assert!(matches!(console_route(&keyed), Route::Closed(_)), "the console really is shut");
        assert_eq!(ssh_route(&keyed), Route::Open, "one declared key is the whole way in");
        assert_eq!(decide(Some(&keyed), None), Decision::Proceed);

        // And it is THAT key doing the work: take it away and the same host
        // becomes a refusal. Without this, the assertion above could be
        // passing for any other reason.
        let mut keyless = keyed.clone();
        for user in &mut keyless.users {
            user.keys.clear();
        }
        let Decision::Refuse(refusal) = decide(Some(&keyless), None) else {
            panic!("removing the only authorized key must leave no way in");
        };
        assert_eq!(refusal.accept_token, "console-locked+ssh-no-credential");
    }

    /// The fifty-odd system users a real host carries must not be mistaken
    /// for ways in. They have no password and no key; the one thing that
    /// would make them look like a login is a shell this check cannot read,
    /// which is exactly the defect the fixtures caught.
    #[test]
    fn the_system_users_on_a_real_host_resolve_to_a_nologin_shell() {
        let facts = evaluated(HEALTHY_HOST, Some(false));
        let nginx =
            facts.users.iter().find(|u| u.name == "nginx").expect("the real host runs nginx");
        assert!(
            shell_refuses_login(&nginx.shell),
            "a system user's shell must resolve to the interpreter, not the package: {}",
            nginx.shell,
        );
        let root = facts.users.iter().find(|u| u.name == "root").unwrap();
        assert!(
            !shell_refuses_login(&root.shell),
            "the control: root really does get a login shell: {}",
            root.shell,
        );
    }

    /// The expression handed to `nix eval --apply` must name every field
    /// `Facts` deserializes, or the gate would be `Unknown` on every real
    /// host while every test here passed. Asserted against the serde names
    /// rather than a hand-written list.
    #[test]
    fn the_eval_expression_produces_every_field_facts_needs() {
        for field in [
            "mutableUsers",
            "sshEnabled",
            "sshPorts",
            "permitRootLogin",
            "passwordAuthentication",
            "authorizedKeysCommand",
            "authorizedKeysFiles",
            "firewallEnabled",
            "allowedTcpPorts",
            "allowedTcpPortRanges",
            "firewallOpaque",
            "users",
            "name",
            "home",
            "shell",
            "password",
            "keys",
            "keyFiles",
        ] {
            assert!(
                EVAL_APPLY.contains(&format!("{field} =")),
                "the eval expression never sets {field}, so Facts could not parse its output",
            );
        }
        // The negative control: a field that is NOT in the document must
        // not be found, or the assertion above would pass against anything.
        assert!(!EVAL_APPLY.contains("liveKeys ="));
    }
}
