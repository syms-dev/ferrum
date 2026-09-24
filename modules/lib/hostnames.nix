# The option types for every ferrum setting that ends up inside a generated
# DIRECTIVE -- in any line-oriented configuration file ferrum generates, not
# only nginx's.
#
# That first line said "nginx" for three security passes, and the word was
# the defect. Every enumeration of "which settings reach a directive" was
# derived BACKWARD, by starting from the files already known to be dangerous
# -- nginx, Authelia, ACME -- and tracing back to settings. A backward pass
# can only ever rediscover the files it started from. It cannot find a sink
# nobody has thought of yet, which is precisely the sink that matters.
#
# A forward sweep from every leaf of modules/lib/settings-schema.json found
# five more root-executed grammars that had never been in scope, all of them
# line- or comma-oriented and all of them executed with more privilege than
# nginx has:
#
#   * systemd.tmpfiles.rules      -- NEWLINE-separated, re-read by
#                                    systemd-tmpfiles as ROOT on every
#                                    switch-to-configuration. An injected
#                                    `w+ /root/.ssh/authorized_keys ...` rule
#                                    was rendered, not theorised.
#   * systemd unit LIST-fields    -- ReadWritePaths, BindPaths and friends.
#     (ReadWritePaths, ...)          NixOS emits one `Key=value` line per
#                                    element with NO escaping. This is the
#                                    asymmetry that makes them dangerous:
#                                    `Environment=` values ARE JSON-quoted by
#                                    nixpkgs, so a newline there renders as a
#                                    literal `\n` inside one quoted directive
#                                    -- and reasoning from that safe case to
#                                    the list case is exactly the wrong
#                                    inference. An injected `ExecStartPre=`
#                                    landed in a real [Service] section.
#   * /etc/fstab OPTIONS field    -- COMMA-separated, not newline. `suid` and
#                                    `dev` smuggled into the media pool's
#                                    options are a setuid-escalation path on
#                                    the one filesystem every app writes to.
#   * users.groups.<name>         -- an ATTRIBUTE NAME, so the value is a
#                                    /etc/group row written by
#                                    update-users-groups.pl, where both `\n`
#                                    and `:` separate.
#   * sops `sopsFile` paths       -- `/. + "${secretsDir}/${name}.sops"`,
#                                    where the separator is `..`.
#
# So the rule for this file is not "nginx is reading them". It is: if a value
# an operator can write is interpolated into a file some program later PARSES,
# the character set is a security control and it belongs here. Ask what
# separates records in that file, and whether this string can contain it.
#
# There is one file for all of them on purpose. Three separate options --
# ferrum.proxy.baseDomain, ferrum.daemon.subdomain and every
# ferrum.apps.<id>.subdomain -- are interpolated into `server_name`, into an
# ACME certificate name, and into modules/proxy/nginx.nix's `error_page 401
# =302 https://auth.${baseDomain}/...`; ferrum.daemon.listenAddress is
# interpolated into `proxy_pass`; every ferrum.proxy.trustedNetworks entry
# into `allow ${net};`; and every ferrum.apps.<id>.auth.bypassPaths entry
# into a `location ${path} {` NAME and into an Authelia access_control
# `resources` REGEX. All six were `types.str`. None of them is free text:
# nginx is reading them.
#
# Six, and the count is the point. The first four were fixed in one pass and
# the last two were not, in the same diff -- ferrum.apps.<id>.subdomain got
# dnsLabel while its sibling three lines below, bypassPaths, kept
# types.listOf types.str. So the rule for this file is: a new option whose
# value lands inside any generated directive belongs
# HERE before it belongs in modules/core/options.nix, and
# nix/modules/flake/checks.nix's daemon-vhost-enforced carries a payload
# fixture for each one.
#
# The concrete defect these replace, proved end to end against a real nginx
# before this file existed:
#
#   ferrum.daemon.listenAddress = ''127.0.0.1 ; return 200 "pwned" ; #''
#
# modules/core/daemon.nix's loopback guard split that on "." into four parts
# whose first is "127" and accepted it; nginx parsed the rendered
# `proxy_pass http://127.0.0.1 ; return 200 "pwned" ; #:7788;` with EXIT 0
# and served `HTTP/1.1 200 pwned` from the control plane's own vhost. The
# trailing `#` comments out only the `:7788;` left behind it.
#
# So the parser cannot be the control. nginx's grammar makes the injected
# config *valid*, which is exactly why it is dangerous, and nixpkgs'
# services.nginx.validateConfigFile does not help either -- it runs gixy, a
# linter, and never invokes nginx's parser at all. The only place to refuse
# these bytes is before they are written: here, and in the `pattern` keyword
# on the same three fields in modules/lib/settings-schema.json, which is what
# stops ferrumd's own `PUT /api/settings` composing the value in the first
# place.
#
# Kept as ONE definition rather than a regex pasted at each option for the
# reason nix/modules/flake/checks.nix's acceptedLoopbackSpellings is one
# list: a constraint copied to four call sites is a constraint that will be
# widened at one of them.
{ lib }:
let
  # A single DNS label: alphanumeric at both ends, hyphens allowed inside.
  # Deliberately not the full RFC 1035 grammar (no length limits, no
  # trailing-dot form) -- this is a character-set control, and the property
  # that matters is that nothing here can terminate an nginx directive or
  # start a comment.
  label = "[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?";
  dotted = "${label}(\\.${label})*";
in
{
  # A dotted name, or nothing. The empty string is load-bearing and must stay
  # legal: it is ferrum.proxy.baseDomain's default and the sentinel every
  # "does this host publish anything" predicate tests against (see
  # modules/proxy/lib.nix's daemonPublished).
  dnsName = lib.types.strMatching "(${dotted})?";

  # A name that must actually be one -- a subdomain with no baseDomain still
  # names a vhost, and an empty one would render `server_name .example.test`.
  # Dots are allowed because "a.b" under a base domain is a legitimate thing
  # to want and is no less safe than "ab".
  dnsLabel = lib.types.strMatching dotted;

  # ferrum.daemon.listenAddress, and deliberately WIDER than the set of
  # addresses ferrum will actually accept: this type's whole job is to bound
  # the CHARACTER SET to things nginx reads as one token, and
  # modules/core/daemon.nix's A5 assertion is what decides whether the value
  # is a loopback address.
  #
  # Splitting it that way is what keeps the operator-facing messages. A value
  # like "localhost" or "127.0.0.1.example.test" is refused either way, but
  # refused HERE it produces "does not match the pattern", while refused
  # there it produces the several paragraphs daemon.nix spends explaining
  # that a name resolves to two addresses and ferrumd binds one of them. The
  # cheap character-set control must not swallow the expensive explanation.
  addressLiteral = lib.types.strMatching "[0-9A-Za-z.:-]*";

  # SEC-01. One entry of ferrum.proxy.trustedNetworks, which
  # modules/proxy/nginx.nix renders as `allow ${net};` at the top of a
  # lan-exposure app's `location /`.
  #
  # This one is not "a malformed allow directive". lanRestriction is
  # concatenated in FRONT of the `deny all;` and the whole auth_request
  # block, so a `}` in this value closes `location /` before nginx has read
  # either of them, and everything after the brace becomes a sibling
  # location with no gate on it at all. Served, not theorised: against a real
  # nginx with an Authelia stub wired to return 401 unconditionally,
  #
  #   ferrum.proxy.trustedNetworks = [
  #     ''127.0.0.1; } location /anything { proxy_pass http://127.0.0.1:8989; #''
  #   ];
  #
  # answered GET / with 200 and the application's body, while the same
  # request against the same upstream with a benign value answered 403.
  #
  # Deliberately a character-set control and not a CIDR parse, for the reason
  # addressLiteral is: what makes the payload work is the space, the `}` and
  # the `#`, and none of them survives this. A value that is in the character
  # set but is not a real network ("1.2.3.4.5/99") is refused later by
  # nginx's own parser -- `nginx -t` fails and the unit does not start, which
  # is an outage rather than a bypass. That asymmetry is the whole reason the
  # cheap control goes here: it closes the direction that silently serves.
  networkLiteral = lib.types.strMatching "[0-9A-Fa-f.:]+(/[0-9]{1,3})?";

  # SEC-02. One entry of ferrum.apps.<id>.auth.bypassPaths, and it reaches
  # TWO generated grammars, which is why the set below is tighter than the
  # nginx side alone would need:
  #
  #   * modules/proxy/nginx.nix: `location ${path} {`, where the path is the
  #     location NAME. An injected block is therefore a SIBLING of "/"
  #     rather than something spliced into it, so it does not merely weaken
  #     the gate on a catalog app -- it adds an ungated route to it.
  #
  #   * modules/proxy/authelia.nix: `resources = [ "^${path}.*$" ]`, a
  #     REGULAR EXPRESSION. A metacharacter here widens the bypass RULE even
  #     when the rendered nginx location is harmless: `/.*` is a perfectly
  #     legal nginx location name and an Authelia rule exempting the entire
  #     vhost.
  #
  # `.` is the one regex metacharacter this admits, because real paths
  # contain it; the cost is that `/a.b` also matches `/axb`, one character
  # wide, on a rule the operator wrote themselves. Everything that quantifies
  # or alternates -- * + ? ( ) | [ ] ^ $ \\ { } -- is out, along with the
  # space, `;` and `#` the nginx half needs excluded.
  #
  # Width checked against the catalog rather than guessed, and
  # nix/modules/flake/checks.nix asserts that rather than trusting this
  # comment: every authBypassPaths value in modules/apps/*/meta.nix
  # (/api, /api/v2, /feed, /ping, /signalr, /identity, /Sessions,
  # /System/Info/Public, /Users/AuthenticateByName) must still generate a
  # location of its own name. Over-tightening is not a safe failure here --
  # `/api` behind forward-auth takes out Prowlarr -> Sonarr/Radarr, every
  # native client, and ferrum's OWN reconciler, so enabling SSO would once
  # again disable the self-setup that SSO exists to protect. That is a bug
  # this repo has actually shipped.
  #
  # The leading `/` is required, matching the option's own documented
  # contract ("location prefixes"). nginx's other location forms -- `= /x`,
  # `~ regex`, `@named` -- are consequently not expressible, which is
  # intended: none of them is a prefix, and an operator-supplied regex is
  # the thing above that this type exists to refuse.
  locationPath = lib.types.strMatching "/[A-Za-z0-9._~%/-]*";

  # ferrum.proxy.acme.email, and this one was found by the sweep the
  # SEC-01/SEC-02 fixes triggered rather than by the finding that prompted
  # them. It is the only value in this file whose sink is a SHELL, not a
  # config grammar.
  #
  # nixpkgs' security.acme passes the address to lego through
  # lib.escapeShellArgs, which is safe, and then interpolates the SAME value
  # raw inside a single-quoted word in the renewal script it generates
  # (nixos/modules/security/acme/default.nix):
  #
  #   [ -n "$(find accounts -name '${data.email}.key')" ]
  #
  # A `'` closes that word. Rendered, control and payload one character
  # apart, read out of the two generated scripts rather than reasoned about:
  #
  #   find accounts -name 'a@example.test.key')" ]; then
  #   find accounts -name 'a'@example.test.key')" ]; then
  #
  # so `a'; <command>; '` runs <command> in acme-<cert>.service, as the
  # `acme` user, on every renewal. nixpkgs types the option types.str and
  # ferrum typed it types.str too, while modules/lib/settings-schema.json
  # typed it {"type":"string"} with no pattern -- an authenticated settings
  # write chose those bytes.
  #
  # The empty string stays legal: it is the option's default, and
  # modules/proxy/acme.nix is what decides an address is REQUIRED (only when
  # a real certificate is needed) and says so in an operator-facing message.
  # Same split as addressLiteral and daemon.nix's A5 assertion.
  #
  # Narrower than RFC 5322's atext, deliberately. The exotic local-part
  # characters it omits -- ' ` " \ $ ; and whitespace among them -- are
  # exactly the shell-significant ones, and a Let's Encrypt contact address
  # that needs them does not exist in practice. `+` is kept because
  # ops+ferrum@example.com is a real thing operators do.
  emailAddress = lib.types.strMatching
    "([A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*)?";

  # ferrum.storage.{stateDir,snapshotDir,journalDir,mediaDir},
  # ferrum.storage.pool.branches[] and ferrum.secretsDir -- the six path
  # options, all of which were types.str.
  #
  # These are the values that made the header above have to be rewritten.
  # Each of them is interpolated UNQUOTED into a systemd.tmpfiles.rules
  # entry, which is a list of NEWLINE-separated records that systemd-tmpfiles
  # executes as root on every switch-to-configuration. Rendered, from a real
  # evaluation rather than reasoned about, with ferrum.secretsDir set to
  # "/etc/ferrum/secrets\nw+ /root/.ssh/authorized_keys 0600 root root - ssh-ed25519 AAAAINJECTED":
  #
  #   d /etc/ferrum/secrets 0750 ferrum ferrum - -
  #   w+ /root/.ssh/authorized_keys 0600 root root - ssh-ed25519 AAAAINJECTED 0750 ferrum ferrum - -
  #
  # a standalone `w+` rule writing an SSH key into root's authorized_keys.
  # The trailing `0750 ferrum ferrum - -` is the remainder of the original
  # rule, which tmpfiles reads as this rule's argument and ignores.
  #
  # Three of the six reach a SECOND grammar with a DIFFERENT separator, which
  # is the reason this is a character-set control and not a "reject newlines"
  # check:
  #
  #   * stateDir also reaches modules/proxy/dns.nix's ReadWritePaths, a
  #     systemd unit list-field, where a newline becomes a real [Service]
  #     directive -- an injected ExecStartPre= ran as root on a timer.
  #   * branches[] also reaches modules/core/pool.nix's /etc/fstab OPTIONS
  #     field, where the separator is a COMMA, not a newline.
  #   * secretsDir also reaches the sops `sopsFile` construction in
  #     modules/proxy/acme.nix and modules/proxy/authelia.nix, where the
  #     separator is `..`.
  #
  # Hence: absolute, one or more segments, no empty segment, no trailing
  # slash, and each segment must BEGIN with a letter, digit or underscore --
  # after which dots, hyphens and underscores are fine.
  #
  # That leading-character rule is doing two jobs and the second one is easy
  # to miss. The charset bans the separators (newline, comma, `:`, space).
  # The leading-character rule bans a `..` segment, because `..` begins with
  # a dot -- which is what closes the sops traversal. Written that way round
  # on purpose: the SAME constraint has to hold in
  # modules/lib/settings-schema.json, whose validator is the Rust `regex`
  # crate, and that engine has NO LOOKAROUND. "Any segment except `..`"
  # cannot be spelled there except as a four-way alternation nobody could
  # audit at a glance, whereas "starts with an alphanumeric" is one
  # character class in both layers. A constraint that is auditable in one
  # layer and clever in the other is a constraint that will drift apart.
  #
  # The cost is stated rather than hidden: a dot-LEADING segment is refused,
  # so a state directory under a hidden directory (/srv/.ferrum/state) is not
  # expressible. Dots elsewhere are fine, so /mnt/disk.1 is. Two values that
  # had to keep working and do: crates/ferrum-install/src/render.rs's
  # /mnt/ferrum-disk-N, and the /nix/store/<hash>-source/... path that
  # nix/modules/flake/checks.nix's example host evaluates ferrum.secretsDir
  # to -- a dot-free rule would have refused neither, but a rule banning
  # dots anywhere in a segment nearly did, which is why the first draft of
  # this type was wrong.
  #
  # Empty is NOT legal here, unlike dnsName and emailAddress. There is no
  # "this host has no state directory" configuration: every one of these six
  # options has a non-empty default, and an empty value would render
  # `d  0751 root root - -` -- a tmpfiles rule with no path.
  absolutePath = lib.types.strMatching "(/[A-Za-z0-9_][A-Za-z0-9._-]*)+";

  # ferrum.storage.mediaGroup, and its first sink is not a value position at
  # all: modules/core/storage.nix writes `users.groups.${cfg.mediaGroup} = {
  # }`, so this string becomes an ATTRIBUTE NAME and from there a row in
  # /etc/group, which update-users-groups.pl writes as root. /etc/group is
  # newline-separated with `:` between fields, so both characters are
  # separators. `builtins.attrNames` confirmed the module system accepts an
  # attribute named "media\nbadroot:x:0:" without complaint -- Nix attribute
  # names are arbitrary strings, so nothing upstream of here objects.
  #
  # It is also the group field of every media tmpfiles rule in the same file
  # (`d ${mediaDir} 0775 root ${mediaGroup} - -`) and lands in six apps'
  # users.users.<app>.extraGroups.
  #
  # The charset is shadow-utils' own NAME_REGEX -- start with a lowercase
  # letter or underscore, then lowercase, digits, `-`, `_`. Narrower than
  # what NixOS's module system would accept, deliberately: a group name that
  # groupadd itself would reject is not a name worth being able to express,
  # and the default (ferrum-media) plus anything an operator would plausibly
  # choose fits inside it.
  groupName = lib.types.strMatching "[a-z_][a-z0-9_-]*";

  # ferrum.proxy.acme.credentialSecret, and the names under ferrum.secrets
  # generally: a secret NAME, which every consumer treats as a path
  # component and none of them re-validates.
  #
  #   * modules/proxy/acme.nix and modules/proxy/authelia.nix build
  #     `${secretsDir}/${name}.sops` -- a `..` here reads a file outside the
  #     secrets directory at evaluation time.
  #   * modules/proxy/dns.nix hands root `/run/secrets/${credentialSecret}`,
  #     which is where the live Cloudflare API token is read from.
  #   * crates/ferrumd/src/secrets_api.rs joins the name under secretsDir to
  #     write `<name>.sops`.
  #
  # This is deliberately the SAME allowlist as
  # crates/ferrum-apply/src/put_secret.rs's validate_secret_name -- lowercase
  # letters, digits, interior hyphens, non-empty, no leading or trailing
  # hyphen -- rather than a second rule of this file's own devising. A name
  # is written at one end and read at the other; two allowlists that merely
  # resemble each other produce a secret that one half of the system will
  # accept and the other will refuse, which is a worse failure than either
  # rule alone. Every secret the tree uses (acme-dns, authelia-jwt-secret,
  # authelia-storage-key, sabnzbd-apikey, qbittorrent-vpn, sonarr-apikey-raw,
  # restic-password) matches it, pinned by that function's own test.
  secretName = lib.types.strMatching "[a-z0-9]([a-z0-9-]*[a-z0-9])?";

  # ferrum.proxy.dns.staticAddress: the IPv4 address every A record points
  # at, or empty when recordMode is "cname".
  #
  # Unlike everything above this is a VALUE control rather than a character-
  # set control, and the difference is worth naming. The value is serialised
  # into JSON by modules/proxy/dns.nix and sent to the Cloudflare API by
  # crates/ferrum-dns, so the serialiser already makes injection impossible;
  # what is not impossible is publishing every app ferrum manages at an
  # address that is not this server. A real address literal is the property
  # that matters, so octet ranges are enforced rather than a loose
  # [0-9.] class.
  #
  # IPv4 only, matching the option's own documented contract that ferrum
  # publishes no AAAA record. Empty stays legal: it is the default and the
  # sentinel modules/proxy/dns.nix's own "is a target configured" check
  # tests against.
  ipv4Literal =
    let octet = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"; in
    lib.types.strMatching "(${octet}(\\.${octet}){3})?";
}
