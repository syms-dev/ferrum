# The option types for every ferrum setting that ends up inside a generated
# nginx directive.
#
# There is one file for all of them on purpose. Three separate options --
# ferrum.proxy.baseDomain, ferrum.daemon.subdomain and every
# ferrum.apps.<id>.subdomain -- are interpolated into `server_name`, into an
# ACME certificate name, and into modules/proxy/nginx.nix's `error_page 401
# =302 https://auth.${baseDomain}/...`, and a fourth,
# ferrum.daemon.listenAddress, is interpolated into `proxy_pass`. All four
# were `types.str`. None of them is free text: nginx is reading them.
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
}
