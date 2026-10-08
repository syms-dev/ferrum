# Read one key out of a WireGuard configuration file and print the addresses
# on it, ONE PER LINE, for a caller that has to apply each of them separately.
#
# This exists because qbt-vpn-netns-setup does not use wg-quick to bring the
# tunnel up -- see the long comment in service.nix about the encrypted socket
# staying bound to the namespace the interface was created in -- and therefore
# has to do wg-quick's own Address= and DNS= handling itself. The first version
# of that handling read the whole line with
#
#     awk -F'=' '/^[[:space:]]*Address[[:space:]]*=/ { gsub(/[ \t]/, "", $2); print $2; exit }'
#
# and handed the result to `ip address add` as a single argument. Every
# mainstream provider issues more than one address, so on the owner's real
# Proton config that argument was "10.2.0.2/32,2a07:b944::2:2/128" and ip(8)
# answered, reproduced for real against iproute2 7.1.0:
#
#     Error: any valid prefix is expected rather than "10.2.0.2/32,2a07:b944::2:2/128".
#     qbt-vpn-netns-setup.service: Main process exited, code=exited, status=1/FAILURE
#
# -- so the unit failed at boot, qbittorrent.service bindsTo'd it and never
# started, and the message named ip(8)'s complaint rather than the config line
# that caused it. Pasting a provider config in unmodified is the whole point of
# the feature, so that is a total failure of it, not an edge case.
#
# A separate awk program rather than more shell inside the unit's script
# because the parsing is the part that was wrong and the part that has to be
# tested, and a `script` is only testable by standing up a privileged network
# namespace. This file can be run against a real provider config in a build
# sandbox with no privileges at all, which is what the
# wireguard-config-with-many-addresses check in nix/modules/flake/checks.nix
# does, using the real config from tests/fixtures/wireguard/.
#
# IPv6 is SKIPPED, loudly, and that is a decision rather than an oversight:
# the qbt-vpn namespace is routed IPv4-only. Its only default route is
# `ip route add default dev wg0`, which is the v4 table; the management veth
# pair to the host is a v4 /30; the kill-switch-off fallback route and its
# MASQUERADE rule are v4 and iptables; and ferrum publishes no AAAA record
# anywhere, which is the same contract ferrum.network.staticAddress already
# states. Configuring an IPv6 address inside that namespace would give
# qBittorrent a source address for a family with no route, no NAT and no
# tested path -- a surface nothing here exercises -- so the address is dropped
# and the operator is told which one and why, in the journal, every start.
# Accepting IPv6 properly means routing it properly, and that is a feature,
# not a parser change.
#
# Usage:
#   awk -v key=Address -v allowPrefix=1 -v required=1 -f wg-parse.awk wg0.conf
#   awk -v key=DNS     -v allowPrefix=0 -v required=0 -f wg-parse.awk wg0.conf
#
# allowPrefix distinguishes the two callers rather than being decoration: an
# address needs its /32 and a resolv.conf nameserver must not have one. A
# provider that wrote "DNS = 10.2.0.1/32" would otherwise produce
# "nameserver 10.2.0.1/32", which resolves nothing and says nothing.
#
# required says whether the absence of any usable entry is fatal. It is for
# Address -- a namespace with no address is a namespace with no network, and
# failing at setup time with a reason beats qBittorrent starting into silence.
# It is not for DNS: "no DNS= line means no resolver" is the documented,
# pre-existing behaviour of this unit and is left alone.
#
# Exit status: 0 with the usable entries on stdout, 1 with a message on stderr
# naming the offending config line. Every message is prefixed with the unit
# name because it is read in `journalctl -u qbt-vpn-netns-setup`.

function note(msg) {
  printf "qbt-vpn-netns-setup: %s\n", msg > "/dev/stderr"
}

function die(msg) {
  printf "qbt-vpn-netns-setup: %s\n  line %d: %s\n", msg, NR, $0 > "/dev/stderr"
  fatal = 1
  exit 1
}

# Deliberately strict, and deliberately not a regex alone: ip(8) accepts
# "10.2.0.300" from a regex that only counts digits and dots, and then fails at
# the point where the error is useless. The whole bug being fixed here is an
# address reaching ip(8) that this program could have rejected by name.
function ipv4ok(a,   slash, addr, prefix, octets, i, n) {
  slash = index(a, "/")
  if (slash > 0) {
    if (!allowPrefix) return 0
    addr = substr(a, 1, slash - 1)
    prefix = substr(a, slash + 1)
    if (prefix !~ /^[0-9][0-9]?$/ || prefix + 0 > 32) return 0
  } else {
    addr = a
  }
  if (addr !~ /^[0-9][0-9]?[0-9]?(\.[0-9][0-9]?[0-9]?){3}$/) return 0
  n = split(addr, octets, ".")
  for (i = 1; i <= n; i++) if (octets[i] + 0 > 255) return 0
  return 1
}

BEGIN {
  if (key == "") {
    note("wg-parse.awk was invoked without -v key=<Address|DNS>")
    fatal = 1
    exit 1
  }
}

# Only the first occurrence, matching the behaviour of the single-line awk this
# replaces. A comment line cannot match: "#" is not whitespace.
$0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
  if (seen) next
  seen = 1

  value = $0
  sub(/^[^=]*=/, "", value)

  n = split(value, entries, ",")
  for (i = 1; i <= n; i++) {
    entry = entries[i]
    gsub(/^[[:space:]]+/, "", entry)
    gsub(/[[:space:]]+$/, "", entry)

    # A trailing comma, or a stray ", ," -- ignored rather than fatal. The
    # operator pasted a file; punctuation is not a configuration error.
    if (entry == "") continue

    # A colon can only be IPv6 here: neither Address= nor DNS= carries a port.
    if (index(entry, ":") > 0) {
      skipped[++nskipped] = entry
      continue
    }

    if (!ipv4ok(entry)) {
      die("\"" entry "\" in the WireGuard config's " key "= list is not an address this host can configure")
    }

    kept[++nkept] = entry
  }
}

END {
  if (fatal) exit 1

  for (i = 1; i <= nskipped; i++) {
    note("skipping the IPv6 " key " entry " skipped[i] \
         " -- the qbt-vpn namespace is routed IPv4-only, so nothing in it could use that address")
  }

  if (!seen) {
    if (required) {
      note("the WireGuard config has no " key "= line, so the qbt-vpn namespace would have no address")
      exit 1
    }
    note("the WireGuard config has no " key "= line, so the qbt-vpn namespace gets no resolver")
    exit 0
  }

  if (nkept == 0) {
    if (required) {
      note("every " key "= entry in the WireGuard config is IPv6, and the qbt-vpn namespace is routed " \
           "IPv4-only, so there is no address left to give it -- ask the provider for an IPv4 config")
      exit 1
    }
    note("every " key "= entry in the WireGuard config is IPv6, so the qbt-vpn namespace gets no resolver")
    exit 0
  }

  for (i = 1; i <= nkept; i++) print kept[i]
}
