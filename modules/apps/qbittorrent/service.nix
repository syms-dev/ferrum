# qBittorrent, wired through the uniform ferrum.apps.qbittorrent submodule
# onto nixpkgs' services.qbittorrent, with an optional VPN-gated network
# namespace. See docs/superpowers/specs/2026-08-20-phase-1-3-catalog-apps-
# design.md's "qBittorrent VPN Kill Switch" section for the full design and
# why network-namespace isolation was chosen over qBittorrent's own
# interface-binding setting (known historical leak classes).
{ config, lib, pkgs, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.qbittorrent or { enable = false; };
  vpnConfig = app.settings.vpnWireguardConfig or "";
  vpnEnabled = vpnConfig != "";
  killSwitch = app.settings.vpnKillSwitch or true;
in
lib.mkIf app.enable {
  services.qbittorrent = {
    enable = true;
    profileDir = app.stateDir;
    user = "qbittorrent";
    group = "qbittorrent";
    webuiPort = app.port;
  };

  users.users.qbittorrent.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  # The WireGuard config is deliberately NEVER Nix-interpolated into this
  # unit -- app.settings.vpnWireguardConfig can contain a private key, and
  # any value embedded into a systemd unit's script text lands in
  # /nix/store, which is world-readable by default to every local user,
  # not just root. This script instead reads /etc/ferrum/settings.json
  # directly at RUNTIME via jq, so the secret flows from one on-disk file
  # to another (settings.json -> /run/qbt-vpn/wg0.conf) without ever
  # passing through Nix evaluation as a literal embedded value.
  systemd.services.qbt-vpn-netns-setup = lib.mkIf vpnEnabled {
    description = "Create the VPN-gated network namespace for qBittorrent";
    unitConfig.DefaultDependencies = false;
    after = [ "network-pre.target" ];
    wants = [ "network-pre.target" ];
    before = [ "qbittorrent.service" ];
    path = [ pkgs.iproute2 pkgs.wireguard-tools pkgs.jq pkgs.iptables pkgs.gawk pkgs.gnugrep pkgs.coreutils ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    # app.settings.vpnWireguardConfig is read at runtime, never
    # Nix-interpolated (see above), so this unit's own store path is
    # invariant under a config change -- switch-to-configuration has
    # nothing to detect on its own. This hash-of-the-value trigger
    # restores restart-on-change without reintroducing the secret into
    # the unit file: a SHA-256 of a value containing a private key is not
    # reversible (found during the final whole-branch review).
    restartTriggers = [ (builtins.hashString "sha256" vpnConfig) ];
    script = ''
      set -euo pipefail
      ip netns del qbt-vpn 2>/dev/null || true
      ip netns add qbt-vpn
      mkdir -p -m 0700 /run/qbt-vpn
      umask 077
      jq -r '.apps.qbittorrent.settings.vpnWireguardConfig // ""' /etc/ferrum/settings.json \
        > /run/qbt-vpn/wg0.conf
      chmod 0600 /run/qbt-vpn/wg0.conf

      # Create the WireGuard interface in THIS (root) namespace first, then
      # move it into qbt-vpn -- a WireGuard interface's encrypted UDP
      # socket stays bound to whichever namespace it was created in, even
      # after the interface itself is moved elsewhere. Creating it
      # directly inside qbt-vpn (the original approach, via `ip netns exec
      # qbt-vpn wg-quick up ...`) leaves the encrypted tunnel traffic with
      # no route out, since qbt-vpn has no other interface to carry it --
      # confirmed via a real `ip route get <peer> mark <fwmark>` test on
      # ferrum-dev returning "Network is unreachable" under that approach
      # (found during the final whole-branch review). Because this
      # bypasses wg-quick's own Address/DNS handling, both are parsed from
      # the runtime-read config below instead.
      wg_address=$(awk -F'=' '/^[[:space:]]*Address[[:space:]]*=/ { gsub(/[ \t]/, "", $2); print $2; exit }' /run/qbt-vpn/wg0.conf)
      if [ -z "$wg_address" ]; then
        echo "qbt-vpn-netns-setup: no Address= line in the WireGuard config" >&2
        exit 1
      fi

      # wg0 is created in the root namespace, ahead of the `ip netns del
      # qbt-vpn` cleanup above having anything to do with it -- if a prior
      # run was killed between this line and the `ip link set ... netns`
      # move below, wg0 would leak into the root namespace and this
      # command would fail with "File exists" on the next start. Guarded
      # the same way the netns cleanup above already is (found during the
      # final whole-branch review's re-review).
      ip link del wg0 2>/dev/null || true
      ip link add wg0 type wireguard
      wg setconf wg0 <(wg-quick strip /run/qbt-vpn/wg0.conf)
      ip link set wg0 netns qbt-vpn
      ip netns exec qbt-vpn ip link set lo up
      ip netns exec qbt-vpn ip address add "$wg_address" dev wg0
      ip netns exec qbt-vpn ip link set wg0 up
      ip netns exec qbt-vpn ip route add default dev wg0

      # DNS: wg-quick would normally manage this itself via resolvconf;
      # since it's not being used to bring the interface up (see above),
      # the namespace's resolver is written by hand from any DNS= line in
      # the config. /etc/netns/qbt-vpn/resolv.conf is what `ip netns exec`
      # bind-mounts over /etc/resolv.conf for commands run through it --
      # but qbittorrent.service itself joins the namespace via systemd's
      # NetworkNamespacePath=, a plain setns() that does NOT get that
      # bind-mount treatment, so qbittorrent.service's own BindReadOnlyPaths
      # below points it at this same file directly. No DNS= line means no
      # resolver is configured for the namespace, matching "the namespace
      # only has what's explicitly given."
      mkdir -p /etc/netns/qbt-vpn
      wg_dns=$(awk -F'=' '/^[[:space:]]*DNS[[:space:]]*=/ { gsub(/[ \t]/, "", $2); print $2; exit }' /run/qbt-vpn/wg0.conf)
      : > /etc/netns/qbt-vpn/resolv.conf
      if [ -n "$wg_dns" ]; then
        IFS=',' read -ra dns_servers <<< "$wg_dns"
        for server in "''${dns_servers[@]}"; do
          echo "nameserver $server" >> /etc/netns/qbt-vpn/resolv.conf
        done
      fi

      # A management-only veth pair to the host is always created,
      # regardless of the kill-switch setting -- without it, nothing in
      # the host's default namespace (Radarr/Sonarr/Prowlarr pushing
      # torrents into qBittorrent's API, a future reverse proxy, ferrum's
      # own health checks) can reach the namespace-isolated WebUI at all,
      # silently contradicting this app's own catalog metadata
      # (integrations.providesTo, authBypassPaths, healthCheck). This does
      # not weaken the kill switch: whether the veth ALSO becomes an
      # internet fallback path is controlled entirely by whether a default
      # route via it exists inside the namespace, which is exactly the
      # branch below.
      ip link add veth-qbt-host type veth peer name veth-qbt-ns
      ip link set veth-qbt-ns netns qbt-vpn
      ip addr add 10.200.1.1/30 dev veth-qbt-host
      ip link set veth-qbt-host up
      ip netns exec qbt-vpn ip addr add 10.200.1.2/30 dev veth-qbt-ns
      ip netns exec qbt-vpn ip link set veth-qbt-ns up

      ${lib.optionalString (!killSwitch) ''
        # Kill switch OFF: add a fallback DEFAULT route back to the host's
        # normal network via the veth pair above, lower priority than the
        # WireGuard route so the tunnel is always preferred when it's up.
        # IP forwarding must be enabled or the MASQUERADE rule below never
        # actually forwards packets (caught during Task 7's review).
        echo 1 > /proc/sys/net/ipv4/ip_forward
        ip netns exec qbt-vpn ip route add default via 10.200.1.1 dev veth-qbt-ns metric 200
        iptables -t nat -A POSTROUTING -s 10.200.1.0/30 -j MASQUERADE
      ''}
    '';
    preStop = ''
      ip netns del qbt-vpn 2>/dev/null || true
      ip link del veth-qbt-host 2>/dev/null || true
      rm -rf /etc/netns/qbt-vpn
      ${lib.optionalString (!killSwitch) ''
        iptables -t nat -D POSTROUTING -s 10.200.1.0/30 -j MASQUERADE 2>/dev/null || true
      ''}
    '';
  };

  systemd.services.qbittorrent = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    after = lib.mkIf vpnEnabled [ "qbt-vpn-netns-setup.service" ];
    bindsTo = lib.mkIf vpnEnabled [ "qbt-vpn-netns-setup.service" ];
    serviceConfig = (lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    }) // lib.optionalAttrs vpnEnabled {
      NetworkNamespacePath = "/var/run/netns/qbt-vpn";
      # qbittorrent.service joins the namespace via NetworkNamespacePath
      # (setns), not `ip netns exec`, so it does not automatically pick up
      # /etc/netns/qbt-vpn/resolv.conf the way commands run through `ip
      # netns exec qbt-vpn ...` do. Bind-mounting it directly onto
      # /etc/resolv.conf gives this unit the same resolver the namespace
      # was actually configured with (found during the final whole-branch
      # review -- NetworkNamespacePath= shares only the network namespace,
      # not iproute2's own /etc overlay mechanism).
      BindReadOnlyPaths = [ "/etc/netns/qbt-vpn/resolv.conf:/etc/resolv.conf" ];
    };
  };
}
