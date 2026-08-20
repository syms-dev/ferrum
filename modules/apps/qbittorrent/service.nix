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
    path = [ pkgs.iproute2 pkgs.wireguard-tools pkgs.jq pkgs.iptables ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      set -euo pipefail
      ip netns del qbt-vpn 2>/dev/null || true
      ip netns add qbt-vpn
      mkdir -p /run/qbt-vpn
      jq -r '.apps.qbittorrent.settings.vpnWireguardConfig // ""' /etc/ferrum/settings.json \
        > /run/qbt-vpn/wg0.conf
      chmod 0600 /run/qbt-vpn/wg0.conf
      ip netns exec qbt-vpn wg-quick up /run/qbt-vpn/wg0.conf
      ${lib.optionalString (!killSwitch) ''
        # Kill switch OFF: add a fallback route back to the host's normal
        # network via a veth pair, lower priority than the WireGuard
        # route so the tunnel is always preferred when it's up. IP
        # forwarding must be enabled or the MASQUERADE rule below never
        # actually forwards packets (caught during Task 7's review).
        echo 1 > /proc/sys/net/ipv4/ip_forward
        ip link add veth-qbt-host type veth peer name veth-qbt-ns
        ip link set veth-qbt-ns netns qbt-vpn
        ip addr add 10.200.1.1/30 dev veth-qbt-host
        ip link set veth-qbt-host up
        ip netns exec qbt-vpn ip addr add 10.200.1.2/30 dev veth-qbt-ns
        ip netns exec qbt-vpn ip link set veth-qbt-ns up
        ip netns exec qbt-vpn ip route add default via 10.200.1.1 dev veth-qbt-ns metric 200
        iptables -t nat -A POSTROUTING -s 10.200.1.0/30 -j MASQUERADE
      ''}
    '';
    preStop = ''
      ip netns del qbt-vpn 2>/dev/null || true
      ${lib.optionalString (!killSwitch) ''
        ip link del veth-qbt-host 2>/dev/null || true
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
    };
  };
}
