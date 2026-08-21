{ config, lib, pkgs, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.qbittorrent or { enable = false; };
  vpnEnabled = ferrum.secrets ? "qbittorrent-vpn";
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

  sops.secrets."qbittorrent-vpn" = lib.mkIf vpnEnabled {
    sopsFile = /. + "${ferrum.secretsDir}/qbittorrent-vpn.sops";
    format = "binary";
  };

  # The WireGuard config is a real sops secret now (ferrum.secrets."qbittorrent-vpn"),
  # written by an operator through the same zero-privilege `sops encrypt`
  # mechanism ferrum-apply's own secret generation uses (see
  # crates/ferrum-apply/src/secrets.rs) -- never Nix-interpolated into this
  # unit, same hard rule as Phase 1.3. sops-nix already decrypted it to
  # /run/secrets/qbittorrent-vpn by the time this script runs, so there's
  # no jq/settings.json read needed anymore -- just copy the already-plaintext
  # file into the netns's own runtime directory.
  systemd.services.qbt-vpn-netns-setup = lib.mkIf vpnEnabled {
    description = "Create the VPN-gated network namespace for qBittorrent";
    unitConfig.DefaultDependencies = false;
    after = [ "network-pre.target" ];
    wants = [ "network-pre.target" ];
    before = [ "qbittorrent.service" ];
    path = [ pkgs.iproute2 pkgs.wireguard-tools pkgs.iptables pkgs.gawk pkgs.gnugrep pkgs.coreutils ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      set -euo pipefail
      ip netns del qbt-vpn 2>/dev/null || true
      ip netns add qbt-vpn
      mkdir -p -m 0700 /run/qbt-vpn
      umask 077
      cp ${config.sops.secrets."qbittorrent-vpn".path} /run/qbt-vpn/wg0.conf
      chmod 0600 /run/qbt-vpn/wg0.conf

      # Create the WireGuard interface in THIS (root) namespace first, then
      # move it into qbt-vpn -- a WireGuard interface's encrypted UDP
      # socket stays bound to whichever namespace it was created in, even
      # after the interface itself is moved elsewhere. Creating it
      # directly inside qbt-vpn leaves the encrypted tunnel traffic with no
      # route out (found for real during Phase 1.3's final whole-branch
      # review, confirmed via an actual WireGuard handshake test).
      wg_address=$(awk -F'=' '/^[[:space:]]*Address[[:space:]]*=/ { gsub(/[ \t]/, "", $2); print $2; exit }' /run/qbt-vpn/wg0.conf)
      if [ -z "$wg_address" ]; then
        echo "qbt-vpn-netns-setup: no Address= line in the WireGuard config" >&2
        exit 1
      fi

      ip link del wg0 2>/dev/null || true
      ip link add wg0 type wireguard
      wg setconf wg0 <(wg-quick strip /run/qbt-vpn/wg0.conf)
      ip link set wg0 netns qbt-vpn
      ip netns exec qbt-vpn ip link set lo up
      ip netns exec qbt-vpn ip address add "$wg_address" dev wg0
      ip netns exec qbt-vpn ip link set wg0 up
      ip netns exec qbt-vpn ip route add default dev wg0

      mkdir -p /etc/netns/qbt-vpn
      wg_dns=$(awk -F'=' '/^[[:space:]]*DNS[[:space:]]*=/ { gsub(/[ \t]/, "", $2); print $2; exit }' /run/qbt-vpn/wg0.conf)
      : > /etc/netns/qbt-vpn/resolv.conf
      if [ -n "$wg_dns" ]; then
        IFS=',' read -ra dns_servers <<< "$wg_dns"
        for server in "''${dns_servers[@]}"; do
          echo "nameserver $server" >> /etc/netns/qbt-vpn/resolv.conf
        done
      fi

      ip link add veth-qbt-host type veth peer name veth-qbt-ns
      ip link set veth-qbt-ns netns qbt-vpn
      ip addr add 10.200.1.1/30 dev veth-qbt-host
      ip link set veth-qbt-host up
      ip netns exec qbt-vpn ip addr add 10.200.1.2/30 dev veth-qbt-ns
      ip netns exec qbt-vpn ip link set veth-qbt-ns up

      ${lib.optionalString (!killSwitch) ''
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
      BindReadOnlyPaths = [ "/etc/netns/qbt-vpn/resolv.conf:/etc/resolv.conf" ];
    };
  };
}
