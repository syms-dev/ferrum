# tests/rollback-proves-necessity.nix
#
# The companion to tests/rollback.nix: performs the same v1->v2 upgrade
# WITHOUT the state restore, and asserts v1 FAILS to start against the
# migrated database (nix/pkgs/testapp/src/main.rs's check_schema_version:
# it bails when the database's PRAGMA user_version is newer than the
# binary's --app-version). This is what proves the problem tests/rollback.nix
# solves is real. If this test ever starts passing, ferrum-testapp's premise
# -- and by extension the whole product's premise -- needs re-examining.
#
# No ferrum modules needed here: this only exercises ferrum-testapp itself,
# directly, on the framework's default ephemeral machine. Built via
# pkgs.callPackage directly (the same package nix/modules/flake/packages.nix
# exposes as packages.ferrum-testapp) rather than through pkgs.ferrum-testapp
# -- that attribute only exists once modules/core/overlays.nix's
# nixpkgs.overlays has been applied to a node's pkgs, which
# pkgs.testers.runNixOSTest makes read-only by default. Building it directly
# here avoids needing that escape hatch (see tests/rollback.nix, which does
# need it, for the full explanation).
{ pkgs, ... }:
let
  ferrum-testapp = pkgs.callPackage ../nix/pkgs/testapp { };
in
pkgs.testers.runNixOSTest {
  name = "ferrum-rollback-proves-necessity";

  nodes.machine = { pkgs, ... }: {
    environment.systemPackages = [ ferrum-testapp pkgs.sqlite ];
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    with subtest("v1 creates and uses a fresh database"):
        # stdout/stderr must be redirected before backgrounding: the test
        # driver's execute() pipes a command's output through `base64 | ...`
        # and waits for that pipe to close, so a detached child that still
        # holds the inherited stdout open would hang this call until the
        # default 15-minute timeout.
        machine.succeed(
            "(${ferrum-testapp}/bin/ferrum-testapp --app-version 1 "
            "--db-path /tmp/app.db --listen 127.0.0.1:8099 "
            "> /dev/null 2>&1 &) ; sleep 2"
        )
        machine.succeed("curl -sf http://127.0.0.1:8099/ping")
        machine.succeed("pkill -f 'ferrum-testapp --app-version 1'")
        machine.sleep(1)

    with subtest("v2 migrates the same database"):
        machine.succeed(
            "(${ferrum-testapp}/bin/ferrum-testapp --app-version 2 "
            "--db-path /tmp/app.db --listen 127.0.0.1:8099 "
            "> /dev/null 2>&1 &) ; sleep 2"
        )
        machine.succeed("curl -sf http://127.0.0.1:8099/ping")
        machine.succeed("pkill -f 'ferrum-testapp --app-version 2'")
        machine.sleep(1)
        machine.succeed(
            "${pkgs.sqlite}/bin/sqlite3 /tmp/app.db 'PRAGMA user_version;' | grep -q '^2$'"
        )

    with subtest(
        "v1, downgraded WITHOUT a state restore, refuses to start against "
        "the migrated database -- this is the failure mode the whole "
        "rollback mechanism exists to prevent. Runs in the foreground (no "
        "trailing &): check_schema_version's refusal happens before the "
        "HTTP server ever binds, so the process exits immediately rather "
        "than hanging"
    ):
        machine.fail(
            "${ferrum-testapp}/bin/ferrum-testapp --app-version 1 "
            "--db-path /tmp/app.db --listen 127.0.0.1:8099"
        )
  '';
}
