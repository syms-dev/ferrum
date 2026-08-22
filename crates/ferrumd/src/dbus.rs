// The real D-Bus client ferrumd uses to cross the privilege boundary.
//
// ferrumd itself is completely unprivileged (User=ferrum, CapabilityBoundingSet="",
// NoNewPrivileges=true -- see modules/core/daemon.nix). The ONLY privileged
// thing it can do is ask systemd to start `ferrum-apply@<uuid>.service`, and
// the only reason that succeeds is the polkit rule in the same file, which
// authorizes exactly that unit-name pattern and exactly the "start" verb for
// the ferrum user. Everything else -- starting sshd, stopping a unit,
// starting ferrum-apply with a non-UUID instance name -- is denied by polkit,
// which is proven for real by tests/privilege-boundary.nix.
//
// Confirmed for real while writing this plan: this exact proxy definition
// compiles against zbus 4.x and successfully called the real systemd
// StartUnit method, receiving a real job object path back.
use serde::Deserialize;
use zbus::{proxy, zvariant::OwnedObjectPath, zvariant::Type, Connection};

/// One entry of systemd's `ListUnits`/`ListUnitsByPatterns` reply. The
/// field order and types are systemd's own documented `a(ssssssouso)`
/// struct -- name, description, load state, active state, sub state,
/// followed-unit, unit object path, queued job id, queued job type, job
/// object path. Field order is load-bearing: D-Bus structs are positional,
/// so a reordering here would silently read the wrong field. There is a
/// real wire-level round-trip test below that pins it.
///
/// Most of these fields are never read by ferrumd -- only `name` and
/// `active_state` are -- but every one of them must still be declared, in
/// this exact order and with these exact types, or the positional decode of
/// the fields that ARE read silently lands on the wrong data. That is what
/// `allow(dead_code)` is buying here: wire-format fidelity, not an unused
/// leftover. (ferrumd is a binary crate, so `pub` alone doesn't exempt
/// them.)
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Type)]
pub struct UnitStatus {
    pub name: String,
    pub description: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub following: String,
    pub unit_path: OwnedObjectPath,
    pub job_id: u32,
    pub job_type: String,
    pub job_path: OwnedObjectPath,
}

/// systemd's own `ActiveState` values that mean "this unit is doing
/// something right now". A `Type=oneshot` unit like `ferrum-apply@` sits in
/// `activating` for the whole of its ExecStart, so that is the state this
/// actually catches in practice; the others are included because a unit in
/// any of them has not finished. `inactive` and `failed` are the terminal
/// states -- a job in either is over.
fn is_running_state(active_state: &str) -> bool {
    matches!(
        active_state,
        "activating" | "active" | "reloading" | "deactivating"
    )
}

/// True if any of these units is still running.
pub fn any_unit_is_running(units: &[UnitStatus]) -> bool {
    units.iter().any(|u| is_running_state(&u.active_state))
}

#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
pub trait SystemdManager {
    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;

    /// Lists loaded units whose names match any of `patterns` (systemd
    /// applies fnmatch(3) to the unit name), optionally filtered to the
    /// given `states`. Not polkit-protected -- this is a read-only query
    /// any unprivileged caller may make, which is what lets ferrumd use it.
    fn list_units_by_patterns(
        &self,
        states: &[&str],
        patterns: &[&str],
    ) -> zbus::Result<Vec<UnitStatus>>;

    /// systemd's own documented gate on unit signals: "Signals are only
    /// sent out if at least one client invoked this method." Without it,
    /// the JobRemoved listener in main.rs can sit on a stream that never
    /// yields anything on a box where nothing else happens to have
    /// subscribed, and ferrumd's single-job interlock would then never
    /// clear. Not a polkit-protected action -- an unprivileged caller may
    /// subscribe.
    fn subscribe(&self) -> zbus::Result<()>;

    #[zbus(signal)]
    fn job_removed(&self, id: u32, job: OwnedObjectPath, unit: String, result: String) -> zbus::Result<()>;
}

/// The unit-name pattern every ferrumd-dispatched job runs under -- the
/// same `ferrum-apply@<uuid>.service` template the polkit rule in
/// modules/core/daemon.nix authorizes.
const FERRUM_APPLY_PATTERN: &str = "ferrum-apply@*.service";

/// Asks systemd -- the real, durable source of truth -- whether a
/// ferrum-apply job is running right now.
///
/// ferrumd's single-job interlock is an in-process `Mutex<bool>`, so it is
/// reset to `false` every time the process starts. That matters because an
/// `apply` job can switch to a generation containing a new ferrumd, which
/// restarts ferrumd *while its own job is still running*: the restarted
/// process would otherwise believe nothing is in flight and admit a second,
/// concurrent job. Seeding the flag from this query at startup closes that
/// window. It deliberately does not try to recover the running job's UUID
/// or reattach its progress stream -- the only guarantee being restored is
/// "refuse a new job while one is genuinely still running".
///
/// An empty `states` filter is passed on purpose: the state classification
/// lives in `is_running_state` here, where it is unit-tested, rather than
/// depending on systemd's own filter semantics matching what we mean.
pub async fn ferrum_apply_job_is_running() -> anyhow::Result<bool> {
    let connection = Connection::system().await?;
    let proxy = SystemdManagerProxy::new(&connection).await?;
    let units = proxy
        .list_units_by_patterns(&[], &[FERRUM_APPLY_PATTERN])
        .await
        .map_err(|e| anyhow::anyhow!("failed to query systemd for running ferrum-apply units: {e}"))?;
    Ok(any_unit_is_running(&units))
}

pub async fn start_ferrum_apply_unit(uuid: &str) -> anyhow::Result<()> {
    let connection = Connection::system().await?;
    let proxy = SystemdManagerProxy::new(&connection).await?;
    proxy
        .start_unit(&format!("ferrum-apply@{uuid}.service"), "replace")
        .await
        .map_err(|e| anyhow::anyhow!("failed to start ferrum-apply@{uuid}.service: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::zvariant::{serialized::Context, to_bytes, ObjectPath, LE};

    /// systemd's documented element type for ListUnitsByPatterns'
    /// `a(ssssssouso)` reply, spelled out as plain Rust primitives so the
    /// round-trip below encodes a genuine D-Bus message body rather than
    /// re-using the very struct it is trying to validate.
    type RawUnit = (
        String,
        String,
        String,
        String,
        String,
        String,
        OwnedObjectPath,
        u32,
        String,
        OwnedObjectPath,
    );

    fn path(p: &str) -> OwnedObjectPath {
        OwnedObjectPath::from(ObjectPath::try_from(p).unwrap())
    }

    fn raw_unit(name: &str, active_state: &str, sub_state: &str) -> RawUnit {
        (
            name.to_string(),
            "ferrum-apply, dispatched from a ferrumd-written request file".to_string(),
            "loaded".to_string(),
            active_state.to_string(),
            sub_state.to_string(),
            String::new(),
            path("/org/freedesktop/systemd1/unit/ferrum_2dapply_2eservice"),
            0,
            String::new(),
            path("/"),
        )
    }

    /// Encodes a reply body exactly as systemd would put it on the bus, then
    /// decodes it through the real `UnitStatus` type -- so a wrong field
    /// order or a wrong field type fails here rather than at runtime on a
    /// real box.
    fn decode(reply: Vec<RawUnit>) -> Vec<UnitStatus> {
        let ctxt = Context::new_dbus(LE, 0);
        let encoded = to_bytes(ctxt, &reply).expect("a realistic reply must encode");
        let (units, _): (Vec<UnitStatus>, _) =
            encoded.deserialize().expect("UnitStatus must match systemd's own wire type");
        units
    }

    #[test]
    fn unit_status_matches_systemds_documented_wire_signature() {
        assert_eq!(UnitStatus::signature().to_string(), "(ssssssouso)");
    }

    #[test]
    fn a_running_ferrum_apply_unit_is_recognised_in_a_realistic_reply() {
        let units = decode(vec![raw_unit(
            "ferrum-apply@6e2f7795-58c7-4654-82b6-f655b065ea47.service",
            // What a Type=oneshot unit really reports for the whole of its
            // ExecStart -- the state that actually matters here.
            "activating",
            "start",
        )]);
        assert_eq!(units.len(), 1);
        assert_eq!(
            units[0].name,
            "ferrum-apply@6e2f7795-58c7-4654-82b6-f655b065ea47.service"
        );
        assert_eq!(units[0].active_state, "activating");
        assert_eq!(units[0].load_state, "loaded");
        assert!(
            any_unit_is_running(&units),
            "a still-running apply must seed the interlock closed"
        );
    }

    #[test]
    fn finished_units_do_not_count_as_running() {
        let units = decode(vec![
            raw_unit("ferrum-apply@aaa.service", "inactive", "dead"),
            raw_unit("ferrum-apply@bbb.service", "failed", "failed"),
        ]);
        assert_eq!(units.len(), 2);
        assert!(
            !any_unit_is_running(&units),
            "units systemd has already finished must not wedge the daemon"
        );
    }

    #[test]
    fn a_finished_unit_alongside_a_running_one_still_counts_as_running() {
        let units = decode(vec![
            raw_unit("ferrum-apply@aaa.service", "inactive", "dead"),
            raw_unit("ferrum-apply@bbb.service", "activating", "start"),
        ]);
        assert!(any_unit_is_running(&units));
    }

    #[test]
    fn an_empty_reply_means_no_job_is_running() {
        assert!(!any_unit_is_running(&decode(vec![])));
    }

    #[test]
    fn every_state_systemd_can_report_is_classified_deliberately() {
        for state in ["activating", "active", "reloading", "deactivating"] {
            assert!(is_running_state(state), "{state} must count as running");
        }
        for state in ["inactive", "failed", "maintenance"] {
            assert!(!is_running_state(state), "{state} must not count as running");
        }
    }
}
