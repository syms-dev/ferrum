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
use zbus::{proxy, zvariant::OwnedObjectPath, Connection};

#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
pub trait SystemdManager {
    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;

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

pub async fn start_ferrum_apply_unit(uuid: &str) -> anyhow::Result<()> {
    let connection = Connection::system().await?;
    let proxy = SystemdManagerProxy::new(&connection).await?;
    proxy
        .start_unit(&format!("ferrum-apply@{uuid}.service"), "replace")
        .await
        .map_err(|e| anyhow::anyhow!("failed to start ferrum-apply@{uuid}.service: {e}"))?;
    Ok(())
}
