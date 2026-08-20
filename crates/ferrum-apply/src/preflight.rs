use std::path::Path;

pub fn check_free_space(path: &Path, min_gib: u64) -> anyhow::Result<()> {
    let stat = rustix::fs::statvfs(path)?;
    let free_bytes = stat.f_bavail as u64 * stat.f_frsize as u64;
    let free_gib = free_bytes / (1024 * 1024 * 1024);
    if free_gib < min_gib {
        anyhow::bail!(
            "not enough free space at {}: {free_gib} GiB free, {min_gib} GiB required",
            path.display()
        );
    }
    Ok(())
}

pub fn check_is_subvolume(path: &Path) -> anyhow::Result<()> {
    let output = std::process::Command::new("btrfs")
        .args(["subvolume", "show"])
        .arg(path)
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "{} is not a btrfs subvolume: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub fn run(state_dir: &Path, snapshot_dir: &Path, min_free_gib: u64) -> anyhow::Result<()> {
    check_free_space(state_dir, min_free_gib)?;
    check_is_subvolume(state_dir)?;
    check_is_subvolume(snapshot_dir)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_space_check_passes_when_plenty_free() {
        let dir = tempfile::tempdir().unwrap();
        // The temp dir's filesystem almost certainly has at least 1 MiB free.
        check_free_space(dir.path(), 0).unwrap();
    }

    #[test]
    fn free_space_check_fails_when_requirement_is_absurd() {
        let dir = tempfile::tempdir().unwrap();
        // No real filesystem has an exbibyte free.
        let err = check_free_space(dir.path(), 1_000_000_000).unwrap_err();
        assert!(err.to_string().contains("free space"));
    }

    #[test]
    fn is_subvolume_check_fails_on_a_plain_directory() {
        let dir = tempfile::tempdir().unwrap();
        // A plain tempdir is never a btrfs subvolume.
        let err = check_is_subvolume(dir.path()).unwrap_err();
        assert!(err.to_string().contains("not a btrfs subvolume"));
    }
}
