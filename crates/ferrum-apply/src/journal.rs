use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JournalEntry {
    pub snapshot: String,
    pub generation: u32,
    pub toplevel: String,
    pub taken_at: String,
    pub quiesced: bool,
}

pub fn snapshot_name(unix_ts: u64, generation: u32) -> String {
    format!("{unix_ts}-gen{generation}")
}

pub fn write(journal_dir: &Path, entry: &JournalEntry) -> anyhow::Result<()> {
    std::fs::create_dir_all(journal_dir)?;
    let path = journal_dir.join(format!("{}.json", entry.snapshot));
    let tmp_path = journal_dir.join(format!("{}.json.tmp", entry.snapshot));
    std::fs::write(&tmp_path, serde_json::to_string_pretty(entry)?)?;
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

// read/list have no caller yet within this task -- restore_state.rs and
// rollback.rs (this plan's Tasks 6/7) and generations.rs (Task 5) are their
// first real consumers. clippy's default (non-`--tests`) pass only sees
// this crate's non-test call graph from main(), so without the allow it
// flags both as dead code between now and whichever task lands first.
#[allow(dead_code)]
pub fn read(journal_dir: &Path, snapshot: &str) -> anyhow::Result<JournalEntry> {
    let path = journal_dir.join(format!("{snapshot}.json"));
    let content = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("no journal entry for {snapshot}: {e}"))?;
    Ok(serde_json::from_str(&content)?)
}

#[allow(dead_code)]
pub fn list(journal_dir: &Path) -> anyhow::Result<Vec<JournalEntry>> {
    if !journal_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for f in std::fs::read_dir(journal_dir)? {
        let f = f?;
        if f.path().extension().and_then(|e| e.to_str()) == Some("json") {
            let content = std::fs::read_to_string(f.path())?;
            entries.push(serde_json::from_str(&content)?);
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_reads_back_identically() {
        let dir = tempfile::tempdir().unwrap();
        let entry = JournalEntry {
            snapshot: "1770000000-gen42".to_string(),
            generation: 42,
            toplevel: "/nix/store/abc-nixos-system-test".to_string(),
            taken_at: "2026-08-20T00:00:00Z".to_string(),
            quiesced: true,
        };
        write(dir.path(), &entry).unwrap();
        let read_back = read(dir.path(), "1770000000-gen42").unwrap();
        assert_eq!(read_back.generation, 42);
        assert_eq!(read_back.toplevel, "/nix/store/abc-nixos-system-test");
        assert!(read_back.quiesced);
    }

    #[test]
    fn reading_a_missing_entry_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(dir.path(), "does-not-exist").is_err());
    }

    #[test]
    fn snapshot_name_embeds_timestamp_and_generation() {
        let name = snapshot_name(1770000000, 42);
        assert_eq!(name, "1770000000-gen42");
    }
}
