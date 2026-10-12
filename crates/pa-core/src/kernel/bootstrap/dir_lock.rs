//! Cross-process bootstrap lock for the kernel venv: a `link(2)`-published
//! lock file whose owner is a live process (pid plus start id, so a recycled
//! pid never reads as the owner); stale locks are renamed aside, verified,
//! then reclaimed.

use std::io::Write;
use std::path::{Path, PathBuf};

use super::venv::{
    BOOTSTRAP_LOCK_NAME, BOOTSTRAP_LOCK_RETRY_MS, BOOTSTRAP_LOCK_STALE_WITHOUT_PID_MS,
};

fn is_process_alive(pid: u32) -> bool {
    crate::platform::process::pid_exists(pid)
}

/// The lock owner: `{pid, processStartId}`, the identity update artifacts
/// record. A pid-only lock (TS, earlier Rust builds) has no start id.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LockOwner {
    pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process_start_id: Option<String>,
}

fn parse_lock_owner(raw: &str) -> Option<LockOwner> {
    if let Some(pid) = strict_pid(Some(raw)) {
        return Some(LockOwner {
            pid,
            process_start_id: None,
        });
    }
    serde_json::from_str::<LockOwner>(raw.trim())
        .ok()
        .filter(|owner| owner.pid > 0)
}

/// A live owner: the pid exists and still carries the recorded start id. A
/// recycled pid carries another one; an unreadable start id keeps the lock.
fn is_owner_alive(owner: &LockOwner) -> bool {
    if !is_process_alive(owner.pid) {
        return false;
    }
    match (
        &owner.process_start_id,
        pa_types::platform::process::process_start_id(owner.pid),
    ) {
        (Some(recorded), Some(current)) => *recorded == current,
        _ => true,
    }
}

/// A `link(2)`-published lock file: born with owner content, EEXIST the only
/// collision signal.
pub(crate) enum DirLockAttempt {
    Acquired,
    Held,
    Reclaimed,
}

fn strict_pid(raw: Option<&str>) -> Option<u32> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() || !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let parsed: u32 = trimmed.parse().ok()?;
    (parsed > 0).then_some(parsed)
}

fn try_acquire_dir_lock(lock_path: &Path) -> anyhow::Result<DirLockAttempt> {
    std::fs::create_dir_all(lock_path.parent().unwrap_or(Path::new("/")))?;
    let token = format!("{}-{}", std::process::id(), uuid::Uuid::new_v4());
    let temp_path = lock_path.with_file_name(format!(
        "{}.candidate-{}",
        lock_path.file_name().unwrap_or_default().to_string_lossy(),
        token
    ));
    {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);
        crate::platform::perms::set_private_mode(&mut options);
        let mut file = options.open(&temp_path)?;
        let pid = std::process::id();
        let owner = LockOwner {
            pid,
            process_start_id: pa_types::platform::process::process_start_id(pid),
        };
        writeln!(file, "{}", serde_json::to_string(&owner)?)?;
    }
    // The primary signal: link() publishing the candidate under the lock path.
    if std::fs::hard_link(&temp_path, lock_path).is_ok() {
        let _ = std::fs::remove_file(&temp_path);
        return Ok(DirLockAttempt::Acquired);
    }
    // Judge the incumbent: dead owner (or no owner readable) means stale.
    let judge = match std::fs::read_to_string(lock_path) {
        Ok(raw) => parse_lock_owner(&raw),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let _ = std::fs::remove_file(&temp_path);
            return Ok(DirLockAttempt::Reclaimed);
        }
        Err(error) if error.kind() == std::io::ErrorKind::IsADirectory => {
            // Legacy directory lock from the old protocol.
            let pid_file = lock_path.join("pid");
            match std::fs::read_to_string(pid_file) {
                Ok(raw) => parse_lock_owner(&raw),
                Err(_) => None,
            }
        }
        Err(_) => None,
    };
    let stale = match judge {
        None => lock_missing_pid_is_stale(lock_path),
        Some(owner) => !is_owner_alive(&owner),
    };
    let result = if stale {
        let aside_path = lock_path.with_file_name(format!(
            "{}.stale-{}",
            lock_path.file_name().unwrap_or_default().to_string_lossy(),
            token
        ));
        match std::fs::rename(lock_path, &aside_path) {
            Ok(()) => {
                if std::fs::remove_file(&aside_path).is_ok() {
                    DirLockAttempt::Reclaimed
                } else {
                    DirLockAttempt::Held
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => DirLockAttempt::Reclaimed,
            Err(_) => DirLockAttempt::Held,
        }
    } else {
        DirLockAttempt::Held
    };
    let _ = std::fs::remove_file(&temp_path);
    Ok(result)
}

fn lock_missing_pid_is_stale(lock_path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(lock_path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    std::time::SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age.as_millis() as u64 > BOOTSTRAP_LOCK_STALE_WITHOUT_PID_MS)
}

/// Serialize concurrent bootstraps across processes on the same venv.
pub(crate) async fn acquire_bootstrap_lock(venv: &Path) -> anyhow::Result<impl Drop> {
    let lock_dir = venv.with_file_name(format!(
        "{}{}",
        venv.file_name().unwrap_or_default().to_string_lossy(),
        BOOTSTRAP_LOCK_NAME
    ));
    std::fs::create_dir_all(lock_dir.parent().unwrap_or(Path::new("/")))?;
    loop {
        match try_acquire_dir_lock(&lock_dir)? {
            DirLockAttempt::Acquired => {
                struct Guard(PathBuf);
                impl Drop for Guard {
                    fn drop(&mut self) {
                        let _ = std::fs::remove_file(&self.0);
                    }
                }
                return Ok(Guard(lock_dir));
            }
            DirLockAttempt::Held | DirLockAttempt::Reclaimed => {
                tokio::time::sleep(std::time::Duration::from_millis(BOOTSTRAP_LOCK_RETRY_MS)).await;
            }
        }
    }
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;

    fn own_start_id() -> String {
        pa_types::platform::process::process_start_id(std::process::id())
            .expect("this platform records process start ids")
    }

    /// A killed bootstrap's lock whose pid now belongs to another live process
    /// (this one, under a start id it never had) must not block the next
    /// bootstrap forever.
    #[tokio::test]
    async fn a_recycled_pid_lock_no_longer_blocks_the_bootstrap() {
        let dir = tempfile::tempdir().unwrap();
        let venv = dir.path().join("kernel-venv");
        let lock = dir.path().join(format!("kernel-venv{BOOTSTRAP_LOCK_NAME}"));
        let recycled = serde_json::json!({
            "pid": std::process::id(),
            "processStartId": "start-id-of-the-killed-owner",
        });
        std::fs::write(&lock, recycled.to_string()).unwrap();
        let guard = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            acquire_bootstrap_lock(&venv),
        )
        .await
        .expect("a recycled pid must not hold the lock")
        .unwrap();
        assert!(parse_lock_owner(&std::fs::read_to_string(&lock).unwrap())
            .is_some_and(|owner| owner.process_start_id == Some(own_start_id())));
        drop(guard);
        assert!(!lock.exists());
    }

    #[test]
    fn a_lock_whose_pid_keeps_its_start_id_stays_held() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("lock");
        let owner = serde_json::json!({
            "pid": std::process::id(),
            "processStartId": own_start_id(),
        });
        std::fs::write(&lock, owner.to_string()).unwrap();
        assert!(matches!(
            try_acquire_dir_lock(&lock).unwrap(),
            DirLockAttempt::Held
        ));
        assert!(lock.exists());
    }

    /// A pid-only lock (TS, earlier Rust builds) keeps the liveness rule.
    #[test]
    fn a_pid_only_lock_naming_a_live_process_stays_held() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("lock");
        std::fs::write(&lock, format!("{}\n", std::process::id())).unwrap();
        assert!(matches!(
            try_acquire_dir_lock(&lock).unwrap(),
            DirLockAttempt::Held
        ));
        assert!(lock.exists());
    }
}
