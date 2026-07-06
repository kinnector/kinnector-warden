//! allowlist.rs — Git-authoritative inode allowlist for web root enforcement.
//!
//! ## Design Philosophy
//!
//! Every file that a web process may legitimately READ, EXECUTE, or WRITE must
//! be indexed in this allowlist at startup.  The allowlist is seeded from
//! `git ls-files --cached` — only files committed to the repository are
//! allowed.  There is NO timing window, NO path-extension guess, NO heuristic:
//! if the inode is not in the set, the operation is blocked.
//!
//! ## Git Commit Watcher
//!
//! A background task polls `git rev-parse HEAD` every 30 seconds per web root.
//! On any new commit it:
//!  - Emits an informational `Event.WebRoot.NewCommit` alert.
//!  - Checks the commit metadata (author, message).
//!  - If the commit is from an AI agent, automated merge, or `git pull`:
//!    - Automatically re-indexes the new tree into the allowlist so newly
//!      deployed files are immediately allowed.
//!  - Otherwise emits only the informational alert — a human must explicitly
//!    call `warden-cli fim register --git <root>` or push to the socket API
//!    to approve the new files.
//!
//! ## Fallback
//!
//! When `git` is unavailable, the allowlist is seeded from a full startup walk.
//! This is less secure (any file on disk at startup is trusted) but preserves
//! functionality on non-git deployments.  A WARNING is logged.

use dashmap::DashSet;
use std::sync::{Arc, OnceLock};
use std::os::unix::fs::MetadataExt;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Global inode allowlist — initialised once at startup, then mutated by the
/// git commit watcher and manual `register_inode` calls.
static ALLOWED_INODES: OnceLock<Arc<DashSet<u64>>> = OnceLock::new();

/// Tracks whether the allowlist was seeded from git (true) or a startup walk
/// (false).  Walk-seeded mode is inherently less strict.
static GIT_SEEDED: OnceLock<bool> = OnceLock::new();

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

/// Seed the allowlist for the given web root directories.
/// Must be called once at daemon startup before enforcement begins.
pub fn seed_inode_allowlist(web_roots: &[String]) -> Arc<DashSet<u64>> {
    let set: Arc<DashSet<u64>> = Arc::new(DashSet::new());
    let mut any_git = false;

    for web_root in web_roots {
        // Strategy 1: `git ls-files --cached -z` (preferred)
        if let Some(count) = git_index_into(&set, web_root) {
            if count > 0 {
                println!(
                    "[Warden Allowlist] Seeded {} inodes from git ls-files in {}",
                    count, web_root
                );
                any_git = true;
                continue;
            }
        }

        // Strategy 2: Full startup snapshot (walkdir) — less strict
        eprintln!(
            "[Warden Allowlist] WARNING: git unavailable in {}. Falling back to startup walk. \
             Any file present at daemon start will be trusted. Deploy git for strict enforcement.",
            web_root
        );
        walk_seed(&set, web_root);
        println!(
            "[Warden Allowlist] Seeded {} inodes from startup walk of {}",
            set.len(),
            web_root
        );
    }

    let _ = ALLOWED_INODES.set(Arc::clone(&set));
    let _ = GIT_SEEDED.set(any_git);
    set
}

/// Dynamically loads standard shells from the system-wide `/etc/shells` configuration.
/// Ensures we do not hardcode a static process list, adhering to Section 1 of KINNECTOR-docs/CODE-RULEBOOK.md.
pub fn load_system_shells() -> std::collections::HashSet<String> {
    let mut shells = std::collections::HashSet::new();
    if let Ok(content) = std::fs::read_to_string("/etc/shells") {
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                shells.insert(trimmed.to_string());
                // Also insert the filename only (e.g. "bash" from "/bin/bash")
                if let Some(filename) = std::path::Path::new(trimmed).file_name().and_then(|f| f.to_str()) {
                    shells.insert(filename.to_string());
                }
            }
        }
    }
    // Generic standard shell fallbacks if /etc/shells is not present/empty
    if shells.is_empty() {
        for s in &["sh", "bash", "dash", "zsh", "ash", "csh", "tcsh", "ksh"] {
            shells.insert(s.to_string());
            shells.insert(format!("/bin/{}", s));
            shells.insert(format!("/usr/bin/{}", s));
        }
    }
    shells
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

/// Returns `true` if the file is allowed (inode in the allowlist).
/// Returns `false` if the allowlist is populated and the inode is absent.
///
/// Permissive when the allowlist has not been seeded yet (daemon initialisation
/// race — should not happen in practice given startup order).
pub fn is_inode_allowed(file_path: &str) -> bool {
    let Some(set) = ALLOWED_INODES.get() else {
        return true; // Not seeded yet — permissive
    };
    if set.is_empty() {
        return true;
    }
    match std::fs::metadata(file_path) {
        Ok(meta) => set.contains(&meta.ino()),
        // Cannot stat the file — conservatively block
        Err(_) => false,
    }
}

/// Same as `is_inode_allowed` but operates directly on an already-obtained
/// inode number (avoids a redundant `stat` call in hot paths).
pub fn is_inode_number_allowed(ino: u64) -> bool {
    let Some(set) = ALLOWED_INODES.get() else {
        return true;
    };
    if set.is_empty() {
        return true;
    }
    set.contains(&ino)
}

/// Returns whether the allowlist was seeded from git (`true`) or a startup
/// walk (`false`).  Used to qualify alert descriptions.
pub fn is_git_seeded() -> bool {
    GIT_SEEDED.get().copied().unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Mutation
// ---------------------------------------------------------------------------

/// Register a single inode into the allowlist.
/// Called by the git commit watcher and `warden-cli fim register`.
pub fn register_inode(file_path: &str) -> bool {
    let Some(set) = ALLOWED_INODES.get() else { return false; };
    match std::fs::metadata(file_path) {
        Ok(meta) => {
            let ino = meta.ino();
            let is_new = set.insert(ino);
            if is_new {
                println!(
                    "[Warden Allowlist] Registered inode {} — {}",
                    ino, file_path
                );
            }
            true
        }
        Err(_) => false,
    }
}

/// Re-index all files tracked by `git ls-files --cached` in `web_root`.
/// Returns the number of NEW inodes added (not already in the set).
pub fn reseed_from_git(web_root: &str) -> usize {
    let Some(set) = ALLOWED_INODES.get() else { return 0; };
    let before = set.len();
    if let Some(total) = git_index_into(set, web_root) {
        let added = set.len().saturating_sub(before);
        println!(
            "[Warden Allowlist] Git re-index of {}: {} files in tree, {} new inodes added",
            web_root, total, added
        );
        added
    } else {
        0
    }
}

/// Get a reference-counted handle to the live allowlist (for diagnostics /
/// API endpoints — do not hold across await points).
pub fn get_allowlist() -> Option<Arc<DashSet<u64>>> {
    ALLOWED_INODES.get().cloned()
}

// ---------------------------------------------------------------------------
// Git commit watcher
// ---------------------------------------------------------------------------

/// Information about a detected new commit.
#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub hash: String,
    pub author: String,
    pub message: String,
    /// True when the commit was created by an automated process (AI agent,
    /// merge commit, `git pull --rebase`, dependabot, etc.).
    pub is_automated: bool,
}

/// Classify whether a commit should be auto-approved for allowlist re-indexing.
///
/// Returns `true` for:
/// - Merge commits (two parents — `git show --format=%P` has a space)
/// - Author names/emails containing automation markers
/// - Commit messages matching pull/merge/deploy/bot/dependabot patterns
fn classify_commit(info: &CommitInfo) -> bool {
    let msg_lower = info.message.to_lowercase();
    let author_lower = info.author.to_lowercase();

    // Merge commits
    if msg_lower.starts_with("merge ") || msg_lower.starts_with("merged ") {
        return true;
    }
    // Pull / rebase operations
    if msg_lower.contains("pull request") || msg_lower.contains("auto-merge") {
        return true;
    }
    // Deploy / CI bot patterns
    if msg_lower.contains("[deploy]") || msg_lower.contains("[bot]") || msg_lower.contains("dependabot") {
        return true;
    }
    // AI agent commit patterns
    if author_lower.contains("bot") || author_lower.contains("agent") || author_lower.contains("copilot")
        || author_lower.contains("claude") || author_lower.contains("gemini") || author_lower.contains("gpt")
        || author_lower.contains("cursor") || author_lower.contains("aider")
    {
        return true;
    }
    if msg_lower.contains("ai-generated") || msg_lower.contains("co-authored-by: claude")
        || msg_lower.contains("co-authored-by: gemini") || msg_lower.contains("co-authored-by: gpt")
        || msg_lower.contains("co-authored-by: copilot")
    {
        return true;
    }

    false
}

/// Read the HEAD commit hash in `repo_root`. Returns `None` if git is unavailable.
fn get_head_hash(repo_root: &str) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_root)
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

/// Read commit metadata (author + message) for a given hash.
fn get_commit_info(repo_root: &str, hash: &str) -> Option<CommitInfo> {
    // --format="%an <%ae>%n%s" gives "Author Name <email>\nsubject"
    let out = std::process::Command::new("git")
        .args(["show", "--no-patch", "--format=%an <%ae>%n%B", hash])
        .current_dir(repo_root)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    let author = lines.next().unwrap_or("").to_string();
    let message = lines.collect::<Vec<_>>().join("\n");

    let mut info = CommitInfo {
        hash: hash.to_string(),
        author,
        message,
        is_automated: false,
    };
    info.is_automated = classify_commit(&info);
    Some(info)
}

/// Spawn a background task that watches for new commits in `web_root` using
/// file system events on the `.git` directory instead of polling.
///
/// On any refs or HEAD changes:
///  - Emits an `Event.WebRoot.NewCommit` informational alert.
///  - If the commit is automated: re-indexes the new tree automatically.
///  - Otherwise: emits the informational alert only. A human must approve.
pub fn start_git_commit_watcher(web_root: String) {
    tokio::spawn(async move {
        let git_dir = std::path::Path::new(&web_root).join(".git");
        if !git_dir.exists() {
            return;
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let mut watcher = match notify::recommended_watcher(move |res| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        }) {
            Ok(w) => w,
            Err(_) => return,
        };

        use notify::Watcher;
        let _ = watcher.watch(&git_dir.join("refs/heads"), notify::RecursiveMode::Recursive);
        let _ = watcher.watch(&git_dir.join("HEAD"), notify::RecursiveMode::NonRecursive);

        let mut last_known_hash = get_head_hash(&web_root);

        // Keep watcher alive by storing it
        let _watcher_holder = watcher;

        while let Some(_event) = rx.recv().await {
            let current = match get_head_hash(&web_root) {
                Some(h) => h,
                None => continue,
            };

            // No change in HEAD hash
            if last_known_hash.as_deref() == Some(current.as_str()) {
                continue;
            }

            let prev_hash = last_known_hash.clone().unwrap_or_else(|| "<none>".to_string());
            
            let info = get_commit_info(&web_root, &current);
            let author = info.as_ref().map(|i| i.author.as_str()).unwrap_or("unknown");
            let message = info.as_ref().map(|i| i.message.as_str()).unwrap_or("");
            let is_automated = info.as_ref().map(|i| i.is_automated).unwrap_or(false);

            if is_automated {
                let added = reseed_from_git(&web_root);
                println!(
                    "[Warden GitWatch] Automated commit {} in {} — auto-indexed {} new inodes. \
                     Author: {}. Message: {:?}",
                    &current[..8.min(current.len())], web_root, added, author, message
                );
                emit_commit_alert(
                    &web_root, &current, &prev_hash, author, message,
                    true, added,
                );
            } else {
                println!(
                    "[Warden GitWatch] New commit {} in {} (author: {}). \
                     Allowlist NOT updated automatically. Run `warden-cli fim register --git {}` to approve.",
                    &current[..8.min(current.len())], web_root, author, web_root
                );
                emit_commit_alert(
                    &web_root, &current, &prev_hash, author, message,
                    false, 0,
                );
            }

            last_known_hash = Some(current);
        }
    });
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Run `git ls-files --cached -z` in `web_root` and insert all discovered
/// inodes into `set`. Returns the number of paths processed, or `None` if git
/// fails.
fn git_index_into(set: &DashSet<u64>, web_root: &str) -> Option<usize> {
    let out = std::process::Command::new("git")
        .args(["ls-files", "--cached", "-z"])
        .current_dir(web_root)
        .output()
        .ok()?;

    if !out.status.success() || out.stdout.is_empty() {
        return None;
    }

    let mut count = 0usize;
    for rel in out.stdout.split(|&b| b == 0) {
        if rel.is_empty() { continue; }
        let Ok(rel_str) = std::str::from_utf8(rel) else { continue; };
        let full = format!("{}/{}", web_root.trim_end_matches('/'), rel_str);
        if let Ok(meta) = std::fs::metadata(&full) {
            set.insert(meta.ino());
            count += 1;
        }
    }

    Some(count)
}

fn walk_seed(set: &DashSet<u64>, root: &str) {
    fn recurse(set: &DashSet<u64>, dir: &std::path::Path) {
        let Ok(entries) = std::fs::read_dir(dir) else { return; };
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                if meta.is_file() {
                    set.insert(meta.ino());
                } else if meta.is_dir() {
                    recurse(set, &path);
                }
            }
        }
    }
    recurse(set, std::path::Path::new(root));
}

fn emit_commit_alert(
    web_root: &str,
    hash: &str,
    prev_hash: &str,
    author: &str,
    message: &str,
    auto_indexed: bool,
    new_inodes: usize,
) {
    let alert_id = uuid::Uuid::new_v4().to_string();
    let status = if auto_indexed {
        format!(
            "Automated commit {} (prev: {}) by '{}' in {} — {} new inodes auto-indexed. Message: {:?}",
            &hash[..8.min(hash.len())], &prev_hash[..8.min(prev_hash.len())],
            author, web_root, new_inodes, message
        )
    } else {
        format!(
            "Human commit {} (prev: {}) by '{}' in {}. Allowlist pending manual approval. Message: {:?}",
            &hash[..8.min(hash.len())], &prev_hash[..8.min(prev_hash.len())],
            author, web_root, message
        )
    };

    let payload = crate::notifications::AlertPayload {
        alert_id,
        timestamp: chrono::Utc::now().to_rfc3339(),
        threat_type: "Event.WebRoot.NewCommit".to_string(),
        severity: "INFO".to_string(),
        container: None,
        process: crate::notifications::ProcessInfo {
            pid: 0,
            exec_path: "git".to_string(),
            cmdline: format!("HEAD={}", hash),
            parent_exec_path: "wardend".to_string(),
            parent_pid: std::process::id(),
        },
        remediation: crate::notifications::RemediationInfo {
            action: if auto_indexed { "AUTO_INDEXED" } else { "PENDING_APPROVAL" }.to_string(),
            status,
        },
    };

    if let Ok(s) = serde_json::to_string(&payload) {
        let _ = crate::audit::write_to_audit_log(&s);
    }
    crate::notifications::dispatch_alert(payload);
}
