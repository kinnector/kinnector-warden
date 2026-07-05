//! allowlist.rs — Immutable inode allowlist for the web root.
//!
//! At daemon startup, we seed a DashSet<u64> of all inodes that legitimately
//! belong to the web root (git-seeded first, startup-walk fallback).
//! Any file whose inode is NOT in this set must not be executed by web
//! context processes — doing so indicates RFI / webshell execution.

use dashmap::DashSet;
use std::sync::{Arc, OnceLock};
use std::os::unix::fs::MetadataExt;

/// Global inode allowlist — initialised once at startup.
static ALLOWED_INODES: OnceLock<Arc<DashSet<u64>>> = OnceLock::new();

/// Seed the allowlist for the given web root directory.
/// Strategy 1: `git ls-files --cached` (preferred — only committed files).
/// Strategy 2: Walk the directory tree (fallback when git is unavailable).
pub fn seed_inode_allowlist(web_root: &str) -> Arc<DashSet<u64>> {
    let set: Arc<DashSet<u64>> = Arc::new(DashSet::new());

    // Strategy 1: git ls-files --cached
    let git_output = std::process::Command::new("git")
        .args(["ls-files", "--cached", "-z"])
        .current_dir(web_root)
        .output();

    if let Ok(output) = git_output {
        if output.status.success() && !output.stdout.is_empty() {
            // NUL-separated list of relative paths
            for rel_path in output.stdout.split(|&b| b == 0) {
                if rel_path.is_empty() { continue; }
                let rel_str = match std::str::from_utf8(rel_path) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let full_path = format!("{}/{}", web_root.trim_end_matches('/'), rel_str);
                if let Ok(meta) = std::fs::metadata(&full_path) {
                    set.insert(meta.ino());
                }
            }

            if !set.is_empty() {
                println!("[Warden Allowlist] Seeded {} inodes from git ls-files in {}", set.len(), web_root);
                let arc = Arc::clone(&set);
                let _ = ALLOWED_INODES.set(arc);
                return set;
            }
        }
    }

    // Strategy 2: full startup snapshot (walkdir)
    walk_seed(&set, web_root);
    println!("[Warden Allowlist] Seeded {} inodes from startup walk of {}", set.len(), web_root);
    let arc = Arc::clone(&set);
    let _ = ALLOWED_INODES.set(arc);
    set
}

fn walk_seed(set: &DashSet<u64>, root: &str) {
    fn recurse(set: &DashSet<u64>, dir: &std::path::Path) {
        let read_dir = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => return,
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            if let Ok(meta) = std::fs::metadata(&path) {
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

/// Returns a reference to the global allowlist.
/// Returns None if `seed_inode_allowlist` has not been called yet.
pub fn get_allowlist() -> Option<Arc<DashSet<u64>>> {
    ALLOWED_INODES.get().cloned()
}

/// Check if a given file path's inode is in the allowlist.
/// Returns true (allowed) if: allowlist is empty OR inode is registered.
/// Returns false (blocked) if: allowlist is populated AND inode is absent.
pub fn is_inode_allowed(file_path: &str) -> bool {
    let Some(set) = ALLOWED_INODES.get() else {
        return true; // Not seeded yet — permissive by default
    };
    if set.is_empty() {
        return true;
    }
    if let Ok(meta) = std::fs::metadata(file_path) {
        set.contains(&meta.ino())
    } else {
        // Can't stat the file — conservatively block
        false
    }
}

/// Register a new inode into the allowlist (used by warden-cli fim register).
pub fn register_inode(file_path: &str) -> bool {
    let Some(set) = ALLOWED_INODES.get() else {
        return false;
    };
    if let Ok(meta) = std::fs::metadata(file_path) {
        use std::os::unix::fs::MetadataExt;
        set.insert(meta.ino());
        println!("[Warden Allowlist] Manually registered inode {} for {}", meta.ino(), file_path);
        true
    } else {
        false
    }
}

/// Re-seed from git (called by warden-cli fim register --git).
pub fn reseed_from_git(web_root: &str) {
    let Some(set) = ALLOWED_INODES.get() else {
        return;
    };
    let git_output = std::process::Command::new("git")
        .args(["ls-files", "--cached", "-z"])
        .current_dir(web_root)
        .output();

    if let Ok(output) = git_output {
        if output.status.success() {
            let mut count = 0usize;
            for rel_path in output.stdout.split(|&b| b == 0) {
                if rel_path.is_empty() { continue; }
                if let Ok(rel_str) = std::str::from_utf8(rel_path) {
                    let full = format!("{}/{}", web_root.trim_end_matches('/'), rel_str);
                    if let Ok(meta) = std::fs::metadata(&full) {
                        use std::os::unix::fs::MetadataExt;
                        set.insert(meta.ino());
                        count += 1;
                    }
                }
            }
            println!("[Warden Allowlist] Re-seeded {} inodes from git in {}", count, web_root);
        }
    }
}
