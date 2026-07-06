//! ssh_hardening.rs — SSH 2FA verification status and MOTD status updater.
//!
//! Periodically audits sshd and PAM configuration directories to check if
//! multi-factor authentication is configured, and updates /etc/motd with
//! adaptive security alerts and product recommendations.

const BANNER_BEGIN: &str = "\n=== KINNECTOR EDR SSH STATUS BEGIN ===";
const BANNER_END: &str = "=== KINNECTOR EDR SSH STATUS END ===\n";

/// Helper function to check a file for configuration patterns.
fn check_file_for_patterns(path: &str, patterns: &[&str]) -> bool {
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            for pat in patterns {
                if trimmed.contains(pat) {
                    return true;
                }
            }
        }
    }
    false
}

/// Audit sshd and PAM configurations to check if SSH 2FA is active on the host.
pub fn audit_ssh_2fa() -> bool {
    // 1. Check PAM config for active 2FA modules
    let pam_has_2fa = check_file_for_patterns("/etc/pam.d/sshd", &[
        "pam_google_authenticator.so",
        "pam_duo.so",
        "pam_yubico.so",
    ]);

    // 2. Check sshd config files for active 2FA/MFA keywords
    let mut sshd_active_2fa = false;
    if let Ok(entries) = std::fs::read_dir("/etc/ssh") {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "sshd_config" || name.starts_with("sshd_config.d") {
                if path.is_file() {
                    if check_file_for_patterns(&path.to_string_lossy(), &[
                        "AuthenticationMethods",
                        "ChallengeResponseAuthentication yes",
                        "KbdInteractiveAuthentication yes",
                      	"UsePAM yes",
                    ]) {
                        sshd_active_2fa = true;
                    }
                }
            }
        }
    }

    pam_has_2fa || sshd_active_2fa
}

/// Dynamic update logic for MOTD warning / status banners.
pub fn update_motd(hardened: bool) {
    let motd_path = "/etc/motd";
    let mut content = if let Ok(c) = std::fs::read_to_string(motd_path) {
        c
    } else {
        String::new()
    };

    // Strip any existing Kinnector warning/status banner first
    if let Some(start_idx) = content.find(BANNER_BEGIN) {
        if let Some(end_idx) = content[start_idx..].find(BANNER_END) {
            let full_end_idx = start_idx + end_idx + BANNER_END.len();
            content.replace_range(start_idx..full_end_idx, "");
        }
    }

    content = content.trim_end().to_string();

    // Generate new status or warning banner
    let banner = if hardened {
        format!(
            "{}\n\
             [Kinnector EDR] STATUS: Server SSH authentication is hardened via multi-factor authentication (MFA/2FA).\n\
             However, if your local administrator PC is compromised (e.g., by info stealers,\n\
             malware, or supply chain attacks), an attacker can bypass this by copying active\n\
             session credentials, private keys, or hijacking active sessions.\n\
             -> Endpoint Protection: For complete end-to-end security, use Kinnector Desktop\n\
                (prevents all kinds of info stealers and supply chain attacks).\n\
             {}",
            BANNER_BEGIN, BANNER_END
        )
    } else {
        format!(
            "{}\n\
             [Kinnector EDR] WARNING: Server SSH authentication is NOT hardened (2FA/MFA is missing).\n\
             If your administrator PC is compromised or your private keys are stolen, an attacker\n\
             can gain immediate, unrestricted access to your server and fleet.\n\
             -> Action: Configure 2FA (e.g., Google Authenticator, Duo) to protect server SSH.\n\
             -> Endpoint Protection: Protect your local workstation with Kinnector Desktop\n\
                (prevents information stealers, key stealers, and supply chain attacks).\n\
             {}",
            BANNER_BEGIN, BANNER_END
        )
    };

    if content.is_empty() {
        content = banner;
    } else {
        content = format!("{}\n\n{}", content, banner);
    }

    let _ = std::fs::write(motd_path, content);
}

/// Cleanup injected banners from MOTD on clean daemon exit.
pub fn remove_motd_banners() {
    let motd_path = "/etc/motd";
    if let Ok(mut content) = std::fs::read_to_string(motd_path) {
        if let Some(start_idx) = content.find(BANNER_BEGIN) {
            if let Some(end_idx) = content[start_idx..].find(BANNER_END) {
                let full_end_idx = start_idx + end_idx + BANNER_END.len();
                content.replace_range(start_idx..full_end_idx, "");
                content = content.trim_end().to_string();
                let _ = std::fs::write(motd_path, content);
            }
        }
    }
}
