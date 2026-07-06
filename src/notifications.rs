use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use dashmap::DashMap;

static DISPATCH_DEDUP: OnceLock<Arc<DashMap<String, i64>>> = OnceLock::new();
const DEDUP_WINDOW_SECS: i64 = 300; // 5 minutes

/// B-09 fix: Emit a one-time warning if notifications.json is absent so operators
/// are not silently left wondering why webhooks aren't firing.
static NOTIF_CONFIG_WARNED: OnceLock<()> = OnceLock::new();

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlackConfig {
    pub enabled: bool,
    pub webhook_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiscordConfig {
    pub enabled: bool,
    pub webhook_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub bot_token: String,
    pub chat_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenericWebhookConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub headers: Option<std::collections::HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NotificationSettings {
    pub slack: Option<SlackConfig>,
    pub discord: Option<DiscordConfig>,
    pub telegram: Option<TelegramConfig>,
    #[serde(rename = "generic_webhook")]
    pub generic_webhook: Option<GenericWebhookConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NotificationConfig {
    pub notifications: NotificationSettings,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AlertPayload {
    pub alert_id: String,
    pub timestamp: String,
    pub threat_type: String,
    pub severity: String,
    pub container: Option<ContainerInfo>,
    pub process: ProcessInfo,
    pub remediation: RemediationInfo,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub exec_path: String,
    pub cmdline: String,
    pub parent_exec_path: String,
    pub parent_pid: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemediationInfo {
    pub action: String,
    pub status: String,
}

pub async fn load_notification_config() -> Option<NotificationConfig> {
    let path = Path::new("/etc/kinnector/notifications.json");
    if !path.exists() {
        return None;
    }
    if let Ok(content) = std::fs::read_to_string(path) {
        if let Ok(config) = serde_json::from_str::<NotificationConfig>(&content) {
            return Some(config);
        }
    }
    None
}

pub fn dispatch_alert(payload: AlertPayload) {
    if let Ok(s) = serde_json::to_string(&payload) {
        let _ = crate::audit::write_to_audit_log(&s);
        crate::cloud::queue_log_entry(&s);
    }
    crate::cloud::send_alert_immediate(&payload);

    tokio::spawn(async move {
        // Dedup: skip if same (threat_type, pid) fired within 5 min
        let dedup_key = format!("{}:{}", payload.threat_type, payload.process.pid);
        let now = chrono::Utc::now().timestamp();
        let dedup = DISPATCH_DEDUP.get_or_init(|| Arc::new(DashMap::new()));
        if let Some(last) = dedup.get(&dedup_key) {
            if now - *last < DEDUP_WINDOW_SECS {
                return;
            }
        }
        dedup.insert(dedup_key, now);

        let config = match load_notification_config().await {
            Some(c) => c,
            None => {
                // B-09 fix: warn once instead of silently returning
                NOTIF_CONFIG_WARNED.get_or_init(|| {
                    eprintln!(
                        "[Warden Notifications] WARNING: /etc/kinnector/notifications.json not found. \
                         Webhook dispatch is disabled. Create the file to enable Slack/Discord/Telegram alerts."
                    );
                });
                return;
            }
        };
        let client = reqwest::Client::new();

        // 1. Slack dispatch
        if let Some(slack) = config.notifications.slack {
            if slack.enabled && !slack.webhook_url.is_empty() {
                let slack_body = serde_json::json!({
                    "text": format!(
                        "🚨 *[Kinnector EDR Alert]*\n*Threat*: `{}`\n*Severity*: `{}`\n*PID*: `{}`\n*Executable*: `{}`\n*Cmdline*: `{}`\n*Action*: `{}` ({})",
                        payload.threat_type, payload.severity, payload.process.pid, payload.process.exec_path, payload.process.cmdline, payload.remediation.action, payload.remediation.status
                    )
                });
                let _ = client.post(&slack.webhook_url).json(&slack_body).send().await;
            }
        }

        // 2. Discord dispatch
        if let Some(discord) = config.notifications.discord {
            if discord.enabled && !discord.webhook_url.is_empty() {
                let discord_body = serde_json::json!({
                    "content": format!(
                        "💥 **[Kinnector EDR Alert]**\n**Threat**: `{}`\n**Severity**: `{}`\n**Executable**: `{}`\n**Action**: `{}`",
                        payload.threat_type, payload.severity, payload.process.exec_path, payload.remediation.action
                    )
                });
                let _ = client.post(&discord.webhook_url).json(&discord_body).send().await;
            }
        }

        // 3. Telegram dispatch
        if let Some(telegram) = config.notifications.telegram {
            if telegram.enabled && !telegram.bot_token.is_empty() && !telegram.chat_id.is_empty() {
                let tg_url = format!("https://api.telegram.org/bot{}/sendMessage", telegram.bot_token);
                let tg_body = serde_json::json!({
                    "chat_id": telegram.chat_id,
                    "text": format!(
                        "⚠️ [Kinnector Alert]\nThreat: {}\nSeverity: {}\nPath: {}\nAction: {}",
                        payload.threat_type, payload.severity, payload.process.exec_path, payload.remediation.action
                    )
                });
                let _ = client.post(&tg_url).json(&tg_body).send().await;
            }
        }

        // 4. Generic Webhook dispatch
        if let Some(generic) = config.notifications.generic_webhook {
            if generic.enabled && !generic.endpoint.is_empty() {
                let mut req = client.post(&generic.endpoint).json(&payload);
                if let Some(headers) = generic.headers {
                    for (k, v) in headers {
                        req = req.header(k, v);
                    }
                }
                let _ = req.send().await;
            }
        }
    });
}
