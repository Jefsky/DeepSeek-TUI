//! Append arity-typed allow prefixes to `execpolicy.toml` when the user chooses
//! "approve for this session" for `exec_shell` (#1186).

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use fd_lock::RwLock;
use serde_json::json;

use super::rules::{ExecPolicyConfig, ExecPolicyDecision, default_execpolicy_path};

/// TOML group for rules learned from approval UI (session-wide approve).
pub const USER_APPROVED_GROUP: &str = "user_approved";

fn normalize_rule_key(pattern: &str) -> String {
    pattern
        .trim()
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Canonical typed allow prefix for `command` (same semantics as rule evaluation).
pub fn typed_allow_pattern(command: &str) -> String {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    crate::command_safety::classify_command(&tokens)
}

fn allow_list_has_normalized(config: &ExecPolicyConfig, norm: &str) -> bool {
    for rs in config.rules.values() {
        for existing in &rs.allow {
            if normalize_rule_key(existing) == norm {
                return true;
            }
        }
    }
    false
}

/// When the user approves `exec_shell` for the session, persist a typed allow
/// prefix to `~/.deepseek/execpolicy.toml` so future runs match
/// [`ExecPolicyDecision::Allow`] without a new rule there.
///
/// Returns `Ok(Some(pattern))` when a new rule was written, `Ok(None)` when
/// nothing was added (already allowed, duplicate, empty command, or no home dir).
pub fn persist_session_approved_shell_command(command: &str) -> Result<Option<String>> {
    let Some(policy_path) = default_execpolicy_path() else {
        return Ok(None);
    };
    persist_session_approved_shell_command_at(&policy_path, command)
}

pub(crate) fn persist_session_approved_shell_command_at(
    policy_path: &Path,
    command: &str,
) -> Result<Option<String>> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if let Some(parent) = policy_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| parent.display().to_string())?;
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(policy_path)
        .with_context(|| format!("open {}", policy_path.display()))?;
    let mut lock = RwLock::new(file);
    let mut guard = lock
        .write()
        .map_err(|e| anyhow::anyhow!("execpolicy.toml lock: {e}"))?;

    let mut contents = String::new();
    guard.seek(SeekFrom::Start(0))?;
    guard.read_to_string(&mut contents)?;

    let mut config: ExecPolicyConfig = if contents.trim().is_empty() {
        ExecPolicyConfig::default()
    } else {
        toml::from_str(&contents).with_context(|| format!("parse {}", policy_path.display()))?
    };

    if !matches!(config.evaluate(trimmed), ExecPolicyDecision::AskUser(_)) {
        return Ok(None);
    }

    let pattern = typed_allow_pattern(trimmed);
    if pattern.is_empty() {
        return Ok(None);
    }

    let norm = normalize_rule_key(&pattern);
    if allow_list_has_normalized(&config, &norm) {
        return Ok(None);
    }

    config
        .rules
        .entry(USER_APPROVED_GROUP.to_string())
        .or_default()
        .allow
        .push(pattern.clone());

    let serialized = toml::to_string_pretty(&config)
        .with_context(|| format!("serialize {}", policy_path.display()))?;
    guard.seek(SeekFrom::Start(0))?;
    guard
        .set_len(0)
        .with_context(|| format!("truncate {}", policy_path.display()))?;
    guard.write_all(serialized.as_bytes())?;
    guard.flush()?;

    crate::audit::log_sensitive_event(
        "tool.execpolicy.persisted",
        json!({
            "pattern": pattern,
            "path": policy_path.display().to_string(),
        }),
    );

    Ok(Some(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tempfile::tempdir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn persists_typed_prefix_and_skips_duplicate() {
        let _g = ENV_LOCK.lock().expect("lock");
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("execpolicy.toml");

        let first = persist_session_approved_shell_command_at(&path, "cargo check --workspace")
            .expect("first persist");
        assert_eq!(first.as_deref(), Some("cargo check"));

        let parsed = ExecPolicyConfig::from_path(&path).expect("parse written");
        assert!(matches!(
            parsed.evaluate("cargo check --all-targets"),
            ExecPolicyDecision::Allow
        ));

        let second = persist_session_approved_shell_command_at(&path, "cargo check")
            .expect("second persist");
        assert!(second.is_none());
    }

    #[test]
    fn skips_when_already_covered_by_existing_allow() {
        let _g = ENV_LOCK.lock().expect("lock");
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("execpolicy-seeded.toml");
        std::fs::write(
            &path,
            r#"[rules.cargo]
allow = ["cargo check"]
deny = []
"#,
        )
        .expect("seed policy");

        let r =
            persist_session_approved_shell_command_at(&path, "cargo check -q").expect("persist");
        assert!(r.is_none());
    }
}
