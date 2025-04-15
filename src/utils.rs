use std::time::{SystemTime, UNIX_EPOCH};

pub fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn format_rate_limit_key(prefix: &str, key: &str) -> String {
    format!("{}:{}", prefix, key)
} 