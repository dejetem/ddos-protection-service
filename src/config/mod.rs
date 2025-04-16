//! Configuration management for the DDoS protection service.
//! 
//! This module handles loading and managing application configuration
//! from environment variables and configuration files.

use std::env;
use config::{Config as ConfigBuilder, ConfigError, Environment, File};
use crate::models::Config;

/// Load configuration from environment variables
pub fn load_config() -> Result<Config, ConfigError> {
    let config_file = env::var("CONFIG_FILE").unwrap_or_else(|_| "config/default.toml".to_string());
    
    let config = ConfigBuilder::builder()
        .add_source(File::with_name(&config_file))
        .add_source(Environment::default())
        .set_default("server.host", "127.0.0.1")?
        .set_default("server.port", 8080)?
        .set_default("redis.url", "redis://127.0.0.1:6379")?
        .set_default("redis.pool_size", 10)?
        .set_default("rate_limit.default_limit", 100)?
        .set_default("rate_limit.burst_size", 200)?
        .set_default("rate_limit.window_seconds", 60)?
        // DDoS detection defaults
        .set_default("ddos_detection.connection_rate_threshold", 100)?
        .set_default("ddos_detection.connection_rate_window", 60)?
        .set_default("ddos_detection.request_rate_threshold", 1000)?
        .set_default("ddos_detection.request_rate_window", 60)?
        .set_default("ddos_detection.traffic_volume_threshold", 10_000_000)?
        .set_default("ddos_detection.traffic_volume_window", 60)?
        .set_default("ddos_detection.anomaly_threshold", 3.0)?
        .set_default("ddos_detection.anomaly_window", 300)?
        // Rule engine defaults
        .set_default("rule_config.rules_file", "config/rules.json")?
        .set_default("rule_config.default_priority", 0)?
        .set_default("rule_config.enabled", true)?
        // Analytics defaults
        .set_default("analytics.enabled", true)?
        .set_default("analytics.storage_type", "redis")?
        .set_default("analytics.retention_days", 30)?
        .set_default("analytics.real_time_enabled", true)?
        // Monitoring defaults
        .set_default("monitoring.enabled", true)?
        .set_default("monitoring.interval_seconds", 60)?
        .set_default("monitoring.alert_thresholds.cpu_usage", 80.0)?
        .set_default("monitoring.alert_thresholds.memory_usage", 80.0)?
        .set_default("monitoring.alert_thresholds.request_rate", 1000)?
        .set_default("monitoring.alert_thresholds.error_rate", 10)?
        .build()?;

    config.try_deserialize()
} 