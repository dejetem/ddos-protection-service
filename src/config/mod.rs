//! Configuration management for the DDoS protection service.
//! 
//! This module handles loading and managing application configuration
//! from environment variables and configuration files.

use serde::Deserialize;
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
        .build()?;

    config.try_deserialize()
} 