use serde::{Deserialize, Serialize};
use crate::core::DdosDetectionConfig;

/// Rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Default rate limit (requests per window)
    pub default_limit: u32,
    /// Burst size (maximum requests allowed in a burst)
    pub burst_size: u32,
    /// Time window in seconds
    pub window_seconds: u32,
}

/// Redis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URL
    pub url: String,
    /// Redis connection pool size
    pub pool_size: u32,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
}

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,
    /// Redis configuration
    pub redis: RedisConfig,
    /// Rate limit configuration
    pub rate_limit: RateLimitConfig,
    /// DDoS detection configuration
    pub ddos_detection: DdosDetectionConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
            },
            redis: RedisConfig {
                url: "redis://127.0.0.1:6379".to_string(),
                pool_size: 10,
            },
            rate_limit: RateLimitConfig {
                default_limit: 100,
                burst_size: 200,
                window_seconds: 60,
            },
            ddos_detection: DdosDetectionConfig::default(),
        }
    }
} 