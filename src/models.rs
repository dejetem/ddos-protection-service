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

/// Rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// Rules file path
    pub rules_file: Option<String>,
    /// Default rule priority
    pub default_priority: i32,
    /// Whether to enable rule engine
    pub enabled: bool,
}

/// Analytics configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnalyticsConfig {
    /// Whether to enable analytics
    pub enabled: bool,
    /// Analytics storage type (redis, file, etc.)
    pub storage_type: String,
    /// Analytics retention period in days
    pub retention_days: u64,
    /// Whether to enable real-time analytics
    pub real_time_enabled: bool,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Whether to enable monitoring
    pub enabled: bool,
    /// Monitoring interval in seconds
    pub interval_seconds: u32,
    /// Alert thresholds
    pub alert_thresholds: AlertThresholds,
}

/// Alert thresholds for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    /// CPU usage threshold (percentage)
    pub cpu_usage: f64,
    /// Memory usage threshold (percentage)
    pub memory_usage: f64,
    /// Request rate threshold (requests per second)
    pub request_rate: u32,
    /// Error rate threshold (errors per second)
    pub error_rate: u32,
}

/// Application configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,
    /// Redis configuration
    pub redis: RedisConfig,
    /// Rate limit configuration
    pub rate_limit: RateLimitConfig,
    /// DDoS detection configuration
    pub ddos_detection: DdosDetectionConfig,
    /// Rule configuration
    pub rule_config: RuleConfig,
    /// Analytics configuration
    pub analytics: AnalyticsConfig,
    /// Monitoring configuration
    pub monitoring: MonitoringConfig,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenv::dotenv().ok();

        Ok(Self {
            redis: RedisConfig {
                url: std::env::var("REDIS_URL")?,
                pool_size: std::env::var("REDIS_POOL_SIZE")?.parse()?,
            },
            server: ServerConfig {
                host: std::env::var("SERVER_HOST")?,
                port: std::env::var("SERVER_PORT")?.parse()?,
            },
            rate_limit: RateLimitConfig {
                default_limit: std::env::var("RATE_LIMIT_DEFAULT")?.parse()?,
                burst_size: std::env::var("RATE_LIMIT_BURST")?.parse()?,
                window_seconds: std::env::var("RATE_LIMIT_WINDOW")?.parse()?,
            },
            ddos_detection: DdosDetectionConfig {
                connection_rate_threshold: std::env::var("DDOS_CONNECTION_RATE_THRESHOLD")?.parse()?,
                connection_rate_window: std::env::var("DDOS_CONNECTION_RATE_WINDOW")?.parse()?,
                request_rate_threshold: std::env::var("DDOS_REQUEST_RATE_THRESHOLD")?.parse()?,
                request_rate_window: std::env::var("DDOS_REQUEST_RATE_WINDOW")?.parse()?,
                traffic_volume_threshold: std::env::var("DDOS_TRAFFIC_VOLUME_THRESHOLD")?.parse()?,
                traffic_volume_window: std::env::var("DDOS_TRAFFIC_VOLUME_WINDOW")?.parse()?,
                anomaly_threshold: std::env::var("DDOS_ANOMALY_THRESHOLD")?.parse()?,
                anomaly_window: std::env::var("DDOS_ANOMALY_WINDOW")?.parse()?,
            },
            rule_config: RuleConfig {
                enabled: std::env::var("RULE_ENGINE_ENABLED")?.parse()?,
                rules_file: Some(std::env::var("RULE_ENGINE_RULES_FILE")?),
                default_priority: std::env::var("RULE_ENGINE_DEFAULT_PRIORITY")?.parse()?,
            },
            analytics: AnalyticsConfig {
                enabled: std::env::var("ANALYTICS_ENABLED")?.parse()?,
                storage_type: std::env::var("ANALYTICS_STORAGE_TYPE")?,
                retention_days: std::env::var("ANALYTICS_RETENTION_DAYS")?.parse()?,
                real_time_enabled: std::env::var("ANALYTICS_REAL_TIME_ENABLED")?.parse()?,
            },
            monitoring: MonitoringConfig {
                enabled: std::env::var("MONITORING_ENABLED")?.parse()?,
                interval_seconds: std::env::var("MONITORING_INTERVAL_SECS")?.parse()?,
                alert_thresholds: AlertThresholds {
                    cpu_usage: std::env::var("MONITORING_CPU_THRESHOLD")?.parse()?,
                    memory_usage: std::env::var("MONITORING_MEMORY_THRESHOLD")?.parse()?,
                    request_rate: std::env::var("MONITORING_REQUEST_RATE_THRESHOLD")?.parse()?,
                    error_rate: std::env::var("MONITORING_ERROR_RATE_THRESHOLD")?.parse()?,
                },
            },
        })
    }
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
            rule_config: RuleConfig {
                rules_file: Some("config/rules.json".to_string()),
                default_priority: 0,
                enabled: true,
            },
            analytics: AnalyticsConfig {
                enabled: true,
                storage_type: "redis".to_string(),
                retention_days: 30,
                real_time_enabled: true,
            },
            monitoring: MonitoringConfig {
                enabled: true,
                interval_seconds: 60,
                alert_thresholds: AlertThresholds {
                    cpu_usage: 80.0,
                    memory_usage: 80.0,
                    request_rate: 1000,
                    error_rate: 10,
                },
            },
        }
    }
} 