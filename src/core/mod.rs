//! Core functionality for the DDoS protection service.
//! 
//! This module contains the core components of the service,
//! including rate limiting, DDoS detection, rule engine, analytics, and monitoring.

pub mod rate_limiter;
pub mod ddos_detector;
pub mod rule_engine;
pub mod analytics;
pub mod monitoring;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosDetectionConfig {
    pub connection_rate_threshold: u32,
    pub connection_rate_window: u32,
    pub request_rate_threshold: u32,
    pub request_rate_window: u32,
    pub traffic_volume_threshold: u64,
    pub traffic_volume_window: u32,
    pub anomaly_threshold: f64,
    pub anomaly_window: u32,
}

impl Default for DdosDetectionConfig {
    fn default() -> Self {
        Self {
            connection_rate_threshold: 100,
            connection_rate_window: 60,
            request_rate_threshold: 1000,
            request_rate_window: 60,
            traffic_volume_threshold: 10_000_000,
            traffic_volume_window: 60,
            anomaly_threshold: 3.0,
            anomaly_window: 300,
        }
    }
}

pub use rate_limiter::RateLimiter;
pub use ddos_detector::DdosDetector;
pub use rule_engine::{RuleEngine, Rule, RuleCondition, RuleAction};
pub use analytics::Analytics;
pub use monitoring::Monitoring; 