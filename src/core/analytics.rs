//! Analytics for the DDoS protection service.
//! 
//! This module provides analytics collection and reporting capabilities
//! for monitoring service performance and detecting patterns.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::models::AnalyticsConfig;
use redis::Client as RedisClient;
use anyhow::Result;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

/// Errors that can occur during analytics operations
#[derive(Error, Debug)]
pub enum AnalyticsError {
    #[error("Redis error: {0}")]
    RedisError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
}

/// Event types for analytics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventType {
    Request,
    BlockedRequest,
    DdosAttack,
    RuleTriggered,
    RateLimitExceeded,
    RateLimit,
    DdosDetection,
    RuleEngine,
    System,
}

/// Analytics event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub source: String,
    pub data: HashMap<String, serde_json::Value>,
}

/// Analytics metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Metrics {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub rate_limited_requests: u64,
    pub ddos_attacks_detected: u64,
    pub rules_triggered: u64,
    pub average_response_time: f64,
    pub error_rate: f64,
}

impl From<redis::RedisError> for AnalyticsError {
    fn from(err: redis::RedisError) -> Self {
        AnalyticsError::RedisError(err.to_string())
    }
}

impl redis::FromRedisValue for Event {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let str_value: String = redis::FromRedisValue::from_redis_value(v)?;
        serde_json::from_str(&str_value)
            .map_err(|e| redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to parse Event from JSON",
                e.to_string(),
            )))
    }
}

impl redis::FromRedisValue for Metrics {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let str_value: String = redis::FromRedisValue::from_redis_value(v)?;
        serde_json::from_str(&str_value)
            .map_err(|e| redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to parse Metrics from JSON",
                e.to_string(),
            )))
    }
}

/// Analytics service
pub struct Analytics {
    redis_client: RedisClient,
    config: AnalyticsConfig,
    events: RwLock<Vec<Event>>,
    metrics: RwLock<Metrics>,
    retention_period: Duration,
}

impl Analytics {
    /// Create a new analytics instance
    pub fn new(redis_client: RedisClient, config: AnalyticsConfig, retention_period: Duration) -> Self {
        Self {
            redis_client,
            config,
            events: RwLock::new(Vec::new()),
            metrics: RwLock::new(Metrics::default()),
            retention_period,
        }
    }

    /// Start analytics collection
    pub async fn start_collection(&self) -> Result<()> {
        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(e) => return Err(anyhow::anyhow!("Redis connection error: {}", e)),
        };

        // Initialize metrics in Redis if they don't exist
        let _: () = redis::cmd("SETNX")
            .arg("analytics:metrics")
            .arg(serde_json::to_string(&Metrics::default())?)
            .query_async::<_, ()>(&mut conn)
            .await?;

        Ok(())
    }

    /// Record an event
    pub async fn record_event(&self, event: Event) -> Result<()> {
        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(e) => return Err(anyhow::anyhow!("Redis connection error: {}", e)),
        };

        let event_json = match serde_json::to_string(&event) {
            Ok(json) => json,
            Err(e) => return Err(anyhow::anyhow!("Event serialization error: {}", e)),
        };

        let _: () = redis::cmd("RPUSH")
            .arg("analytics:events")
            .arg(event_json)
            .query_async::<_, ()>(&mut conn)
            .await?;

        Ok(())
    }

    /// Get analytics metrics
    pub async fn get_metrics(&self) -> Result<Metrics, AnalyticsError> {
        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(e) => return Err(AnalyticsError::RedisError(e.to_string())),
        };

        let metrics: redis::RedisResult<Option<String>> = redis::cmd("GET")
            .arg("analytics:metrics")
            .query_async::<_, Option<String>>(&mut conn)
            .await;

        match metrics {
            Ok(Some(json_str)) => {
                match serde_json::from_str(&json_str) {
                    Ok(metrics) => Ok(metrics),
                    Err(e) => Err(AnalyticsError::RedisError(format!("Failed to parse metrics: {}", e))),
                }
            },
            Ok(None) => Ok(Metrics::default()),
            Err(e) => Err(AnalyticsError::RedisError(e.to_string())),
        }
    }

    /// Get events within a time range
    pub async fn get_events(&self, start_time: u64, end_time: u64, event_type: Option<EventType>) -> Result<Vec<Event>, AnalyticsError> {
        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(e) => return Err(AnalyticsError::RedisError(e.to_string())),
        };

        let events: redis::RedisResult<Vec<String>> = redis::cmd("LRANGE")
            .arg("analytics:events")
            .arg(0)
            .arg(-1)
            .query_async::<_, Vec<String>>(&mut conn)
            .await;

        match events {
            Ok(json_strs) => {
                let mut filtered_events = Vec::new();
                for json_str in json_strs {
                    match serde_json::from_str::<Event>(&json_str) {
                        Ok(event) => {
                            let timestamp = event.timestamp.timestamp() as u64;
                            if timestamp >= start_time && timestamp <= end_time {
                                if let Some(ref expected_type) = event_type {
                                    if event.event_type == *expected_type {
                                        filtered_events.push(event);
                                    }
                                } else {
                                    filtered_events.push(event);
                                }
                            }
                        },
                        Err(e) => log::error!("Failed to parse event: {}", e),
                    }
                }
                Ok(filtered_events)
            },
            Err(e) => Err(AnalyticsError::RedisError(e.to_string())),
        }
    }

    /// Collect metrics from events
    pub async fn collect_metrics(&self) -> Result<()> {
        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(e) => return Err(anyhow::anyhow!("Redis connection error: {}", e)),
        };

        let total_requests = match self.get_metric_value(&mut conn, "total_requests").await {
            Ok(value) => value,
            Err(e) => return Err(anyhow::anyhow!("Failed to get total_requests: {}", e)),
        };

        let blocked_requests = match self.get_metric_value(&mut conn, "blocked_requests").await {
            Ok(value) => value,
            Err(e) => return Err(anyhow::anyhow!("Failed to get blocked_requests: {}", e)),
        };

        let ddos_attacks_detected = match self.get_metric_value(&mut conn, "ddos_attacks").await {
            Ok(value) => value,
            Err(e) => return Err(anyhow::anyhow!("Failed to get ddos_attacks: {}", e)),
        };

        let average_response_time = match self.get_metric_value(&mut conn, "avg_response_time").await {
            Ok(value) => value as f64,
            Err(e) => return Err(anyhow::anyhow!("Failed to get avg_response_time: {}", e)),
        };

        let metrics = Metrics {
            total_requests,
            blocked_requests,
            rate_limited_requests: 0, // TODO: Implement this
            ddos_attacks_detected,
            rules_triggered: 0, // TODO: Implement this
            average_response_time,
            error_rate: 0.0, // TODO: Implement this
        };

        let metrics_json = match serde_json::to_string(&metrics) {
            Ok(json) => json,
            Err(e) => return Err(anyhow::anyhow!("Metrics serialization error: {}", e)),
        };

        let _: () = match redis::cmd("SET")
            .arg("analytics:metrics")
            .arg(metrics_json)
            .query_async::<_, ()>(&mut conn)
            .await {
                Ok(_) => (),
                Err(e) => return Err(anyhow::anyhow!("Redis query error: {}", e)),
            };

        Ok(())
    }

    /// Helper function to get a metric value from Redis
    async fn get_metric_value(&self, conn: &mut redis::aio::Connection, key: &str) -> Result<u64> {
        let value: Option<String> = match redis::cmd("GET")
            .arg(format!("analytics:{}", key))
            .query_async(conn)
            .await {
                Ok(value) => value,
                Err(e) => return Err(anyhow::anyhow!("Redis query error: {}", e)),
            };

        match value {
            Some(v) => match v.parse() {
                Ok(value) => Ok(value),
                Err(e) => Err(anyhow::anyhow!("Value parsing error: {}", e)),
            },
            None => Ok(0),
        }
    }

    /// Clean up old data based on retention policy
    pub async fn cleanup_old_data(&self) -> Result<()> {
        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(e) => return Err(anyhow::anyhow!("Redis connection error: {}", e)),
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cutoff = now - self.retention_period.as_secs();
        let cutoff_dt = DateTime::<Utc>::from_timestamp(cutoff as i64, 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid timestamp"))?;

        let events: Vec<Event> = redis::cmd("LRANGE")
            .arg("analytics:events")
            .arg(0)
            .arg(-1)
            .query_async::<_, Vec<Event>>(&mut conn)
            .await?;

        for event in events {
            if event.timestamp < cutoff_dt {
                let _: () = match redis::cmd("LREM")
                    .arg("analytics:events")
                    .arg(1)
                    .arg(serde_json::to_string(&event)?)
                    .query_async::<_, ()>(&mut conn)
                    .await {
                        Ok(_) => (),
                        Err(e) => return Err(anyhow::anyhow!("Redis query error: {}", e)),
                    };
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_analytics() {
        // This is a placeholder test
        // In a real implementation, we would use a test Redis instance
    }
} 