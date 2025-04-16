//! Monitoring for the DDoS protection service.
//! 
//! This module provides monitoring capabilities for tracking
//! system performance and detecting issues.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time;
use crate::models::MonitoringConfig;
use redis::Client as RedisClient;
use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use log::{info, warn, error};
use std::sync::Arc;
use tokio::sync::broadcast::Receiver;
use redis::AsyncCommands;

/// Errors that can occur during monitoring operations
#[derive(Error, Debug)]
pub enum MonitoringError {
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    #[error("Monitoring error: {0}")]
    MonitoringError(String),
}

/// System metrics
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SystemMetrics {
    /// CPU usage (percentage)
    pub cpu_usage: f64,
    /// Memory usage (percentage)
    pub memory_usage: f64,
    /// Disk usage (percentage)
    pub disk_usage: f64,
    /// Network traffic in (bytes)
    pub network_in: u64,
    /// Network traffic out (bytes)
    pub network_out: u64,
    /// Request rate (requests per second)
    pub request_rate: f64,
    /// Error rate (errors per second)
    pub error_rate: f64,
    /// Response time (ms)
    pub response_time_ms: f64,
    /// Timestamp
    pub timestamp: i64,
}

impl redis::FromRedisValue for SystemMetrics {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let str_value: String = redis::FromRedisValue::from_redis_value(v)?;
        serde_json::from_str(&str_value)
            .map_err(|e| redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to parse SystemMetrics from JSON",
                e.to_string(),
            )))
    }
}

/// Alert level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertLevel {
    /// Info alert
    Info,
    /// Warning alert
    Warning,
    /// Error alert
    Error,
    /// Critical alert
    Critical,
}

/// Alert status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertStatus {
    Active,
    Acknowledged,
    Resolved,
}

/// Alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Alert ID
    pub id: String,
    /// Alert level
    pub level: AlertLevel,
    /// Alert message
    pub message: String,
    /// Alert source
    pub source: String,
    /// Alert status
    pub status: AlertStatus,
    /// Alert creation timestamp
    pub created_at: DateTime<Utc>,
    /// Alert update timestamp
    pub updated_at: DateTime<Utc>,
    /// Alert acknowledgment timestamp
    pub acknowledged_at: Option<DateTime<Utc>>,
    /// Alert resolution timestamp
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Monitoring service
pub struct Monitoring {
    /// Redis client
    redis_client: RedisClient,
    /// Monitoring configuration
    config: MonitoringConfig,
}

impl Monitoring {
    /// Create a new monitoring service
    pub fn new(redis_client: RedisClient, config: MonitoringConfig) -> Self {
        Self {
            redis_client,
            config,
        }
    }

    /// Start monitoring
    pub async fn start_monitoring(&self) -> Result<()> {
        info!("Starting monitoring service...");
        let mut interval = time::interval(Duration::from_secs(self.config.interval_seconds as u64));

        loop {
            interval.tick().await;
            match self.check_system_health().await {
                Ok(_) => info!("System health check completed successfully"),
                Err(e) => error!("System health check failed: {}", e),
            }
        }
    }

    async fn check_system_health(&self) -> Result<()> {
        // Check Redis connection
        let mut conn = self.redis_client.get_async_connection().await
            .map_err(|e| anyhow::anyhow!("Failed to connect to Redis: {}", e))?;

        // Check memory usage
        self.check_memory_usage(&mut conn).await?;

        // Check request rate
        self.check_request_rate(&mut conn).await?;

        Ok(())
    }

    async fn check_memory_usage(&self, conn: &mut redis::aio::Connection) -> Result<()> {
        let info: String = redis::cmd("INFO")
            .query_async(conn)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get Redis INFO: {}", e))?;

        // Parse used_memory from INFO command output
        let used_memory = info
            .lines()
            .find(|line| line.starts_with("used_memory:"))
            .and_then(|line| line.split(':').nth(1))
            .and_then(|value| value.trim().parse::<u64>().ok())
            .ok_or_else(|| anyhow::anyhow!("Failed to parse memory usage from Redis INFO"))?;

        let memory_threshold = self.config.alert_thresholds.memory_usage * 1024.0 * 1024.0; // Convert percentage to bytes
        if used_memory as f64 > memory_threshold {
            warn!(
                "Memory usage exceeds threshold: {} bytes (threshold: {} bytes)",
                used_memory, memory_threshold
            );
        }

        Ok(())
    }

    async fn check_request_rate(&self, conn: &mut redis::aio::Connection) -> Result<()> {
        let request_count: Option<u64> = conn
            .get("request_count")
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get request count: {}", e))?;

        if let Some(count) = request_count {
            if count > self.config.alert_thresholds.request_rate as u64 {
                warn!(
                    "Request rate exceeds threshold: {} requests (threshold: {})",
                    count, self.config.alert_thresholds.request_rate
                );
            }
        }

        Ok(())
    }

    /// Collect system metrics
    async fn collect_metrics(&self) -> Result<SystemMetrics, Box<dyn std::error::Error>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // In a real implementation, we would collect actual system metrics
        // For now, we'll use placeholder values
        let metrics = SystemMetrics {
            cpu_usage: 45.5,
            memory_usage: 60.2,
            disk_usage: 60.0,
            network_in: 1000000,
            network_out: 500000,
            request_rate: 100.0,
            error_rate: 0.02,
            response_time_ms: 50.0,
            timestamp: now as i64,
        };
        
        let mut conn = self.redis_client.get_async_connection().await?;
        
        let metrics_json = serde_json::to_string(&metrics)?;
        
        let _: () = redis::cmd("SET")
            .arg("system_metrics")
            .arg(metrics_json)
            .query_async(&mut conn)
            .await?;
        
        Ok(metrics)
    }

    /// Check for alerts
    async fn check_thresholds(&self, metrics: &SystemMetrics) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.redis_client.get_async_connection().await?;

        // Check CPU usage
        if metrics.cpu_usage > self.config.alert_thresholds.cpu_usage as f64 {
            self.create_alert(
                "High CPU Usage",
                &format!("CPU usage is at {}%", metrics.cpu_usage),
                AlertLevel::Warning,
            ).await?;
        }

        // Check memory usage
        if metrics.memory_usage > self.config.alert_thresholds.memory_usage as f64 {
            self.create_alert(
                "High Memory Usage",
                &format!("Memory usage is at {}%", metrics.memory_usage),
                AlertLevel::Warning,
            ).await?;
        }

        // Check request rate
        if metrics.request_rate > self.config.alert_thresholds.request_rate as f64 {
            self.create_alert(
                "High Request Rate",
                &format!("Request rate is at {}/s", metrics.request_rate),
                AlertLevel::Warning,
            ).await?;
        }

        // Check error rate
        if metrics.error_rate > self.config.alert_thresholds.error_rate as f64 {
            self.create_alert(
                "High Error Rate",
                &format!("Error rate is at {}%", metrics.error_rate),
                AlertLevel::Error,
            ).await?;
        }

        Ok(())
    }

    /// Get current system metrics
    pub async fn get_current_metrics(&self) -> Result<SystemMetrics> {
        let mut conn = self.redis_client.get_async_connection().await?;
        
        let metrics_json: Option<String> = redis::cmd("GET")
            .arg("system_metrics")
            .query_async(&mut conn)
            .await?;

        if let Some(json) = metrics_json {
            Ok(serde_json::from_str(&json)?)
        } else {
            Ok(SystemMetrics {
                cpu_usage: 0.0,
                memory_usage: 0.0,
                disk_usage: 0.0,
                network_in: 0,
                network_out: 0,
                request_rate: 0.0,
                error_rate: 0.0,
                response_time_ms: 0.0,
                timestamp: Utc::now().timestamp(),
            })
        }
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(_) => return Vec::new(),
        };

        let alerts_json: Vec<String> = match redis::cmd("ZRANGE")
            .arg("alerts")
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await {
                Ok(alerts) => alerts,
                Err(_) => return Vec::new(),
            };

        alerts_json
            .into_iter()
            .filter_map(|json| serde_json::from_str(&json).ok())
            .filter(|alert: &Alert| alert.status == AlertStatus::Active)
            .collect()
    }

    /// Acknowledge an alert
    pub async fn acknowledge_alert(&self, alert_id: &str) -> Result<()> {
        let mut conn = self.redis_client.get_async_connection().await?;
        
        let alerts_json: Vec<String> = redis::cmd("ZRANGE")
            .arg("alerts")
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await?;

        for alert_json in alerts_json {
            if let Ok(mut alert) = serde_json::from_str::<Alert>(&alert_json) {
                if alert.id == alert_id {
                    alert.status = AlertStatus::Acknowledged;
                    alert.acknowledged_at = Some(Utc::now());
                    alert.updated_at = Utc::now();

                    let updated_json = serde_json::to_string(&alert)?;
                    let _: () = redis::pipe()
                        .atomic()
                        .cmd("ZREM")
                        .arg("alerts")
                        .arg(alert_json)
                        .cmd("ZADD")
                        .arg("alerts")
                        .arg(alert.updated_at.timestamp())
                        .arg(updated_json)
                        .query_async(&mut conn)
                        .await?;

                    break;
                }
            }
        }

        Ok(())
    }

    /// Clean up old alerts
    async fn cleanup_old_alerts(&self) -> Result<()> {
        let mut conn = self.redis_client.get_async_connection().await?;
        let retention_days = 30; // Keep alerts for 30 days
        let cutoff = Utc::now().timestamp() - (retention_days * 24 * 60 * 60);

        let _: () = redis::cmd("ZREMRANGEBYSCORE")
            .arg("alerts")
            .arg("-inf")
            .arg(cutoff)
            .query_async(&mut conn)
            .await?;

        Ok(())
    }

    async fn create_alert(&self, title: &str, message: &str, level: AlertLevel) -> Result<()> {
        let mut conn = self.redis_client.get_async_connection().await?;
        
        let alert = Alert {
            id: Uuid::new_v4().to_string(),
            level,
            message: message.to_string(),
            source: title.to_string(),
            status: AlertStatus::Active,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            acknowledged_at: None,
            resolved_at: None,
        };

        let alert_json = serde_json::to_string(&alert)?;
        let _: Result<(), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("ZADD")
            .arg("alerts")
            .arg(alert.created_at.timestamp())
            .arg(alert_json)
            .query_async(&mut conn)
            .await;

        Ok(())
    }

    pub async fn get_alerts(&self) -> Result<Vec<Alert>, MonitoringError> {
        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(_) => return Ok(Vec::new()),
        };

        let alerts_json: Vec<String> = match redis::cmd("ZRANGE")
            .arg("alerts")
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await {
                Ok(alerts) => alerts,
                Err(_) => return Ok(Vec::new()),
            };

        Ok(alerts_json
            .into_iter()
            .filter_map(|json| serde_json::from_str(&json).ok())
            .collect())
    }

    pub async fn get_metrics(&self) -> Result<SystemMetrics, MonitoringError> {
        let _conn = self.redis_client.get_async_connection().await?;
        // TODO: Implement metrics retrieval from Redis
        Ok(SystemMetrics::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_monitoring() {
        // This is a placeholder test
        // In a real implementation, we would use a test Redis instance
    }
} 