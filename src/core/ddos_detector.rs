//! DDoS detection algorithms for the DDoS protection service.
//! 
//! This module provides sophisticated DDoS detection algorithms,
//! including traffic pattern analysis, connection rate monitoring,
//! and anomaly detection.

use std::collections::{HashMap, VecDeque};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during DDoS detection
#[derive(Error, Debug)]
pub enum DdosDetectionError {
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    #[error("Detection error: {0}")]
    DetectionError(String),
}

/// DDoS detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosDetectionConfig {
    /// Threshold for connection rate (connections per second)
    pub connection_rate_threshold: u32,
    /// Time window for connection rate monitoring (seconds)
    pub connection_rate_window: u32,
    /// Threshold for request rate (requests per second)
    pub request_rate_threshold: u32,
    /// Time window for request rate monitoring (seconds)
    pub request_rate_window: u32,
    /// Threshold for traffic volume (bytes per second)
    pub traffic_volume_threshold: u64,
    /// Time window for traffic volume monitoring (seconds)
    pub traffic_volume_window: u32,
    /// Threshold for anomaly detection (standard deviations)
    pub anomaly_threshold: f64,
    /// Time window for anomaly detection (seconds)
    pub anomaly_window: u32,
}

impl Default for DdosDetectionConfig {
    fn default() -> Self {
        Self {
            connection_rate_threshold: 100,
            connection_rate_window: 60,
            request_rate_threshold: 1000,
            request_rate_window: 60,
            traffic_volume_threshold: 10_000_000, // 10 MB/s
            traffic_volume_window: 60,
            anomaly_threshold: 3.0,
            anomaly_window: 300, // 5 minutes
        }
    }
}

/// DDoS detector implementation
pub struct DdosDetector {
    /// Redis connection manager
    redis: redis::Client,
    /// DDoS detection configuration
    config: DdosDetectionConfig,
    /// In-memory connection tracking
    connection_tracker: HashMap<String, VecDeque<Instant>>,
    /// In-memory request tracking
    request_tracker: HashMap<String, VecDeque<Instant>>,
    /// In-memory traffic tracking
    traffic_tracker: HashMap<String, VecDeque<(Instant, u64)>>,
}

impl DdosDetector {
    /// Create a new DDoS detector instance
    pub fn new(redis: redis::Client, config: DdosDetectionConfig) -> Self {
        Self {
            redis,
            config,
            connection_tracker: HashMap::new(),
            request_tracker: HashMap::new(),
            traffic_tracker: HashMap::new(),
        }
    }

    /// Check if a connection should be blocked due to DDoS detection
    /// 
    /// # Arguments
    /// 
    /// * `ip` - The IP address of the connection
    /// 
    /// # Returns
    /// 
    /// * `Ok(false)` if the connection should be allowed
    /// * `Ok(true)` if the connection should be blocked
    /// * `Err(DdosDetectionError)` if there was an error during detection
    pub async fn check_connection(&mut self, ip: &str) -> Result<bool, DdosDetectionError> {
        let key = format!("connection:{}", ip);
        let mut conn = match self.redis.get_async_connection().await {
            Ok(conn) => conn,
            Err(e) => return Err(DdosDetectionError::RedisError(e)),
        };
        
        let count: u32 = match conn.incr(&key, 1).await {
            Ok(count) => count,
            Err(e) => return Err(DdosDetectionError::RedisError(e)),
        };
        
        if count == 1 {
            let _: () = match conn.expire::<_, ()>(&key, self.config.connection_rate_window as usize).await {
                Ok(_) => (),
                Err(e) => return Err(DdosDetectionError::RedisError(e)),
            };
        }
        
        if count > self.config.connection_rate_threshold {
            return Ok(true);
        }
        
        Ok(false)
    }

    /// Check if a request should be blocked due to DDoS detection
    /// 
    /// # Arguments
    /// 
    /// * `ip` - The IP address of the request
    /// * `size` - The size of the request in bytes
    /// 
    /// # Returns
    /// 
    /// * `Ok(false)` if the request should be allowed
    /// * `Ok(true)` if the request should be blocked
    /// * `Err(DdosDetectionError)` if there was an error during detection
    pub async fn check_request(&mut self, ip: &str, size: u64) -> Result<bool, DdosDetectionError> {
        let key = format!("request:{}", ip);
        let mut conn = match self.redis.get_async_connection().await {
            Ok(conn) => conn,
            Err(e) => return Err(DdosDetectionError::RedisError(e)),
        };
        
        let count: u32 = match conn.incr(&key, 1).await {
            Ok(count) => count,
            Err(e) => return Err(DdosDetectionError::RedisError(e)),
        };
        let volume: u64 = match conn.incr(format!("volume:{}", ip), size).await {
            Ok(volume) => volume,
            Err(e) => return Err(DdosDetectionError::RedisError(e)),
        };
        
        if count == 1 {
            let _: () = match conn.expire::<_, ()>(&key, self.config.request_rate_window as usize).await {
                Ok(_) => (),
                Err(e) => return Err(DdosDetectionError::RedisError(e)),
            };
            let _: () = match conn.expire::<_, ()>(format!("volume:{}", ip), self.config.traffic_volume_window as usize).await {
                Ok(_) => (),
                Err(e) => return Err(DdosDetectionError::RedisError(e)),
            };
        }
        
        if count > self.config.request_rate_threshold || volume > self.config.traffic_volume_threshold {
            return Ok(true);
        }
        
        Ok(false)
    }

    /// Detect anomalies in traffic patterns
    /// 
    /// # Arguments
    /// 
    /// * `ip` - The IP address to check for anomalies
    /// 
    /// # Returns
    /// 
    /// * `Ok(false)` if no anomalies were detected
    /// * `Ok(true)` if anomalies were detected
    /// * `Err(DdosDetectionError)` if there was an error during detection
    async fn detect_anomaly(&self, ip: &str) -> Result<bool, DdosDetectionError> {
        let key = format!("anomaly:{}", ip);
        let mut conn = match self.redis.get_async_connection().await {
            Ok(conn) => conn,
            Err(e) => return Err(DdosDetectionError::RedisError(e)),
        };
        
        let count: u32 = match conn.incr(&key, 1).await {
            Ok(count) => count,
            Err(e) => return Err(DdosDetectionError::RedisError(e)),
        };
        
        if count == 1 {
            let _: () = match conn.expire::<_, ()>(&key, self.config.anomaly_window as usize).await {
                Ok(_) => (),
                Err(e) => return Err(DdosDetectionError::RedisError(e)),
            };
        }
        
        if count as f64 > self.config.anomaly_threshold {
            return Ok(true);
        }
        
        Ok(false)
    }

    /// Reset DDoS detection for a given IP
    /// 
    /// # Arguments
    /// 
    /// * `ip` - The IP address to reset detection for
    pub async fn reset_detection(&mut self, ip: &str) -> Result<(), DdosDetectionError> {
        let mut conn = match self.redis.get_async_connection().await {
            Ok(conn) => conn,
            Err(e) => return Err(DdosDetectionError::RedisError(e)),
        };
        let _: () = match conn.del::<_, ()>(format!("connection:{}", ip)).await {
            Ok(_) => (),
            Err(e) => return Err(DdosDetectionError::RedisError(e)),
        };
        let _: () = match conn.del::<_, ()>(format!("request:{}", ip)).await {
            Ok(_) => (),
            Err(e) => return Err(DdosDetectionError::RedisError(e)),
        };
        let _: () = match conn.del::<_, ()>(format!("volume:{}", ip)).await {
            Ok(_) => (),
            Err(e) => return Err(DdosDetectionError::RedisError(e)),
        };
        let _: () = match conn.del::<_, ()>(format!("anomaly:{}", ip)).await {
            Ok(_) => (),
            Err(e) => return Err(DdosDetectionError::RedisError(e)),
        };
        Ok(())
    }
}

/// Get the current Unix timestamp
fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::Client;

    #[tokio::test]
    async fn test_connection_detection() {
        let client = Client::open("redis://127.0.0.1:6379").unwrap();
        let config = DdosDetectionConfig {
            connection_rate_threshold: 2,
            connection_rate_window: 60,
            request_rate_threshold: 1000,
            request_rate_window: 60,
            traffic_volume_threshold: 10_000_000,
            traffic_volume_window: 60,
            anomaly_threshold: 3.0,
            anomaly_window: 300,
        };
        
        let mut detector = DdosDetector::new(client, config);
        
        // First connection should be allowed
        assert!(!detector.check_connection("127.0.0.1").await.unwrap());
        
        // Second connection should be allowed
        assert!(!detector.check_connection("127.0.0.1").await.unwrap());
        
        // Third connection should be blocked
        assert!(detector.check_connection("127.0.0.1").await.unwrap());
        
        // Reset should allow new connections
        detector.reset_detection("127.0.0.1").await.unwrap();
        assert!(!detector.check_connection("127.0.0.1").await.unwrap());
    }
} 