//! DDoS detection algorithms for the DDoS protection service.
//! 
//! This module provides sophisticated DDoS detection algorithms,
//! including traffic pattern analysis, connection rate monitoring,
//! and anomaly detection.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::utils::format_rate_limit_key;

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
        // Update connection tracker
        let now = Instant::now();
        let connections = self.connection_tracker.entry(ip.to_string()).or_insert_with(VecDeque::new);
        
        // Remove old connections
        let window_duration = Duration::from_secs(self.config.connection_rate_window as u64);
        while connections.front().map_or(false, |&time| now.duration_since(time) > window_duration) {
            connections.pop_front();
        }
        
        // Add new connection
        connections.push_back(now);
        
        // Check if connection rate exceeds threshold
        if connections.len() > self.config.connection_rate_threshold as usize {
            // Store in Redis for persistence
            let key = format_rate_limit_key("ddos_connection", ip);
            let mut conn = self.redis.get_async_connection().await?;
            conn.set(&key, get_current_timestamp()).await?;
            conn.expire(&key, self.config.connection_rate_window as usize).await?;
            
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
        // Update request tracker
        let now = Instant::now();
        let requests = self.request_tracker.entry(ip.to_string()).or_insert_with(VecDeque::new);
        
        // Remove old requests
        let window_duration = Duration::from_secs(self.config.request_rate_window as u64);
        while requests.front().map_or(false, |&time| now.duration_since(time) > window_duration) {
            requests.pop_front();
        }
        
        // Add new request
        requests.push_back(now);
        
        // Update traffic tracker
        let traffic = self.traffic_tracker.entry(ip.to_string()).or_insert_with(VecDeque::new);
        
        // Remove old traffic entries
        let traffic_window_duration = Duration::from_secs(self.config.traffic_volume_window as u64);
        while traffic.front().map_or(false, |&(time, _)| now.duration_since(time) > traffic_window_duration) {
            traffic.pop_front();
        }
        
        // Add new traffic entry
        traffic.push_back((now, size));
        
        // Check if request rate exceeds threshold
        if requests.len() > self.config.request_rate_threshold as usize {
            // Store in Redis for persistence
            let key = format_rate_limit_key("ddos_request", ip);
            let mut conn = self.redis.get_async_connection().await?;
            conn.set(&key, get_current_timestamp()).await?;
            conn.expire(&key, self.config.request_rate_window as usize).await?;
            
            return Ok(true);
        }
        
        // Check if traffic volume exceeds threshold
        let total_traffic: u64 = traffic.iter().map(|&(_, size)| size).sum();
        if total_traffic > self.config.traffic_volume_threshold {
            // Store in Redis for persistence
            let key = format_rate_limit_key("ddos_traffic", ip);
            let mut conn = self.redis.get_async_connection().await?;
            conn.set(&key, get_current_timestamp()).await?;
            conn.expire(&key, self.config.traffic_volume_window as usize).await?;
            
            return Ok(true);
        }
        
        // Check for anomalies
        if self.detect_anomaly(ip).await? {
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
        // This is a simplified anomaly detection algorithm
        // In a real-world scenario, you would use more sophisticated statistical methods
        
        // Get historical traffic data from Redis
        let key = format_rate_limit_key("traffic_history", ip);
        let mut conn = self.redis.get_async_connection().await?;
        
        // If no history, return false
        if !conn.exists(&key).await? {
            return Ok(false);
        }
        
        // Get traffic history
        let history: Vec<u64> = conn.lrange(&key, 0, -1).await?;
        
        // Calculate mean and standard deviation
        if history.len() < 2 {
            return Ok(false);
        }
        
        let mean = history.iter().sum::<u64>() as f64 / history.len() as f64;
        let variance = history.iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / (history.len() - 1) as f64;
        let std_dev = variance.sqrt();
        
        // Get current traffic
        let current_traffic = history.last().unwrap();
        
        // Check if current traffic is an anomaly
        let z_score = (*current_traffic as f64 - mean) / std_dev;
        
        if z_score.abs() > self.config.anomaly_threshold {
            // Store in Redis for persistence
            let key = format_rate_limit_key("ddos_anomaly", ip);
            conn.set(&key, get_current_timestamp()).await?;
            conn.expire(&key, self.config.anomaly_window as usize).await?;
            
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
        // Clear in-memory trackers
        self.connection_tracker.remove(ip);
        self.request_tracker.remove(ip);
        self.traffic_tracker.remove(ip);
        
        // Clear Redis keys
        let mut conn = self.redis.get_async_connection().await?;
        let keys = [
            format_rate_limit_key("ddos_connection", ip),
            format_rate_limit_key("ddos_request", ip),
            format_rate_limit_key("ddos_traffic", ip),
            format_rate_limit_key("ddos_anomaly", ip),
        ];
        
        for key in keys.iter() {
            conn.del(key).await?;
        }
        
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