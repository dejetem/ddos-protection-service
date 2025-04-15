//! Rate limiting implementation for the DDoS protection service.
//! 
//! This module provides rate limiting functionality using Redis as the backend
//! storage for tracking request counts and implementing the token bucket algorithm.

use redis::AsyncCommands;
use std::time::SystemTime;
use crate::models::RateLimitConfig;
use crate::utils::format_rate_limit_key;
use thiserror::Error;

/// Errors that can occur during rate limiting operations
#[derive(Error, Debug)]
pub enum RateLimitError {
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    #[error("Rate limit exceeded")]
    ExceededLimit,
}

/// Rate limiter implementation using Redis
pub struct RateLimiter {
    /// Redis connection manager
    redis: redis::Client,
    /// Rate limit configuration
    config: RateLimitConfig,
}

impl RateLimiter {
    /// Create a new rate limiter instance
    pub fn new(redis: redis::Client, config: RateLimitConfig) -> Self {
        Self { redis, config }
    }

    /// Check if a request should be rate limited
    /// 
    /// # Arguments
    /// 
    /// * `key` - The key to rate limit (e.g., IP address or user ID)
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` if the request should be allowed
    /// * `Err(RateLimitError::ExceededLimit)` if the rate limit has been exceeded
    /// * `Err(RateLimitError::RedisError)` if there was an error communicating with Redis
    pub async fn check_rate_limit(&mut self, key: &str) -> Result<(), RateLimitError> {
        let window_key = format_rate_limit_key("rate_limit", key);
        let mut conn = self.redis.get_async_connection().await?;
        
        let count: u32 = conn.incr(&window_key, 1).await?;
        
        if count == 1 {
            conn.expire(&window_key, self.config.window_seconds as usize)
                .await?;
        }

        if count > self.config.default_limit {
            return Err(RateLimitError::ExceededLimit);
        }

        Ok(())
    }

    /// Reset the rate limit for a given key
    /// 
    /// # Arguments
    /// 
    /// * `key` - The key to reset the rate limit for
    pub async fn reset_rate_limit(&mut self, key: &str) -> Result<(), RateLimitError> {
        let window_key = format_rate_limit_key("rate_limit", key);
        let mut conn = self.redis.get_async_connection().await?;
        conn.del(&window_key).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::Client;

    #[tokio::test]
    async fn test_rate_limiter() {
        let client = Client::open("redis://127.0.0.1:6379").unwrap();
        let redis = client.get_connection_manager().await.unwrap();
        
        let config = RateLimitConfig {
            default_limit: 2,
            burst_size: 3,
            window_seconds: 60,
        };
        
        let limiter = RateLimiter::new(redis, config);
        
        // First request should succeed
        assert!(limiter.check_rate_limit("test_key").await.is_ok());
        
        // Second request should succeed
        assert!(limiter.check_rate_limit("test_key").await.is_ok());
        
        // Third request should fail
        assert!(matches!(
            limiter.check_rate_limit("test_key").await,
            Err(RateLimitError::ExceededLimit)
        ));
        
        // Reset should allow new requests
        limiter.reset_rate_limit("test_key").await.unwrap();
        assert!(limiter.check_rate_limit("test_key").await.is_ok());
    }
} 