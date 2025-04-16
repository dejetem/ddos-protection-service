//! Custom rule engine for the DDoS protection service.
//! 
//! This module provides a flexible rule engine that allows defining
//! custom detection and mitigation rules based on various conditions.

use std::collections::HashMap;
use redis::Client as RedisClient;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use anyhow::Result;
use thiserror::Error;
use crate::models::RuleConfig;
use crate::core::monitoring::{Alert, MonitoringError};
use std::time::Duration;
use log::{info, error};

/// Errors that can occur during rule evaluation
#[derive(Error, Debug)]
pub enum RuleEngineError {
    #[error("Rule evaluation error: {0}")]
    EvaluationError(String),
    #[error("Rule parsing error: {0}")]
    ParsingError(String),
}

/// Rule operator for comparing values
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleOperator {
    /// Equal to
    Equals,
    /// Not equal to
    NotEquals,
    /// Greater than
    GreaterThan,
    /// Less than
    LessThan,
    /// Greater than or equal to
    GreaterThanOrEqual,
    /// Less than or equal to
    LessThanOrEqual,
    /// Contains
    Contains,
    /// Not contains
    NotContains,
    /// In range
    InRange,
    /// Not in range
    NotInRange,
}

/// Rule condition type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    RequestRate {
        threshold: u32,
        window_seconds: u32,
    },
    TrafficVolume {
        threshold_bytes: u64,
        window_seconds: u32,
    },
    UserAgent {
        pattern: String,
    },
    IpReputation {
        min_score: f32,
    },
}

/// Rule action type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    Block {
        duration_seconds: u32,
    },
    RateLimit {
        requests_per_second: u32,
    },
    Log {
        level: String,
        message: String,
    },
    Notify {
        channel: String,
        message: String,
    },
}

/// Rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Rule ID
    pub id: String,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: Option<String>,
    /// Rule conditions
    pub conditions: Vec<RuleCondition>,
    /// Rule actions
    pub actions: Vec<RuleAction>,
    /// Rule priority (higher numbers have higher priority)
    pub priority: i32,
    /// Whether the rule is enabled
    pub enabled: bool,
}

/// Rule engine state
pub struct RuleEngine {
    redis_client: RedisClient,
    config: RuleConfig,
    rules: RwLock<HashMap<String, Rule>>,
}

impl RuleEngine {
    /// Create a new rule engine instance
    pub fn new(redis_client: RedisClient, config: RuleConfig) -> Self {
        Self {
            redis_client,
            config,
            rules: RwLock::new(HashMap::new()),
        }
    }

    /// Load rules from storage
    pub async fn load_rules(&self) -> Result<()> {
        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(e) => return Err(anyhow::anyhow!("Redis connection error: {}", e)),
        };
        let rules_json: Option<String> = match redis::cmd("GET")
            .arg("rules")
            .query_async(&mut conn)
            .await {
                Ok(rules) => rules,
                Err(e) => return Err(anyhow::anyhow!("Redis query error: {}", e)),
            };

        if let Some(json) = rules_json {
            let rules: HashMap<String, Rule> = match serde_json::from_str(&json) {
                Ok(rules) => rules,
                Err(e) => return Err(anyhow::anyhow!("Rule parsing error: {}", e)),
            };
            let mut rules_lock = self.rules.write().await;
            *rules_lock = rules;
        }

        Ok(())
    }

    /// Save rules to storage
    pub async fn save_rules(&self) -> Result<()> {
        let rules_lock = self.rules.read().await;
        let rules_json = match serde_json::to_string(&*rules_lock) {
            Ok(json) => json,
            Err(e) => return Err(anyhow::anyhow!("Rule serialization error: {}", e)),
        };

        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(e) => return Err(anyhow::anyhow!("Redis connection error: {}", e)),
        };
        let _: () = match redis::cmd("SET")
            .arg("rules")
            .arg(rules_json)
            .query_async::<_, ()>(&mut conn)
            .await {
                Ok(_) => (),
                Err(e) => return Err(anyhow::anyhow!("Redis query error: {}", e)),
            };

        Ok(())
    }

    /// Add a new rule
    pub async fn add_rule(&mut self, rule: Rule) {
        let mut rules_lock = self.rules.write().await;
        rules_lock.insert(rule.id.clone(), rule);
        drop(rules_lock);
        let _ = self.save_rules().await;
    }

    /// Get a rule by ID
    pub async fn get_rule(&self, id: &str) -> Option<Rule> {
        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(_) => return None,
        };
        
        let rules_json: Vec<String> = match redis::cmd("ZRANGE")
            .arg("rules")
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await {
                Ok(rules) => rules,
                Err(_) => return None,
            };

        rules_json
            .into_iter()
            .filter_map(|json| serde_json::from_str(&json).ok())
            .find(|rule: &Rule| rule.id == id)
    }

    /// Get all rules
    pub async fn get_rules(&self) -> Vec<Rule> {
        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(_) => return vec![],
        };

        let rules_json: Vec<String> = match redis::cmd("ZRANGE")
            .arg("rules")
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await {
                Ok(rules) => rules,
                Err(_) => return vec![],
            };

        rules_json
            .into_iter()
            .filter_map(|json| serde_json::from_str(&json).ok())
            .collect()
    }

    /// Update an existing rule
    pub async fn update_rule(&mut self, id: &str, updated_rule: Rule) -> bool {
        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(_) => return false,
        };
        
        let rules_json: Vec<String> = match redis::cmd("ZRANGE")
            .arg("rules")
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await {
                Ok(rules) => rules,
                Err(_) => return false,
            };

        let mut found = false;
        for json in rules_json {
            if let Ok(rule) = serde_json::from_str::<Rule>(&json) {
                if rule.id == id {
                    found = true;
                    let updated_json = match serde_json::to_string(&updated_rule) {
                        Ok(json) => json,
                        Err(_) => continue,
                    };
                    let _: Result<(), redis::RedisError> = redis::pipe()
                        .atomic()
                        .cmd("ZREM")
                        .arg("rules")
                        .arg(json)
                        .cmd("ZADD")
                        .arg("rules")
                        .arg(updated_rule.priority)
                        .arg(updated_json)
                        .query_async(&mut conn)
                        .await;
                    break;
                }
            }
        }

        found
    }

    /// Remove a rule
    pub async fn remove_rule(&mut self, id: &str) -> bool {
        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(_) => return false,
        };
        
        let rules_json: Vec<String> = match redis::cmd("ZRANGE")
            .arg("rules")
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await {
                Ok(rules) => rules,
                Err(_) => return false,
            };

        let mut found = false;
        for json in rules_json {
            if let Ok(rule) = serde_json::from_str::<Rule>(&json) {
                if rule.id == id {
                    found = true;
                    let _: Result<(), redis::RedisError> = redis::cmd("ZREM")
                        .arg("rules")
                        .arg(json)
                        .query_async(&mut conn)
                        .await;
                    break;
                }
            }
        }

        found
    }

    /// Evaluate rules for a request
    pub async fn evaluate_request(
        &self,
        ip: &str,
        _request_size: u64,
        user_agent: &str,
    ) -> Result<Vec<RuleAction>> {
        let mut actions = Vec::new();
        let rules_lock = self.rules.read().await;

        for rule in rules_lock.values() {
            if !rule.enabled {
                continue;
            }

            let mut conditions_met = true;
            for condition in &rule.conditions {
                match condition {
                    RuleCondition::RequestRate { threshold, window_seconds } => {
                        let key = format!("request_rate:{}:{}", ip, window_seconds);
                        let count = match self.get_counter(&key).await {
                            Ok(count) => count,
                            Err(_) => continue,
                        };
                        if count <= *threshold as i64 {
                            conditions_met = false;
                            break;
                        }
                    },
                    RuleCondition::TrafficVolume { threshold_bytes, window_seconds } => {
                        let key = format!("traffic_volume:{}:{}", ip, window_seconds);
                        let volume = match self.get_counter(&key).await {
                            Ok(volume) => volume,
                            Err(_) => continue,
                        };
                        if volume <= *threshold_bytes as i64 {
                            conditions_met = false;
                            break;
                        }
                    },
                    RuleCondition::UserAgent { pattern } => {
                        if !user_agent.contains(pattern) {
                            conditions_met = false;
                            break;
                        }
                    },
                    RuleCondition::IpReputation { min_score } => {
                        let score = match self.get_ip_reputation(ip).await {
                            Ok(score) => score,
                            Err(_) => continue,
                        };
                        if score < *min_score {
                            conditions_met = false;
                            break;
                        }
                    },
                }
            }

            if conditions_met {
                actions.extend(rule.actions.clone());
            }
        }

        Ok(actions)
    }

    /// Get a counter value from Redis
    async fn get_counter(&self, key: &str) -> Result<i64> {
        let mut conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(e) => return Err(anyhow::anyhow!("Redis connection error: {}", e)),
        };
        let count: Option<i64> = match redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await {
                Ok(count) => count,
                Err(e) => return Err(anyhow::anyhow!("Redis query error: {}", e)),
            };
        Ok(count.unwrap_or(0))
    }

    /// Get IP reputation score (placeholder implementation)
    async fn get_ip_reputation(&self, _ip: &str) -> Result<f32> {
        // TODO: Implement actual IP reputation lookup
        Ok(5.0)
    }

    pub async fn get_alerts(&self) -> Result<Vec<Alert>, MonitoringError> {
        let _conn = match self.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(_) => return Ok(Vec::new()),
        };

        Ok(Vec::new())
    }

    pub async fn process_rules(&self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            // Get all rules
            let rules = self.get_rules().await;
            
            // Process each rule
            for rule in &rules {
                if !rule.enabled {
                    continue;
                }

                // Check rule conditions
                if self.check_rule_conditions(rule).await? {
                    // Execute rule actions
                    self.execute_rule_actions(rule).await?;
                }
            }

            // Sleep for a short duration before next iteration
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn check_rule_conditions(&self, rule: &Rule) -> Result<bool, Box<dyn std::error::Error>> {
        let _conn = self.redis_client.get_async_connection().await?;
        
        // TODO: Implement rule condition checking logic
        // For now, just return true if the rule is enabled
        Ok(rule.enabled)
    }

    async fn execute_rule_actions(&self, rule: &Rule) -> Result<(), Box<dyn std::error::Error>> {
        let _conn = self.redis_client.get_async_connection().await?;
        
        // TODO: Implement rule action execution logic
        info!("Executing rule: {}", rule.name);
        Ok(())
    }
}

/// Load rules from configuration
pub fn load_rules(_config: &RuleConfig) -> Result<Vec<Rule>, RuleEngineError> {
    // In a real implementation, this would load rules from a file or database
    // For now, we'll just return an empty vector
    Ok(Vec::new())
}

impl redis::FromRedisValue for Rule {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let str_value: String = redis::FromRedisValue::from_redis_value(v)?;
        serde_json::from_str(&str_value)
            .map_err(|e| redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to parse Rule from JSON",
                e.to_string(),
            )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_rule_engine() {
        let mut engine = RuleEngine::new();
        
        // Create a rule
        let rule = Rule {
            id: "rule1".to_string(),
            name: "High Traffic Rule".to_string(),
            description: Some("Detect high traffic".to_string()),
            conditions: vec![
                RuleCondition::RequestRate {
                    threshold: 100,
                    window_seconds: 60,
                }
            ],
            actions: vec![
                RuleAction::Block {
                    duration_seconds: 300,
                }
            ],
            priority: 1,
            enabled: true,
        };
        
        // Add the rule
        engine.add_rule(rule);
        
        // Create a context
        let mut context = HashMap::new();
        context.insert("request_count".to_string(), serde_json::json!(150));
        
        // Evaluate rules
        let actions = engine.evaluate_request("127.0.0.1", 150, "Mozilla/5.0").await.unwrap();
        
        // Check that one action was triggered
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], RuleAction::Block { duration_seconds: 300 });
    }
} 