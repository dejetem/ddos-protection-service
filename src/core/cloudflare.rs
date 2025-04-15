//! Cloudflare API client for the DDoS protection service.
//! 
//! This module provides functionality to interact with the Cloudflare API,
//! including retrieving zone information and managing DDoS protection settings.

use std::time::Duration;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during Cloudflare API operations
#[derive(Debug, Error)]
pub enum CloudflareError {
    #[error("API request failed: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

/// Cloudflare zone information
#[derive(Debug, Deserialize)]
pub struct Zone {
    /// Zone ID
    pub id: String,
    /// Zone name
    pub name: String,
    /// Zone status
    pub status: String,
}

/// Cloudflare API client
pub struct CloudflareClient {
    /// HTTP client
    client: Client,
    /// API token
    api_token: String,
    /// Zone ID
    zone_id: Option<String>,
}

impl CloudflareClient {
    /// Create a new Cloudflare client instance
    pub fn new(api_token: String, zone_id: Option<String>) -> Self {
        Self {
            client: Client::new(),
            api_token,
            zone_id,
        }
    }

    /// Get the zone ID for a domain
    /// 
    /// If a zone ID is already configured, it will be returned.
    /// Otherwise, it will be retrieved from the Cloudflare API.
    /// 
    /// # Arguments
    /// 
    /// * `domain` - The domain to get the zone ID for
    /// 
    /// # Returns
    /// 
    /// * `Ok(String)` if the zone ID was found
    /// * `Err(CloudflareError)` if there was an error retrieving the zone ID
    pub async fn get_zone_id(&self, domain: &str) -> Result<String, CloudflareError> {
        // If zone ID is already configured, return it
        if let Some(zone_id) = &self.zone_id {
            return Ok(zone_id.clone());
        }
        
        // Otherwise, retrieve it from the API
        let url = "https://api.cloudflare.com/client/v4/zones";
        let response = self.client
            .get(url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .send()
            .await?;
        
        let zones: Vec<Zone> = response.json().await?;
        
        // Find the zone for the domain
        let zone = zones.into_iter()
            .find(|z| z.name == domain)
            .ok_or(CloudflareError::InvalidResponse("No zones found".to_string()))?;
        
        Ok(zone.id)
    }
    
    /// Update DDoS protection settings for a zone
    /// 
    /// # Arguments
    /// 
    /// * `settings` - The DDoS protection settings to apply
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` if the settings were updated successfully
    /// * `Err(CloudflareError)` if there was an error updating the settings
    pub async fn update_ddos_protection(&self, settings: DdosProtectionSettings) -> Result<(), CloudflareError> {
        // TODO: Implement Cloudflare API calls
        Ok(())
    }
}

/// DDoS protection settings
#[derive(Debug, Serialize)]
pub struct DdosProtectionSettings {
    /// Security level
    pub security_level: String,
    /// Challenge pass duration
    pub challenge_pass: Duration,
    /// Browser check
    pub browser_check: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_get_zone_id() {
        let client = CloudflareClient::new("test_token".to_string(), Some("test_zone_id".to_string()));
        let zone_id = client.get_zone_id("example.com").await.unwrap();
        
        assert_eq!(zone_id, "test_zone_id");
    }
} 