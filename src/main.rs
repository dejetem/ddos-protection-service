//! DDoS Protection Service
//! 
//! This is the main entry point for the DDoS protection service.
//! It initializes the application components and starts the web server.

mod api;
mod config;
mod core;
mod models;
mod utils;

use actix_web::{web, App, HttpServer};
use actix_web::middleware::Logger;
use dotenv::dotenv;
use log::{info, error};
use std::sync::Arc;
use tokio::sync::broadcast;
use redis::Client as RedisClient;
use std::time::Duration;

use crate::models::Config;
use crate::core::{Analytics, Monitoring, RuleEngine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();
    info!("Starting DDoS Protection Service...");

    // Load configuration
    let config = Config::from_env()?;
    info!("Configuration loaded successfully");

    // Initialize Redis connection
    let redis_client = RedisClient::open(config.redis.url.clone())?;
    let _redis_conn = redis_client.get_async_connection().await?;
    info!("Connected to Redis successfully");

    // Initialize services with their configurations
    let analytics = Arc::new(Analytics::new(
        redis_client.clone(),
        config.analytics.clone(),
        Duration::from_secs(config.analytics.retention_days * 24 * 60 * 60),
    ));

    let monitoring = Arc::new(Monitoring::new(
        redis_client.clone(),
        config.monitoring.clone(),
    ));

    let rule_engine = Arc::new(RuleEngine::new(
        redis_client.clone(),
        config.rule_config.clone(),
    ));

    // Start background tasks
    let analytics_clone = analytics.clone();
    let monitoring_clone = monitoring.clone();
    let rule_engine_clone = rule_engine.clone();

    // Create shutdown signal
    let (shutdown_tx, _shutdown_rx) = broadcast::channel(1);
    let mut shutdown_rx_clone = shutdown_tx.subscribe();

    // Spawn background tasks
    let analytics_handle = tokio::spawn(async move {
        if let Err(e) = analytics_clone.start_collection().await {
            error!("Analytics processing error: {}", e);
        }
    });

    let monitoring_handle = tokio::spawn(async move {
        if let Err(e) = monitoring_clone.start_monitoring().await {
            error!("Monitoring error: {}", e);
        }
    });

    let rule_engine_handle = tokio::spawn(async move {
        if let Err(e) = rule_engine_clone.process_rules().await {
            error!("Rule engine processing error: {}", e);
        }
    });

    // Handle shutdown signals
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    
    tokio::select! {
        _ = &mut ctrl_c => {
            info!("Received shutdown signal");
            let _ = shutdown_tx.send(());
        }
    }

    // Wait for shutdown signal
    let _ = shutdown_rx_clone.recv().await;
    info!("Shutting down...");

    // Cancel all background tasks
    analytics_handle.abort();
    monitoring_handle.abort();
    rule_engine_handle.abort();

    info!("Shutdown complete");
    Ok(())
}
