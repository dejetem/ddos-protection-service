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
use log::info;
use std::sync::Arc;
use tokio::sync::Mutex;
use redis::Client as RedisClient;

use crate::core::{RateLimiter, DdosDetector};
use crate::models::Config;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    dotenv().ok();
    
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    info!("Starting DDoS Protection Service...");
    
    // Load configuration
    let config = config::load_config().expect("Failed to load configuration");
    
    // Initialize Redis client
    let redis_client = RedisClient::open(config.redis.url.as_str())
        .expect("Failed to create Redis client");
    
    // Initialize rate limiter
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new(
        redis_client.clone(),
        config.rate_limit.clone(),
    )));

    // Initialize DDoS detector
    let ddos_detector = Arc::new(Mutex::new(DdosDetector::new(
        redis_client.clone(),
        config.ddos_detection.clone(),
    )));
    
    // Create API state
    let state = web::Data::new(api::ApiState {
        rate_limiter,
        ddos_detector,
        config: config.clone(),
    });
    
    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(state.clone())
            .configure(api::config)
    })
    .bind((config.server.host.as_str(), config.server.port))?
    .run()
    .await
}
