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
use dotenv::dotenv;
use log::info;
use std::sync::Arc;
use std::sync::Mutex;
use redis::Client;
use crate::api::{ApiState, check_rate_limit};
use crate::core::RateLimiter;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    dotenv().ok();
    
    // Initialize logging
    env_logger::init();
    
    info!("Starting DDoS Protection Service...");
    
    // Load configuration
    let config = config::load_config().expect("Failed to load configuration");
    let config = Arc::new(config);
    
    // Initialize Redis client
    let redis_client = Client::open(config.redis.url.as_str())
        .expect("Failed to create Redis client");
    
    // Initialize rate limiter
    let rate_limiter = RateLimiter::new(redis_client, config.rate_limit.clone());
    let rate_limiter = Arc::new(Mutex::new(rate_limiter));
    
    // Create API state
    let state = web::Data::new(ApiState {
        rate_limiter,
        config: config.clone(),
    });
    
    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(
                web::scope("/api")
                    .route("/rate-limit", web::post().to(check_rate_limit))
            )
    })
    .bind((config.server.host.as_str(), config.server.port))?
    .run()
    .await
}
