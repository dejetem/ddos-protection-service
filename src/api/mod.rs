//! API endpoints for the DDoS protection service.
//! 
//! This module provides HTTP endpoints for interacting with the service,
//! including rate limit management and DDoS protection configuration.

use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::core::{RateLimiter, DdosDetector};
use crate::models::Config;

pub struct ApiState {
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    pub ddos_detector: Arc<Mutex<DdosDetector>>,
    pub config: Config,
}

/// API configuration function for Actix-web
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .service(web::resource("/health").route(web::get().to(health_check)))
            .service(web::resource("/rate-limit").route(web::post().to(check_rate_limit)))
    );
}

/// Health check endpoint response
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

/// Rate limit check request
#[derive(Debug, Serialize, Deserialize)]
pub struct RateLimitRequest {
    pub ip: String,
}

/// Rate limit check response
#[derive(Serialize)]
struct RateLimitResponse {
    allowed: bool,
    message: String,
    remaining: Option<u32>,
    retry_after: Option<u64>,
}

/// Health check endpoint
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Rate limit check endpoint
pub async fn check_rate_limit(
    state: web::Data<ApiState>,
    req: web::Json<RateLimitRequest>,
) -> impl Responder {
    let ip = req.ip.clone();
    
    // Check for DDoS activity first
    let mut detector = state.ddos_detector.lock().await;
    if let Err(e) = detector.check_connection(&ip).await {
        return HttpResponse::TooManyRequests().json(RateLimitResponse {
            allowed: false,
            message: format!("DDoS protection triggered: {}", e),
            remaining: None,
            retry_after: None,
        });
    }
    
    // Then check rate limit
    let mut limiter = state.rate_limiter.lock().await;
    match limiter.check_rate_limit(&ip).await {
        Ok(()) => HttpResponse::Ok().json(RateLimitResponse {
            allowed: true,
            message: "Request allowed".to_string(),
            remaining: None,
            retry_after: None,
        }),
        Err(_) => HttpResponse::TooManyRequests().json(RateLimitResponse {
            allowed: false,
            message: "Rate limit exceeded".to_string(),
            remaining: None,
            retry_after: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use redis::Client;

    #[actix_web::test]
    async fn test_health_check() {
        let app = test::init_service(
            App::new()
                .configure(config)
        ).await;

        let req = test::TestRequest::get().uri("/api/v1/health").to_request();
        let resp = test::call_service(&app, req).await;
        
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_rate_limit() {
        let client = Client::open("redis://127.0.0.1:6379").unwrap();
        let config = Config::default();
        let rate_limiter = Arc::new(Mutex::new(RateLimiter::new(
            client.clone(),
            config.rate_limit.clone(),
        )));
        let ddos_detector = Arc::new(Mutex::new(DdosDetector::new(
            client.clone(),
            config.ddos_detection.clone(),
        )));

        let state = web::Data::new(ApiState {
            rate_limiter,
            ddos_detector,
            config,
        });

        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .configure(config)
        ).await;

        let req = test::TestRequest::post()
            .uri("/api/v1/rate-limit")
            .set_json(RateLimitRequest {
                ip: "127.0.0.1".to_string(),
            })
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
} 