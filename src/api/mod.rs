//! API endpoints for the DDoS protection service.
//! 
//! This module provides HTTP endpoints for interacting with the service,
//! including rate limit management, DDoS protection configuration,
//! rule engine management, analytics, and monitoring.

use actix_web::{web, HttpResponse, Responder, HttpRequest};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::core::{RateLimiter, DdosDetector, RuleEngine, Rule, Analytics, Monitoring, RuleCondition, RuleAction};
use crate::core::analytics::EventType;
use crate::models::Config;

pub struct ApiState {
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    pub ddos_detector: Arc<Mutex<DdosDetector>>,
    pub rule_engine: Arc<Mutex<RuleEngine>>,
    pub analytics: Arc<Mutex<Analytics>>,
    pub monitoring: Arc<Mutex<Monitoring>>,
    pub config: Config,
}

/// API configuration function for Actix-web
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .service(web::resource("/health").route(web::get().to(health_check)))
            .service(web::resource("/rate-limit").route(web::post().to(check_rate_limit)))
            .service(web::resource("/ddos-check").route(web::post().to(check_ddos)))
            .service(web::resource("/rules").route(web::get().to(get_rules)))
            .service(web::resource("/rules").route(web::post().to(create_rule)))
            .service(web::resource("/rules/{id}").route(web::get().to(get_rule)))
            .service(web::resource("/rules/{id}").route(web::put().to(update_rule)))
            .service(web::resource("/rules/{id}").route(web::delete().to(delete_rule)))
            .service(web::resource("/analytics/metrics").route(web::get().to(get_analytics_metrics)))
            .service(web::resource("/analytics/events").route(web::get().to(get_analytics_events)))
            .service(web::resource("/monitoring/metrics").route(web::get().to(get_monitoring_metrics)))
            .service(web::resource("/monitoring/alerts").route(web::get().to(get_monitoring_alerts)))
            .service(web::resource("/monitoring/alerts/{id}/acknowledge").route(web::post().to(acknowledge_alert)))
    );
}

/// Health check endpoint response
#[derive(Serialize)]
pub struct HealthCheckResponse {
    status: String,
    version: String,
}

/// Rate limit request
#[derive(Deserialize)]
pub struct RateLimitRequest {
    ip: String,
    path: String,
}

/// Rate limit response
#[derive(Serialize)]
pub struct RateLimitResponse {
    allowed: bool,
    remaining: u32,
    reset: u64,
}

/// DDoS check request
#[derive(Deserialize)]
pub struct DdosCheckRequest {
    ip: String,
    request_size: u64,
}

/// DDoS check response
#[derive(Serialize)]
pub struct DdosCheckResponse {
    is_under_attack: bool,
    detection_type: Option<String>,
}

/// Rule request
#[derive(Deserialize)]
pub struct RuleRequest {
    name: String,
    description: Option<String>,
    conditions: Vec<RuleCondition>,
    actions: Vec<RuleAction>,
    priority: i32,
    enabled: bool,
}

/// Rule response
#[derive(Serialize)]
pub struct RuleResponse {
    id: String,
    name: String,
    description: Option<String>,
    conditions: Vec<RuleCondition>,
    actions: Vec<RuleAction>,
    priority: i32,
    enabled: bool,
}

/// Analytics events request
#[derive(Deserialize)]
pub struct AnalyticsEventsRequest {
    start_time: u64,
    end_time: u64,
    event_type: Option<String>,
}

/// Health check endpoint
pub async fn health_check() -> impl Responder {
    let response = HealthCheckResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    
    HttpResponse::Ok().json(response)
}

/// Rate limit check endpoint
pub async fn check_rate_limit(
    state: web::Data<ApiState>,
    req: HttpRequest,
) -> impl Responder {
    let key = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    let mut rate_limiter = state.rate_limiter.lock().await;
    
    match rate_limiter.check_rate_limit(&key).await {
        Ok(_) => {
            let remaining = rate_limiter.get_remaining(&key).await;
            let reset = rate_limiter.get_reset_time(&key).await.unwrap_or(0);
            
            HttpResponse::Ok().json(RateLimitResponse {
                allowed: true,
                remaining: remaining.try_into().unwrap_or(0),
                reset,
            })
        }
        Err(_) => {
            let reset = rate_limiter.get_reset_time(&key).await.unwrap_or(0);
            
            HttpResponse::TooManyRequests().json(RateLimitResponse {
                allowed: false,
                remaining: 0,
                reset,
            })
        }
    }
}

/// DDoS check endpoint
pub async fn check_ddos(
    state: web::Data<ApiState>,
    req: web::Json<DdosCheckRequest>,
) -> impl Responder {
    let mut ddos_detector = state.ddos_detector.lock().await;
    
    match ddos_detector.check_request(&req.ip, req.request_size).await {
        Ok(is_under_attack) => {
            let response = DdosCheckResponse {
                is_under_attack,
                detection_type: if is_under_attack {
                    Some("request_rate".to_string())
                } else {
                    None
                },
            };
            
            HttpResponse::Ok().json(response)
        },
        Err(_) => {
            HttpResponse::InternalServerError().finish()
        },
    }
}

/// Get all rules endpoint
pub async fn get_rules(
    state: web::Data<ApiState>,
) -> impl Responder {
    let rule_engine = state.rule_engine.lock().await;
    let rules = rule_engine.get_rules().await;
    
    let response: Vec<RuleResponse> = rules.iter().map(|rule| {
        RuleResponse {
            id: rule.id.clone(),
            name: rule.name.clone(),
            description: rule.description.clone(),
            conditions: rule.conditions.clone(),
            actions: rule.actions.clone(),
            priority: rule.priority,
            enabled: rule.enabled,
        }
    }).collect();
    
    HttpResponse::Ok().json(response)
}

/// Create rule endpoint
pub async fn create_rule(
    state: web::Data<ApiState>,
    req: web::Json<RuleRequest>,
) -> impl Responder {
    let mut rule_engine = state.rule_engine.lock().await;
    
    // Generate a unique ID
    let id = format!("rule_{}", Uuid::new_v4());
    
    let rule = Rule {
        id: id.clone(),
        name: req.name.clone(),
        description: req.description.clone(),
        conditions: req.conditions.clone(),
        actions: req.actions.clone(),
        priority: req.priority,
        enabled: req.enabled,
    };
    
    rule_engine.add_rule(rule);
    
    let response = RuleResponse {
        id,
        name: req.name.clone(),
        description: req.description.clone(),
        conditions: req.conditions.clone(),
        actions: req.actions.clone(),
        priority: req.priority,
        enabled: req.enabled,
    };
    
    HttpResponse::Created().json(response)
}

/// Get rule by ID endpoint
pub async fn get_rule(
    state: web::Data<ApiState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let rule_engine = state.rule_engine.lock().await;
    
    if let Some(rule) = rule_engine.get_rule(&id).await {
        HttpResponse::Ok().json(RuleResponse {
            id: rule.id,
            name: rule.name,
            description: rule.description,
            conditions: rule.conditions,
            actions: rule.actions,
            priority: rule.priority,
            enabled: rule.enabled,
        })
    } else {
        HttpResponse::NotFound().finish()
    }
}

/// Update rule endpoint
pub async fn update_rule(
    state: web::Data<ApiState>,
    path: web::Path<String>,
    rule: web::Json<RuleRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let mut rule_engine = state.rule_engine.lock().await;
    let updated_rule = Rule {
        id: id.clone(),
        name: rule.name.clone(),
        description: rule.description.clone(),
        conditions: rule.conditions.clone(),
        actions: rule.actions.clone(),
        priority: rule.priority,
        enabled: rule.enabled,
    };
    
    if rule_engine.update_rule(&id, updated_rule).await {
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::NotFound().finish()
    }
}

/// Delete rule endpoint
pub async fn delete_rule(
    state: web::Data<ApiState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let mut rule_engine = state.rule_engine.lock().await;
    
    if rule_engine.remove_rule(&id).await {
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::NotFound().finish()
    }
}

/// Get analytics metrics endpoint
pub async fn get_analytics_metrics(
    state: web::Data<ApiState>,
) -> impl Responder {
    let analytics = state.analytics.lock().await;
    
    match analytics.get_metrics().await {
        Ok(metrics) => {
            HttpResponse::Ok().json(metrics)
        }
        Err(e) => {
            log::error!("Failed to get metrics: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Get analytics events endpoint
pub async fn get_analytics_events(
    state: web::Data<ApiState>,
    query: web::Query<AnalyticsEventsRequest>,
) -> impl Responder {
    let analytics = state.analytics.lock().await;
    
    let event_type = query.event_type.as_ref().map(|t| {
        match t.as_str() {
            "Request" => EventType::Request,
            "RateLimit" => EventType::RateLimit,
            "DdosDetection" => EventType::DdosDetection,
            "RuleEngine" => EventType::RuleEngine,
            "System" => EventType::System,
            _ => EventType::Request,
        }
    });
    
    match analytics.get_events(query.start_time, query.end_time, event_type).await {
        Ok(events) => {
            HttpResponse::Ok().json(events)
        },
        Err(_) => {
            HttpResponse::InternalServerError().finish()
        },
    }
}

/// Get monitoring metrics endpoint
pub async fn get_monitoring_metrics(
    state: web::Data<ApiState>,
) -> impl Responder {
    let monitoring = state.monitoring.lock().await;
    
    match monitoring.get_current_metrics().await {
        Ok(metrics) => {
            HttpResponse::Ok().json(metrics)
        },
        Err(_) => {
            HttpResponse::InternalServerError().finish()
        },
    }
}

/// Get monitoring alerts endpoint
pub async fn get_monitoring_alerts(
    state: web::Data<ApiState>,
) -> impl Responder {
    let monitoring = state.monitoring.lock().await;
    
    let alerts = monitoring.get_active_alerts().await;
    HttpResponse::Ok().json(alerts)
}

/// Acknowledge alert endpoint
pub async fn acknowledge_alert(
    state: web::Data<ApiState>,
    path: web::Path<String>,
) -> impl Responder {
    let monitoring = state.monitoring.lock().await;
    let id = path.into_inner();
    
    match monitoring.acknowledge_alert(&id).await {
        Ok(()) => {
            HttpResponse::NoContent().finish()
        },
        Err(_) => {
            HttpResponse::InternalServerError().finish()
        },
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