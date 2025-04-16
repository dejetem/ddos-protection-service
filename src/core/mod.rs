//! Core functionality for the DDoS protection service.
//! 
//! This module contains the core business logic for the service,
//! including rate limiting, DDoS detection, and traffic management.

mod cloudflare;
mod rate_limiter;
mod ddos_detector;

pub use cloudflare::{CloudflareClient, CloudflareError, Zone};
pub use rate_limiter::{RateLimiter, RateLimitError};
pub use ddos_detector::{DdosDetector, DdosDetectionConfig, DdosDetectionError}; 