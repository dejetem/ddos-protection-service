//! Core functionality for the DDoS protection service.
//! 
//! This module contains the core business logic for the service,
//! including rate limiting, DDoS detection, and traffic management.

pub mod cloudflare;
pub mod rate_limiter;

pub use cloudflare::{CloudflareClient, CloudflareError, DdosProtectionSettings};
pub use rate_limiter::{RateLimiter, RateLimitError}; 