//! OAuth 2.1 implementation
//!
//! Implements:
//! - RFC 8414: OAuth 2.0 Authorization Server Metadata
//! - RFC 7591: OAuth 2.0 Dynamic Client Registration
//! - OAuth 2.1 Authorization Code flow with PKCE

pub mod authorize;
pub mod metadata;
pub mod registration;
pub mod token;
