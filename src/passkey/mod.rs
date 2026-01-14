//! Passkey authentication module
//!
//! Provides WebAuthn-based passkey authentication for the auth service.

pub mod html;
pub mod login;
pub mod setup;

pub use login::validate_session_from_headers;
