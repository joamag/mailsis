//! Built-in email transformations applied before delivery.
//!
//! Each transformer runs in the SMTP pipeline between message reception
//! and routing, enriching or normalizing the email. Currently supports
//! `Message-ID` header injection and SPF/DKIM/DMARC verification
//! (feature-gated behind `email-auth`).

#[cfg(feature = "email-auth")]
pub mod email_auth;
pub mod message_id;

#[cfg(feature = "email-auth")]
pub use email_auth::*;
pub use message_id::*;
