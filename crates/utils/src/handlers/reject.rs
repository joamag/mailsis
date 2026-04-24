//! Void message handler that always refuses delivery.
//!
//! Provides [`RejectHandler`], a [`MessageHandler`](crate::MessageHandler)
//! implementation that never stores or forwards a message and instead
//! returns a [`HandlerError::Rejected`] carrying a configurable SMTP reply.

use tracing::{info, warn};

use crate::{
    handler::{HandlerError, HandlerFuture, MessageHandler},
    EmailMessage,
};

/// Message handler that always refuses delivery.
pub struct RejectHandler {
    code: u16,
    message: String,
}

impl RejectHandler {
    /// Creates a new [`RejectHandler`] with the given reply code and message.
    pub fn new(code: u16, message: String) -> Self {
        info!(
            code = code,
            message = %message,
            "Reject handler initialized"
        );
        Self { code, message }
    }

    /// Returns the configured SMTP reply code.
    pub fn code(&self) -> u16 {
        self.code
    }

    /// Returns the configured SMTP reply message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl MessageHandler for RejectHandler {
    fn handle<'a>(&'a self, message: &'a EmailMessage) -> HandlerFuture<'a> {
        Box::pin(async move {
            warn!(
                message_id = %message.message_id,
                to = %message.to,
                code = self.code,
                "Rejecting message"
            );
            Err(HandlerError::Rejected(self.message.clone()))
        })
    }

    fn name(&self) -> &str {
        "reject"
    }

    fn reject_reply(&self) -> Option<(u16, String)> {
        Some((self.code, self.message.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_reject_handler_returns_rejected_error() {
        let handler = RejectHandler::new(550, "Relay access denied".to_string());
        let message = EmailMessage::from_raw("sender@example.com", "rcpt@example.com", "Hi");

        let result = handler.handle(&message).await;
        match result {
            Err(HandlerError::Rejected(msg)) => {
                assert_eq!(msg, "Relay access denied");
            }
            other => panic!("Expected Rejected error, got {other:?}"),
        }
        assert_eq!(
            handler.reject_reply(),
            Some((550, "Relay access denied".to_string()))
        );
    }

    #[test]
    fn test_reject_handler_name() {
        let handler = RejectHandler::new(550, "Relay access denied".to_string());
        assert_eq!(handler.name(), "reject");
    }

    #[test]
    fn test_reject_handler_accessors() {
        let handler = RejectHandler::new(521, "No mail accepted here".to_string());
        assert_eq!(handler.code(), 521);
        assert_eq!(handler.message(), "No mail accepted here");
    }
}
