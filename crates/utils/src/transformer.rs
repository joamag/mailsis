//! In-pipeline email message transformations.
//!
//! Transformers run after the SMTP `DATA` phase and before routing,
//! allowing headers to be injected, authentication results to be checked,
//! or other modifications to be applied to an [`EmailMessage`] in place.
//! Concrete implementations live in the [`transformers`](crate::transformers)
//! module.

use std::{future::Future, pin::Pin};

use tracing::debug;

use crate::EmailMessage;

/// Boxed future type for transformer operations, enabling async transformers.
pub type TransformFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Trait for message transformers that modify emails in the pipeline.
///
/// Transformers run after [`EmailMessage`] construction and before routing,
/// allowing in-place modification of message fields and body.
/// Transformers may perform async operations such as DNS lookups.
pub trait MessageTransformer: Send + Sync {
    /// Transforms an email message in place, possibly performing async operations.
    fn transform<'a>(&'a self, message: &'a mut EmailMessage) -> TransformFuture<'a>;

    /// Returns the name of this transformer.
    fn name(&self) -> &str;

    /// Applies a list of transformers to a message in order.
    fn apply<'a>(
        transformers: &'a [Box<dyn MessageTransformer>],
        message: &'a mut EmailMessage,
    ) -> TransformFuture<'a>
    where
        Self: Sized,
    {
        Box::pin(async move {
            for transformer in transformers {
                debug!(transformer = transformer.name(), "Applying transformer");
                transformer.transform(message).await;
            }
            message.rebuild();
        })
    }
}
