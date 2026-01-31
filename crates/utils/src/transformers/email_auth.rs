//! SPF, DKIM, and DMARC verification for incoming emails.
//!
//! Checks each message against the sender's published DNS policies and
//! prepends an `Authentication-Results` header with the outcome. Results
//! are informational - messages are never rejected. Feature-gated behind
//! `email-auth`.

use mail_auth::{
    dmarc::verify::DmarcParameters, spf::verify::SpfParameters, AuthenticatedMessage, DkimResult,
    DmarcResult, MessageAuthenticator, SpfResult,
};
use tracing::{debug, info, warn};

use crate::{EmailMessage, MessageTransformer, TransformFuture};

/// Transformer that verifies SPF, DKIM, and DMARC authentication for incoming emails.
///
/// Results are informational only, an `Authentication-Results` header is prepended
/// to the message body and results are logged. Messages are never rejected.
pub struct EmailAuthTransformer {
    /// The authserv-id used in the Authentication-Results header (typically the server hostname).
    authserv_id: String,
    /// DNS resolver/authenticator for performing verification lookups.
    authenticator: MessageAuthenticator,
}

impl EmailAuthTransformer {
    /// Creates a new [`EmailAuthTransformer`] with the given authserv-id.
    ///
    /// Initializes a DNS resolver from the system configuration,
    /// falling back to Cloudflare DNS-over-TLS if system config is unavailable.
    pub async fn new(authserv_id: String) -> Self {
        let authenticator = MessageAuthenticator::new_system_conf().unwrap_or_else(|_| {
            warn!("Failed to load system DNS config, falling back to Cloudflare TLS");
            MessageAuthenticator::new_cloudflare_tls()
                .expect("Failed to create Cloudflare TLS resolver")
        });
        info!(authserv_id = %authserv_id, "Email auth transformer initialized");
        Self {
            authserv_id,
            authenticator,
        }
    }
}

impl MessageTransformer for EmailAuthTransformer {
    fn transform<'a>(&'a self, message: &'a mut EmailMessage) -> TransformFuture<'a> {
        Box::pin(async move {
            let client_ip = match message.client_ip {
                Some(ip) => ip,
                None => {
                    debug!("No client IP available, skipping email auth checks");
                    return;
                }
            };

            let helo_domain = message.helo_domain.as_deref().unwrap_or("unknown");

            let from_domain = message
                .from
                .rsplit('@')
                .next()
                .unwrap_or("unknown")
                .to_string();

            // SPF verification
            let spf_output = self
                .authenticator
                .verify_spf(SpfParameters::verify_mail_from(
                    client_ip,
                    helo_domain,
                    helo_domain,
                    &message.from,
                ))
                .await;
            let spf_result = spf_output.result();
            let spf_str = format_spf_result(spf_result);
            info!(
                from = %message.from,
                client_ip = %client_ip,
                result = %spf_str,
                "SPF verification"
            );

            // DKIM verification, use the original raw body to preserve
            // the exact byte sequence the sender signed.
            let dkim_str = if let Some(authenticated_message) =
                AuthenticatedMessage::parse(message.original_raw().as_bytes())
            {
                let dkim_output = self.authenticator.verify_dkim(&authenticated_message).await;
                let dkim_result = dkim_output
                    .first()
                    .map(|o| o.result().clone())
                    .unwrap_or(DkimResult::None);
                let result_str = format_dkim_result(&dkim_result);
                info!(
                    from = %message.from,
                    result = %result_str,
                    "DKIM verification"
                );

                // DMARC verification (requires SPF + DKIM results)
                let dmarc_output = self
                    .authenticator
                    .verify_dmarc(DmarcParameters::new(
                        &authenticated_message,
                        &dkim_output,
                        &from_domain,
                        &spf_output,
                    ))
                    .await;
                let dmarc_result = dmarc_output.dkim_result();
                let dmarc_spf_result = dmarc_output.spf_result();
                let dmarc_str = format_dmarc_result(dmarc_result);
                let dmarc_spf_str = format_dmarc_result(dmarc_spf_result);
                info!(
                    from = %message.from,
                    dkim = %dmarc_str,
                    spf = %dmarc_spf_str,
                    "DMARC verification"
                );

                let dmarc_policy_result = dmarc_output.policy();
                let auth_value = format!(
                    "{};\r\n\tspf={} smtp.mailfrom={};\r\n\tdkim={} header.from={};\r\n\tdmarc={} (p={:?}) header.from={}",
                    self.authserv_id,
                    spf_str,
                    message.from,
                    result_str,
                    from_domain,
                    dmarc_str,
                    dmarc_policy_result,
                    from_domain,
                );

                message.prepend_header("Authentication-Results", &auth_value);
                return;
            } else {
                debug!("Failed to parse message for DKIM verification");
                format_dkim_result(&DkimResult::None)
            };

            // If DKIM parsing failed, still add SPF-only results
            let auth_value = format!(
                "{};\r\n\tspf={} smtp.mailfrom={};\r\n\tdkim={}",
                self.authserv_id, spf_str, message.from, dkim_str,
            );
            message.prepend_header("Authentication-Results", &auth_value);
        })
    }

    fn name(&self) -> &str {
        "email_auth"
    }
}

fn format_spf_result(result: SpfResult) -> &'static str {
    match result {
        SpfResult::Pass => "pass",
        SpfResult::Fail => "fail",
        SpfResult::SoftFail => "softfail",
        SpfResult::Neutral => "neutral",
        SpfResult::None => "none",
        SpfResult::TempError => "temperror",
        SpfResult::PermError => "permerror",
    }
}

fn format_dkim_result(result: &DkimResult) -> &'static str {
    match result {
        DkimResult::Pass => "pass",
        DkimResult::Fail(_) => "fail",
        DkimResult::Neutral(_) => "neutral",
        DkimResult::None => "none",
        DkimResult::TempError(_) => "temperror",
        DkimResult::PermError(_) => "permerror",
    }
}

fn format_dmarc_result(result: &DmarcResult) -> &'static str {
    match result {
        DmarcResult::Pass => "pass",
        DmarcResult::Fail(_) => "fail",
        DmarcResult::TempError(_) => "temperror",
        DmarcResult::PermError(_) => "permerror",
        DmarcResult::None => "none",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn test_format_spf_result() {
        assert_eq!(format_spf_result(SpfResult::Pass), "pass");
        assert_eq!(format_spf_result(SpfResult::Fail), "fail");
        assert_eq!(format_spf_result(SpfResult::SoftFail), "softfail");
        assert_eq!(format_spf_result(SpfResult::Neutral), "neutral");
        assert_eq!(format_spf_result(SpfResult::None), "none");
        assert_eq!(format_spf_result(SpfResult::TempError), "temperror");
        assert_eq!(format_spf_result(SpfResult::PermError), "permerror");
    }

    #[test]
    fn test_format_dkim_result() {
        assert_eq!(format_dkim_result(&DkimResult::Pass), "pass");
        assert_eq!(
            format_dkim_result(&DkimResult::Fail(mail_auth::Error::FailedVerification)),
            "fail"
        );
        assert_eq!(
            format_dkim_result(&DkimResult::Neutral(mail_auth::Error::RevokedPublicKey)),
            "neutral"
        );
        assert_eq!(format_dkim_result(&DkimResult::None), "none");
        assert_eq!(
            format_dkim_result(&DkimResult::TempError(mail_auth::Error::DnsError(
                "timeout".to_string()
            ))),
            "temperror"
        );
        assert_eq!(
            format_dkim_result(&DkimResult::PermError(mail_auth::Error::ParseError)),
            "permerror"
        );
    }

    #[test]
    fn test_format_dmarc_result() {
        assert_eq!(format_dmarc_result(&DmarcResult::Pass), "pass");
        assert_eq!(
            format_dmarc_result(&DmarcResult::Fail(mail_auth::Error::NotAligned)),
            "fail"
        );
        assert_eq!(
            format_dmarc_result(&DmarcResult::TempError(mail_auth::Error::DnsError(
                "timeout".to_string()
            ))),
            "temperror"
        );
        assert_eq!(
            format_dmarc_result(&DmarcResult::PermError(mail_auth::Error::ParseError)),
            "permerror"
        );
        assert_eq!(format_dmarc_result(&DmarcResult::None), "none");
    }

    #[tokio::test]
    async fn test_transformer_name() {
        let transformer = EmailAuthTransformer::new("mail.example.com".to_string()).await;
        assert_eq!(transformer.name(), "email_auth");
    }

    #[tokio::test]
    async fn test_skip_without_client_ip() {
        let transformer = EmailAuthTransformer::new("mail.example.com".to_string()).await;
        let original_body = "Subject: Test\r\n\r\nHello";
        let mut message =
            EmailMessage::from_raw("sender@example.com", "rcpt@example.com", original_body);

        transformer.transform(&mut message).await;

        assert_eq!(message.raw(), original_body);
    }

    #[tokio::test]
    async fn test_skip_preserves_fields() {
        let transformer = EmailAuthTransformer::new("mail.example.com".to_string()).await;
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Subject: Preserve\r\n\r\nBody",
        );
        let original_from = message.from.clone();
        let original_to = message.to.clone();
        let original_id = message.message_id.clone();

        transformer.transform(&mut message).await;

        assert_eq!(message.from, original_from);
        assert_eq!(message.to, original_to);
        assert_eq!(message.message_id, original_id);
    }

    #[tokio::test]
    async fn test_adds_auth_results_header() {
        let transformer = EmailAuthTransformer::new("mail.test.local".to_string()).await;
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Subject: Test\r\n\r\nBody content",
        );
        message.client_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        message.helo_domain = Some("localhost".to_string());

        transformer.transform(&mut message).await;
        message.rebuild();

        assert!(message
            .raw()
            .starts_with("Authentication-Results: mail.test.local;"));
    }

    #[tokio::test]
    async fn test_auth_results_contains_spf() {
        let transformer = EmailAuthTransformer::new("mx.local".to_string()).await;
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Subject: Test\r\n\r\nBody",
        );
        message.client_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        message.helo_domain = Some("localhost".to_string());

        transformer.transform(&mut message).await;
        message.rebuild();

        assert!(message.raw().contains("spf="));
    }

    #[tokio::test]
    async fn test_preserves_original_body() {
        let transformer = EmailAuthTransformer::new("mx.local".to_string()).await;
        let original_body = "Subject: Hello\r\n\r\nOriginal body content here";
        let mut message =
            EmailMessage::from_raw("sender@example.com", "rcpt@example.com", original_body);
        message.client_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));

        transformer.transform(&mut message).await;
        message.rebuild();

        assert!(message.raw().contains(original_body));
    }

    #[tokio::test]
    async fn test_missing_helo_domain() {
        let transformer = EmailAuthTransformer::new("mx.local".to_string()).await;
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Subject: Test\r\n\r\nBody",
        );
        message.client_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));

        transformer.transform(&mut message).await;
        message.rebuild();

        assert!(message.raw().starts_with("Authentication-Results:"));
    }

    #[tokio::test]
    async fn test_plain_text_body() {
        let transformer = EmailAuthTransformer::new("mx.local".to_string()).await;
        let mut message =
            EmailMessage::from_raw("sender@example.com", "rcpt@example.com", "Just plain text");
        message.client_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        message.helo_domain = Some("mail.example.com".to_string());

        transformer.transform(&mut message).await;
        message.rebuild();

        assert!(message.raw().starts_with("Authentication-Results:"));
        assert!(message.raw().contains("spf="));
        assert!(message.raw().contains("dkim="));
        assert!(message.raw().ends_with("Just plain text"));
    }

    #[tokio::test]
    async fn test_authserv_id_in_header() {
        let transformer =
            EmailAuthTransformer::new("custom.authserv.example.org".to_string()).await;
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Subject: Test\r\n\r\nBody",
        );
        message.client_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));

        transformer.transform(&mut message).await;
        message.rebuild();

        assert!(message.raw().contains("custom.authserv.example.org"));
    }

    #[tokio::test]
    async fn test_mime_body_full_results() {
        let transformer = EmailAuthTransformer::new("mx.local".to_string()).await;
        let mime_body = "From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: Test\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nBody content";
        let mut message =
            EmailMessage::from_raw("sender@example.com", "rcpt@example.com", mime_body);
        message.client_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        message.helo_domain = Some("localhost".to_string());

        transformer.transform(&mut message).await;
        message.rebuild();

        assert!(message
            .raw()
            .starts_with("Authentication-Results: mx.local;"));
        assert!(message.raw().contains("spf="));
        assert!(message.raw().contains("dkim="));
        assert!(message.raw().contains("dmarc="));
    }

    #[tokio::test]
    async fn test_ipv6_client_ip() {
        let transformer = EmailAuthTransformer::new("mx.local".to_string()).await;
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Subject: IPv6 Test\r\n\r\nBody",
        );
        message.client_ip = Some("::1".parse().unwrap());
        message.helo_domain = Some("localhost".to_string());

        transformer.transform(&mut message).await;
        message.rebuild();

        assert!(message.raw().starts_with("Authentication-Results:"));
    }
}
