use std::sync::Arc;

use crate::{
    handler::{HandlerResult, MessageHandler},
    transformer::MessageTransformer,
    EmailMessage,
};

/// The type of match for a routing rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchType {
    /// Matches an exact email address (e.g. "admin@example.com").
    ExactAddress,
    /// Matches all users at a domain (e.g. "example.com").
    Domain,
    /// Matches all subdomains (e.g. "*.example.com").
    WildcardDomain,
}

/// A single routing rule that maps a pattern to a handler.
pub struct RoutingRule {
    pub match_type: MatchType,
    pub pattern: String,
    pub handler: Arc<dyn MessageHandler>,
    pub transformers: Vec<Box<dyn MessageTransformer>>,
    pub auth_required: Option<bool>,
}

impl RoutingRule {
    /// Tests if this rule matches the given recipient address.
    pub fn matches(&self, address: &str) -> bool {
        match self.match_type {
            MatchType::ExactAddress => address.eq_ignore_ascii_case(&self.pattern),
            MatchType::Domain => {
                if let Some(domain) = address.rsplit('@').next() {
                    domain.eq_ignore_ascii_case(&self.pattern)
                } else {
                    false
                }
            }
            MatchType::WildcardDomain => {
                let wildcard = self.pattern.strip_prefix("*.").unwrap_or(&self.pattern);
                if let Some(domain) = address.rsplit('@').next() {
                    // Match the domain itself or any subdomain
                    domain.eq_ignore_ascii_case(wildcard)
                        || domain
                            .to_ascii_lowercase()
                            .ends_with(&format!(".{}", wildcard.to_ascii_lowercase()))
                } else {
                    false
                }
            }
        }
    }
}

/// Routes incoming email messages to handlers based on recipient address rules.
///
/// Rules are evaluated in specificity order: exact address > domain > wildcard domain.
/// If no rule matches, the default handler is used.
pub struct MessageRouter {
    rules: Vec<RoutingRule>,
    default_handler: Arc<dyn MessageHandler>,
    default_transformers: Vec<Box<dyn MessageTransformer>>,
}

impl std::fmt::Debug for MessageRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageRouter")
            .field("rules", &self.rules.len())
            .finish()
    }
}

impl MessageRouter {
    /// Creates a new [`MessageRouter`] with the given rules, default handler, and
    /// default transformers.
    ///
    /// Rules are automatically sorted by specificity (exact > domain > wildcard).
    pub fn new(
        mut rules: Vec<RoutingRule>,
        default_handler: Arc<dyn MessageHandler>,
        default_transformers: Vec<Box<dyn MessageTransformer>>,
    ) -> Self {
        // Sort by specificity: ExactAddress first, then Domain, then WildcardDomain
        rules.sort_by_key(|r| match r.match_type {
            MatchType::ExactAddress => 0,
            MatchType::Domain => 1,
            MatchType::WildcardDomain => 2,
        });
        Self {
            rules,
            default_handler,
            default_transformers,
        }
    }

    /// Resolves which handler should process a message for the given recipient.
    pub fn resolve(&self, recipient: &str) -> &Arc<dyn MessageHandler> {
        for rule in &self.rules {
            if rule.matches(recipient) {
                return &rule.handler;
            }
        }
        &self.default_handler
    }

    /// Resolves the transformers for a given recipient.
    ///
    /// Returns rule-specific transformers if the matching rule defines them,
    /// otherwise falls back to the default transformers.
    fn resolve_transformers(&self, recipient: &str) -> &[Box<dyn MessageTransformer>] {
        for rule in &self.rules {
            if rule.matches(recipient) {
                if !rule.transformers.is_empty() {
                    return &rule.transformers;
                }
                return &self.default_transformers;
            }
        }
        &self.default_transformers
    }

    /// Routes a message to the appropriate handler based on the recipient address.
    ///
    /// Applies transformers before dispatching to the handler.
    pub async fn route(&self, message: &mut EmailMessage) -> HandlerResult<()> {
        let transformers = self.resolve_transformers(&message.to);
        <crate::MessageIdTransformer as MessageTransformer>::apply(transformers, message).await;

        let handler = self.resolve(&message.to);
        handler.handle(message).await
    }

    /// Resolves whether authentication is required for a recipient.
    ///
    /// Returns the rule's [`RoutingRule::auth_required`] if the matching rule defines it,
    /// otherwise returns the provided global default.
    pub fn resolve_auth_required(&self, recipient: &str, global_default: bool) -> bool {
        for rule in &self.rules {
            if rule.matches(recipient) {
                if let Some(auth_req) = rule.auth_required {
                    return auth_req;
                }
                break;
            }
        }
        global_default
    }

    /// Returns a reference to the default handler.
    pub fn default_handler(&self) -> &Arc<dyn MessageHandler> {
        &self.default_handler
    }
}

/// Determines the match type from a routing rule configuration.
///
/// Returns [`ExactAddress`](MatchType::ExactAddress) if an address field is present,
/// [`WildcardDomain`](MatchType::WildcardDomain) if the domain starts with `*.`,
/// or [`Domain`](MatchType::Domain) otherwise.
pub fn determine_match_type(address: &Option<String>, domain: &Option<String>) -> MatchType {
    if address.is_some() {
        MatchType::ExactAddress
    } else if let Some(d) = domain {
        if d.starts_with("*.") {
            MatchType::WildcardDomain
        } else {
            MatchType::Domain
        }
    } else {
        MatchType::Domain
    }
}

/// Extracts the pattern string from a routing rule configuration.
pub fn extract_pattern(address: &Option<String>, domain: &Option<String>) -> String {
    address
        .as_ref()
        .or(domain.as_ref())
        .cloned()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::handler::HandlerFuture;

    struct CountingHandler {
        name: &'static str,
        count: AtomicUsize,
    }

    impl CountingHandler {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                count: AtomicUsize::new(0),
            }
        }

        fn count(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
    }

    impl MessageHandler for CountingHandler {
        fn handle<'a>(&'a self, _message: &'a EmailMessage) -> HandlerFuture<'a> {
            Box::pin(async move {
                self.count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }

        fn name(&self) -> &str {
            self.name
        }
    }

    #[test]
    fn test_exact_address_match() {
        let handler = Arc::new(CountingHandler::new("test"));
        let rule = RoutingRule {
            match_type: MatchType::ExactAddress,
            pattern: "admin@example.com".to_string(),
            handler,
            transformers: vec![],
            auth_required: None,
        };

        assert!(rule.matches("admin@example.com"));
        assert!(rule.matches("ADMIN@EXAMPLE.COM"));
        assert!(!rule.matches("user@example.com"));
        assert!(!rule.matches("admin@other.com"));
    }

    #[test]
    fn test_domain_match() {
        let handler = Arc::new(CountingHandler::new("test"));
        let rule = RoutingRule {
            match_type: MatchType::Domain,
            pattern: "example.com".to_string(),
            handler,
            transformers: vec![],
            auth_required: None,
        };

        assert!(rule.matches("user@example.com"));
        assert!(rule.matches("admin@example.com"));
        assert!(rule.matches("user@EXAMPLE.COM"));
        assert!(!rule.matches("user@other.com"));
        assert!(!rule.matches("user@sub.example.com"));
    }

    #[test]
    fn test_wildcard_domain_match() {
        let handler = Arc::new(CountingHandler::new("test"));
        let rule = RoutingRule {
            match_type: MatchType::WildcardDomain,
            pattern: "*.example.com".to_string(),
            handler,
            transformers: vec![],
            auth_required: None,
        };

        assert!(rule.matches("user@sub.example.com"));
        assert!(rule.matches("user@deep.sub.example.com"));
        assert!(rule.matches("user@example.com"));
        assert!(!rule.matches("user@other.com"));
    }

    #[tokio::test]
    async fn test_router_specificity_order() {
        let exact_handler = Arc::new(CountingHandler::new("exact"));
        let domain_handler = Arc::new(CountingHandler::new("domain"));
        let default_handler = Arc::new(CountingHandler::new("default"));

        let rules = vec![
            RoutingRule {
                match_type: MatchType::Domain,
                pattern: "example.com".to_string(),
                handler: domain_handler.clone(),
                transformers: vec![],
                auth_required: None,
            },
            RoutingRule {
                match_type: MatchType::ExactAddress,
                pattern: "admin@example.com".to_string(),
                handler: exact_handler.clone(),
                transformers: vec![],
                auth_required: None,
            },
        ];

        let router = MessageRouter::new(rules, default_handler.clone(), vec![]);

        // Verify exact match takes priority over domain match
        let mut msg = EmailMessage::from_raw("sender@test.com", "admin@example.com", "test");
        router.route(&mut msg).await.unwrap();
        assert_eq!(exact_handler.count(), 1);
        assert_eq!(domain_handler.count(), 0);

        // Verify domain match for other users
        let mut msg = EmailMessage::from_raw("sender@test.com", "user@example.com", "test");
        router.route(&mut msg).await.unwrap();
        assert_eq!(domain_handler.count(), 1);

        // Verify default handler for unmatched domains
        let mut msg = EmailMessage::from_raw("sender@test.com", "user@other.com", "test");
        router.route(&mut msg).await.unwrap();
        assert_eq!(default_handler.count(), 1);
    }

    #[test]
    fn test_resolve_auth_required() {
        let handler = Arc::new(CountingHandler::new("test"));
        let rules = vec![
            RoutingRule {
                match_type: MatchType::ExactAddress,
                pattern: "secure@example.com".to_string(),
                handler: handler.clone(),
                transformers: vec![],
                auth_required: Some(true),
            },
            RoutingRule {
                match_type: MatchType::Domain,
                pattern: "open.com".to_string(),
                handler: handler.clone(),
                transformers: vec![],
                auth_required: Some(false),
            },
            RoutingRule {
                match_type: MatchType::Domain,
                pattern: "default.com".to_string(),
                handler: handler.clone(),
                transformers: vec![],
                auth_required: None,
            },
        ];

        let router = MessageRouter::new(rules, handler, vec![]);

        // Rule with auth_required=true overrides global
        assert!(router.resolve_auth_required("secure@example.com", false));

        // Rule with auth_required=false overrides global
        assert!(!router.resolve_auth_required("user@open.com", true));

        // Rule with auth_required=None falls back to global
        assert!(router.resolve_auth_required("user@default.com", true));
        assert!(!router.resolve_auth_required("user@default.com", false));

        // No matching rule falls back to global
        assert!(router.resolve_auth_required("user@unknown.com", true));
        assert!(!router.resolve_auth_required("user@unknown.com", false));
    }

    #[test]
    fn test_determine_match_type() {
        assert_eq!(
            determine_match_type(&Some("user@test.com".to_string()), &None),
            MatchType::ExactAddress
        );
        assert_eq!(
            determine_match_type(&None, &Some("example.com".to_string())),
            MatchType::Domain
        );
        assert_eq!(
            determine_match_type(&None, &Some("*.example.com".to_string())),
            MatchType::WildcardDomain
        );
    }

    #[test]
    fn test_extract_pattern() {
        assert_eq!(
            extract_pattern(&Some("user@test.com".to_string()), &None),
            "user@test.com"
        );
        assert_eq!(
            extract_pattern(&None, &Some("example.com".to_string())),
            "example.com"
        );
    }
}
