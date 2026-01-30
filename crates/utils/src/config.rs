use std::{collections::HashMap, fs, path::Path};

use serde::Deserialize;

/// Top-level configuration for the Mailsis SMTP server.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub smtp: SmtpConfig,
}

/// SMTP server configuration.
#[derive(Debug, Deserialize)]
pub struct SmtpConfig {
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default)]
    pub auth_required: bool,

    #[serde(default)]
    pub tls: TlsConfig,

    #[serde(default)]
    pub auth: AuthConfig,

    #[serde(default)]
    pub handlers: HashMap<String, HandlerConfig>,

    #[serde(default)]
    pub routing: RoutingConfig,
}

/// TLS certificate configuration.
#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_cert")]
    pub cert: String,

    #[serde(default = "default_key")]
    pub key: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert: default_cert(),
            key: default_key(),
        }
    }
}

/// Authentication configuration.
#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_credentials_file")]
    pub credentials_file: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            credentials_file: default_credentials_file(),
        }
    }
}

/// Configuration for a named message handler.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum HandlerConfig {
    /// File-based storage handler.
    #[serde(rename = "file_storage")]
    FileStorage {
        #[serde(default = "default_mailbox_path")]
        path: String,
        #[serde(default = "default_true")]
        metadata: bool,
    },

    /// Redis queue handler.
    #[serde(rename = "redis")]
    Redis {
        #[serde(default = "default_redis_url")]
        url: String,
        #[serde(default = "default_redis_queue")]
        queue: String,
    },
}

/// Routing configuration with rules and a default handler.
#[derive(Debug, Deserialize)]
pub struct RoutingConfig {
    /// Default handler name for routed messages.
    #[serde(default = "default_handler_name")]
    pub default: String,

    /// Default transformers applied to all routed messages unless
    /// overridden per rule.
    #[serde(default)]
    pub transformers: Vec<TransformerConfig>,

    /// Sequence of routing rules to be applied according to specificity.
    #[serde(default)]
    pub rules: Vec<RoutingRuleConfig>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            default: default_handler_name(),
            transformers: Vec::new(),
            rules: Vec::new(),
        }
    }
}

/// A single routing rule that matches by address or domain.
#[derive(Debug, Clone, Deserialize)]
pub struct RoutingRuleConfig {
    /// Exact email address match (e.g. "admin@example.com").
    pub address: Option<String>,

    /// Domain match, supports wildcard prefix (e.g. "example.com" or "*.example.com").
    pub domain: Option<String>,

    /// Name of the handler to route to.
    pub handler: String,

    /// Transformers for this rule, overrides the default transformers if present.
    pub transformers: Option<Vec<TransformerConfig>>,
}

/// Configuration for a message transformer.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum TransformerConfig {
    /// Ensures a Message-ID header exists in the email body.
    #[serde(rename = "message_id")]
    MessageId {
        /// Domain used when generating new Message-ID values.
        #[serde(default = "default_host")]
        domain: String,
    },
}

/// Loads configuration from a TOML file.
pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    let content = fs::read_to_string(path).map_err(ConfigError::Io)?;
    toml::from_str(&content).map_err(ConfigError::Parse)
}

/// Errors that can occur while loading configuration.
#[derive(Debug)]
pub enum ConfigError {
    /// An I/O error occurred reading the file.
    Io(std::io::Error),
    /// A parse error occurred deserializing TOML.
    Parse(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "Config I/O error: {e}"),
            ConfigError::Parse(e) => write!(f, "Config parse error: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    2525
}

fn default_cert() -> String {
    "certs/server.cert.pem".to_string()
}

fn default_key() -> String {
    "certs/server.key.pem".to_string()
}

fn default_credentials_file() -> String {
    "passwords/example.txt".to_string()
}

fn default_mailbox_path() -> String {
    "mailbox".to_string()
}

fn default_true() -> bool {
    true
}

fn default_redis_url() -> String {
    "redis://127.0.0.1:6379".to_string()
}

fn default_redis_queue() -> String {
    "incoming_emails".to_string()
}

fn default_handler_name() -> String {
    "local".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
[smtp]
host = "0.0.0.0"
port = 25
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.smtp.host, "0.0.0.0");
        assert_eq!(config.smtp.port, 25);
        assert!(!config.smtp.auth_required);
        assert_eq!(config.smtp.routing.default, "local");
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
[smtp]
host = "0.0.0.0"
port = 25
auth_required = true

[smtp.tls]
cert = "my/cert.pem"
key = "my/key.pem"

[smtp.auth]
credentials_file = "my/passwords.txt"

[smtp.handlers.local]
type = "file_storage"
path = "my_mailbox"
metadata = false

[smtp.handlers.queue]
type = "redis"
url = "redis://redis:6379"
queue = "emails"

[smtp.routing]
default = "local"

[[smtp.routing.rules]]
address = "admin@example.com"
handler = "queue"

[[smtp.routing.rules]]
domain = "example.com"
handler = "queue"

[[smtp.routing.rules]]
domain = "*.internal.org"
handler = "local"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.smtp.host, "0.0.0.0");
        assert_eq!(config.smtp.port, 25);
        assert!(config.smtp.auth_required);
        assert_eq!(config.smtp.tls.cert, "my/cert.pem");
        assert_eq!(config.smtp.auth.credentials_file, "my/passwords.txt");
        assert_eq!(config.smtp.handlers.len(), 2);
        assert_eq!(config.smtp.routing.rules.len(), 3);

        // Verify handler types
        match &config.smtp.handlers["local"] {
            HandlerConfig::FileStorage { path, metadata } => {
                assert_eq!(path, "my_mailbox");
                assert!(!metadata);
            }
            _ => panic!("Expected FileStorage handler"),
        }

        match &config.smtp.handlers["queue"] {
            HandlerConfig::Redis { url, queue } => {
                assert_eq!(url, "redis://redis:6379");
                assert_eq!(queue, "emails");
            }
            _ => panic!("Expected Redis handler"),
        }

        // Verify routing rules
        assert_eq!(
            config.smtp.routing.rules[0].address.as_deref(),
            Some("admin@example.com")
        );
        assert_eq!(config.smtp.routing.rules[0].handler, "queue");
        assert_eq!(
            config.smtp.routing.rules[1].domain.as_deref(),
            Some("example.com")
        );
        assert_eq!(
            config.smtp.routing.rules[2].domain.as_deref(),
            Some("*.internal.org")
        );
    }

    #[test]
    fn test_parse_transformers_config() {
        let toml = r#"
[smtp]

[[smtp.routing.transformers]]
type = "message_id"
domain = "mail.example.com"

[[smtp.routing.rules]]
domain = "example.com"
handler = "local"

  [[smtp.routing.rules.transformers]]
  type = "message_id"
  domain = "example.com"

[[smtp.routing.rules]]
domain = "other.com"
handler = "local"
"#;
        let config: Config = toml::from_str(toml).unwrap();

        // Default transformers
        assert_eq!(config.smtp.routing.transformers.len(), 1);
        match &config.smtp.routing.transformers[0] {
            TransformerConfig::MessageId { domain } => {
                assert_eq!(domain, "mail.example.com");
            }
        }

        // Per-rule transformers
        assert!(config.smtp.routing.rules[0].transformers.is_some());
        let rule_transformers = config.smtp.routing.rules[0].transformers.as_ref().unwrap();
        assert_eq!(rule_transformers.len(), 1);
        match &rule_transformers[0] {
            TransformerConfig::MessageId { domain } => {
                assert_eq!(domain, "example.com");
            }
        }

        // Rule without transformers
        assert!(config.smtp.routing.rules[1].transformers.is_none());
    }

    #[test]
    fn test_parse_defaults() {
        let toml = r#"
[smtp]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.smtp.host, "127.0.0.1");
        assert_eq!(config.smtp.port, 2525);
        assert_eq!(config.smtp.tls.cert, "certs/server.cert.pem");
        assert_eq!(config.smtp.tls.key, "certs/server.key.pem");
        assert_eq!(config.smtp.auth.credentials_file, "passwords/example.txt");
    }
}
