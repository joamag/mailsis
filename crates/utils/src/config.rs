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

    #[serde(default = "default_hostname")]
    pub hostname: String,

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

    /// Whether authentication is required for recipients matching this rule.
    /// Overrides the global `smtp.auth_required` setting when present.
    pub auth_required: Option<bool>,
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

    /// Verifies SPF, DKIM, and DMARC; adds an Authentication-Results header.
    #[serde(rename = "email_auth")]
    EmailAuth {
        /// The authserv-id for the Authentication-Results header.
        /// Defaults to the global `hostname` if not specified.
        #[serde(default)]
        authserv_id: String,
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

fn default_hostname() -> String {
    "localhost".to_string()
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
            _ => panic!("Expected MessageId transformer"),
        }

        // Per-rule transformers
        assert!(config.smtp.routing.rules[0].transformers.is_some());
        let rule_transformers = config.smtp.routing.rules[0].transformers.as_ref().unwrap();
        assert_eq!(rule_transformers.len(), 1);
        match &rule_transformers[0] {
            TransformerConfig::MessageId { domain } => {
                assert_eq!(domain, "example.com");
            }
            _ => panic!("Expected MessageId transformer"),
        }

        // Rule without transformers
        assert!(config.smtp.routing.rules[1].transformers.is_none());
    }

    #[test]
    fn test_parse_auth_required_per_rule() {
        let toml = r#"
[smtp]

[[smtp.routing.rules]]
address = "secure@example.com"
handler = "local"
auth_required = true

[[smtp.routing.rules]]
domain = "open.com"
handler = "local"
auth_required = false

[[smtp.routing.rules]]
domain = "default.com"
handler = "local"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.smtp.routing.rules[0].auth_required, Some(true));
        assert_eq!(config.smtp.routing.rules[1].auth_required, Some(false));
        assert_eq!(config.smtp.routing.rules[2].auth_required, None);
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

    #[test]
    fn test_config_error_display_io() {
        let error = ConfigError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file missing",
        ));
        assert!(error.to_string().starts_with("Config I/O error:"));
    }

    #[test]
    fn test_config_error_display_parse() {
        let toml_err = toml::from_str::<Config>("invalid toml {{{{").unwrap_err();
        let error = ConfigError::Parse(toml_err);
        assert!(error.to_string().starts_with("Config parse error:"));
    }

    #[test]
    fn test_load_config_success() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        std::fs::write(&config_path, "[smtp]\nhost = \"0.0.0.0\"\nport = 25\n").unwrap();

        let config = load_config(&config_path).unwrap();
        assert_eq!(config.smtp.host, "0.0.0.0");
        assert_eq!(config.smtp.port, 25);
    }

    #[test]
    fn test_load_config_file_not_found() {
        let result = load_config(Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config_path = temp_dir.path().join("bad.toml");
        std::fs::write(&config_path, "this is not valid {{{{ toml").unwrap();

        let result = load_config(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_email_auth_transformer() {
        let toml = r#"
[smtp]

[[smtp.routing.transformers]]
type = "email_auth"
authserv_id = "mx.example.com"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.smtp.routing.transformers.len(), 1);
        match &config.smtp.routing.transformers[0] {
            TransformerConfig::EmailAuth { authserv_id } => {
                assert_eq!(authserv_id, "mx.example.com");
            }
            _ => panic!("Expected EmailAuth transformer"),
        }
    }
}
