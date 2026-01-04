use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;

/// Result type for authentication operations.
pub type AuthResult<T> = Result<T, AuthError>;

/// Errors that can occur during authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The provided credentials are invalid.
    InvalidCredentials,
    /// The user was not found.
    UserNotFound,
    /// The authentication engine encountered an internal error.
    EngineError(String),
}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "Invalid credentials"),
            AuthError::UserNotFound => write!(f, "User not found"),
            AuthError::EngineError(msg) => write!(f, "Engine error: {}", msg),
        }
    }
}

impl std::error::Error for AuthError {}

/// Trait for authentication engines.
///
/// Implementations of this trait provide different authentication backends,
/// such as in-memory storage, databases, LDAP, etc.
pub trait AuthEngine: Send + Sync + Default {
    /// Authenticates a user with the given username and password.
    ///
    /// Returns `Ok(true)` if authentication succeeds, `Ok(false)` if the
    /// credentials are invalid, or an error if something went wrong.
    fn authenticate(&self, username: &str, password: &str) -> AuthResult<bool>;

    /// Checks if a user exists in the authentication store.
    fn user_exists(&self, username: &str) -> AuthResult<bool>;
}

/// In-memory authentication engine using a HashMap.
///
/// This is a simple authentication engine that stores credentials in memory.
/// Useful for testing and simple deployments.
#[derive(Debug, Clone)]
pub struct MemoryAuthEngine {
    credentials: Arc<HashMap<String, String>>,
}

impl MemoryAuthEngine {
    /// Creates a new empty MemoryAuthEngine.
    pub fn new() -> Self {
        Self {
            credentials: Arc::new(HashMap::new()),
        }
    }

    /// Creates a MemoryAuthEngine from an existing HashMap.
    pub fn from_map(credentials: HashMap<String, String>) -> Self {
        Self {
            credentials: Arc::new(credentials),
        }
    }

    /// Creates a MemoryAuthEngine from an Arc<HashMap>.
    pub fn from_arc(credentials: Arc<HashMap<String, String>>) -> Self {
        Self { credentials }
    }

    /// Loads credentials from a file.
    ///
    /// The file should be formatted as:
    /// ```text
    /// username:password
    /// username2:password2
    /// ```
    pub fn from_file(path: &str) -> Self {
        let mut creds = HashMap::new();
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                if let Some((user, pass)) = line.split_once(':') {
                    creds.insert(user.trim().to_string(), pass.trim().to_string());
                }
            }
        }
        Self::from_map(creds)
    }

    /// Adds a user to the credential store.
    ///
    /// Note: This requires mutable access and will clone the internal HashMap.
    pub fn add_user(&mut self, username: String, password: String) {
        let mut creds = (*self.credentials).clone();
        creds.insert(username, password);
        self.credentials = Arc::new(creds);
    }

    /// Returns the number of users in the store.
    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    /// Returns true if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }
}

impl Default for MemoryAuthEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthEngine for MemoryAuthEngine {
    fn authenticate(&self, username: &str, password: &str) -> AuthResult<bool> {
        match self.credentials.get(username) {
            Some(stored_password) => Ok(stored_password == password),
            None => Ok(false),
        }
    }

    fn user_exists(&self, username: &str) -> AuthResult<bool> {
        Ok(self.credentials.contains_key(username))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{AuthEngine, AuthError, MemoryAuthEngine};

    #[test]
    fn test_memory_engine_new() {
        let engine = MemoryAuthEngine::new();
        assert!(engine.is_empty());
    }

    #[test]
    fn test_memory_engine_from_map() {
        let mut map = HashMap::new();
        map.insert("user1".to_string(), "pass1".to_string());
        map.insert("user2".to_string(), "pass2".to_string());

        let engine = MemoryAuthEngine::from_map(map);
        assert_eq!(engine.len(), 2);
    }

    #[test]
    fn test_memory_engine_authenticate_success() {
        let mut map = HashMap::new();
        map.insert("testuser".to_string(), "testpass".to_string());

        let engine = MemoryAuthEngine::from_map(map);
        assert!(engine.authenticate("testuser", "testpass").unwrap());
    }

    #[test]
    fn test_memory_engine_authenticate_wrong_password() {
        let mut map = HashMap::new();
        map.insert("testuser".to_string(), "testpass".to_string());

        let engine = MemoryAuthEngine::from_map(map);
        assert!(!engine.authenticate("testuser", "wrongpass").unwrap());
    }

    #[test]
    fn test_memory_engine_authenticate_user_not_found() {
        let engine = MemoryAuthEngine::new();
        assert!(!engine.authenticate("nonexistent", "pass").unwrap());
    }

    #[test]
    fn test_memory_engine_user_exists() {
        let mut map = HashMap::new();
        map.insert("testuser".to_string(), "testpass".to_string());

        let engine = MemoryAuthEngine::from_map(map);
        assert!(engine.user_exists("testuser").unwrap());
        assert!(!engine.user_exists("nonexistent").unwrap());
    }

    #[test]
    fn test_memory_engine_add_user() {
        let mut engine = MemoryAuthEngine::new();
        engine.add_user("newuser".to_string(), "newpass".to_string());

        assert!(engine.authenticate("newuser", "newpass").unwrap());
        assert_eq!(engine.len(), 1);
    }

    #[test]
    fn test_auth_error_display() {
        assert_eq!(
            AuthError::InvalidCredentials.to_string(),
            "Invalid credentials"
        );
        assert_eq!(AuthError::UserNotFound.to_string(), "User not found");
        assert_eq!(
            AuthError::EngineError("test error".to_string()).to_string(),
            "Engine error: test error"
        );
    }
}
