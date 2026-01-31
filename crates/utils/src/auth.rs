//! Credential verification for SMTP and IMAP sessions.
//!
//! Both the SMTP `AUTH LOGIN` flow and the IMAP `LOGIN` command delegate
//! to an [`AuthEngine`] implementation. The crate ships with
//! [`MemoryAuthEngine`], which can be loaded from a plaintext credentials
//! file or constructed in-memory for tests.

use std::{collections::HashMap, fmt::Display, fs::read_to_string, io, sync::Arc};

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
            AuthError::EngineError(msg) => write!(f, "Engine error: {msg}"),
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
    /// Returns `Ok(())` if authentication succeeds, or an error if authentication
    /// fails (`AuthError::InvalidCredentials` for wrong password,
    /// `AuthError::UserNotFound` for non-existent user).
    fn authenticate(&self, username: &str, password: &str) -> AuthResult<()>;

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
    ///
    /// Returns an error if the file cannot be read.
    pub fn from_file(path: &str) -> io::Result<Self> {
        let content = read_to_string(path)?;
        let mut creds = HashMap::new();
        for line in content.lines() {
            if let Some((user, pass)) = line.split_once(':') {
                creds.insert(user.trim().to_string(), pass.trim().to_string());
            }
        }
        Ok(Self::from_map(creds))
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
    fn authenticate(&self, username: &str, password: &str) -> AuthResult<()> {
        match self.credentials.get(username) {
            Some(stored_password) if stored_password == password => Ok(()),
            Some(_) => Err(AuthError::InvalidCredentials),
            None => Err(AuthError::UserNotFound),
        }
    }

    fn user_exists(&self, username: &str) -> AuthResult<bool> {
        Ok(self.credentials.contains_key(username))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(engine.authenticate("testuser", "testpass").is_ok());
    }

    #[test]
    fn test_memory_engine_authenticate_wrong_password() {
        let mut map = HashMap::new();
        map.insert("testuser".to_string(), "testpass".to_string());

        let engine = MemoryAuthEngine::from_map(map);
        assert_eq!(
            engine.authenticate("testuser", "wrongpass"),
            Err(AuthError::InvalidCredentials)
        );
    }

    #[test]
    fn test_memory_engine_authenticate_user_not_found() {
        let engine = MemoryAuthEngine::new();
        assert_eq!(
            engine.authenticate("nonexistent", "pass"),
            Err(AuthError::UserNotFound)
        );
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

        assert!(engine.authenticate("newuser", "newpass").is_ok());
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

    #[test]
    fn test_memory_engine_from_arc() {
        let mut map = HashMap::new();
        map.insert("user".to_string(), "pass".to_string());
        let arc = Arc::new(map);

        let engine = MemoryAuthEngine::from_arc(arc.clone());
        assert_eq!(engine.len(), 1);
        assert!(engine.authenticate("user", "pass").is_ok());
    }

    #[test]
    fn test_memory_engine_from_file() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let file_path = temp_dir.path().join("credentials.txt");
        std::fs::write(&file_path, "alice:secret\nbob:password123\n").unwrap();

        let engine = MemoryAuthEngine::from_file(file_path.to_str().unwrap()).unwrap();
        assert_eq!(engine.len(), 2);
        assert!(engine.authenticate("alice", "secret").is_ok());
        assert!(engine.authenticate("bob", "password123").is_ok());
    }

    #[test]
    fn test_memory_engine_from_file_not_found() {
        let result = MemoryAuthEngine::from_file("/nonexistent/credentials.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_engine_from_file_with_whitespace() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let file_path = temp_dir.path().join("creds.txt");
        std::fs::write(&file_path, " alice : secret \n bob : pass \n").unwrap();

        let engine = MemoryAuthEngine::from_file(file_path.to_str().unwrap()).unwrap();
        assert!(engine.authenticate("alice", "secret").is_ok());
        assert!(engine.authenticate("bob", "pass").is_ok());
    }

    #[test]
    fn test_memory_engine_from_file_empty() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let file_path = temp_dir.path().join("empty.txt");
        std::fs::write(&file_path, "").unwrap();

        let engine = MemoryAuthEngine::from_file(file_path.to_str().unwrap()).unwrap();
        assert!(engine.is_empty());
    }

    #[test]
    fn test_memory_engine_default() {
        let engine = MemoryAuthEngine::default();
        assert!(engine.is_empty());
        assert_eq!(engine.len(), 0);
    }

    #[test]
    fn test_memory_engine_len_and_is_empty() {
        let mut engine = MemoryAuthEngine::new();
        assert!(engine.is_empty());
        assert_eq!(engine.len(), 0);

        engine.add_user("user".to_string(), "pass".to_string());
        assert!(!engine.is_empty());
        assert_eq!(engine.len(), 1);
    }
}
