use std::{error::Error, fs::File, io::BufReader, path::PathBuf, str::FromStr};

use rustls::{
    pki_types::{
        pem::{PemObject, SectionKind},
        CertificateDer, PrivateKeyDer,
    },
    server::ServerSessionMemoryCache,
    ClientConfig, RootCertStore, ServerConfig,
};
use rustls_pemfile::certs;

use crate::get_crate_root;

/// Loads the TLS configuration from the files and returns a ServerConfig.
///
/// The files should be structured as follows:
/// cert.pem: The certificate file.
/// key.pem: The private key file.
pub fn load_tls_server_config(
    cert_path: &str,
    key_path: &str,
) -> Result<ServerConfig, Box<dyn Error>> {
    // Create a new server config with the certificate chain and private key
    let (cert_chain, key) = load_chain_and_key(cert_path, key_path)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    // Allow multiple sessions per client, making it possible to
    // re-use the same TLS connection for multiple SMTP sessions
    config.session_storage = ServerSessionMemoryCache::new(256);
    Ok(config)
}

pub fn load_tls_client_config() -> Result<ClientConfig, Box<dyn Error>> {
    let cert_chain = load_default_ca_cert()?;
    let mut root_store: RootCertStore = RootCertStore::empty();
    root_store.add_parsable_certificates(cert_chain);

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

pub fn load_tls_client_config_cert(
    cert_path: &str,
    key_path: &str,
) -> Result<ClientConfig, Box<dyn Error>> {
    let cert_chain = load_default_ca_cert()?;
    let mut root_store: RootCertStore = RootCertStore::empty();
    root_store.add_parsable_certificates(cert_chain);

    // Create a new server config with the certificate chain and private key
    let (cert_chain, key) = load_chain_and_key(cert_path, key_path)?;
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, key)?;

    Ok(config)
}

fn load_chain_and_key(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn Error>> {
    // Load the certificate chain from the cert file
    let cert_file = &mut BufReader::new(File::open(cert_path)?);
    let cert_chain = certs(cert_file)?
        .into_iter()
        .map(|der| CertificateDer::from_pem(SectionKind::Certificate, der).unwrap())
        .collect::<Vec<_>>();

    // Load the private key from the key file
    let key = PrivateKeyDer::from_pem_file(key_path)?;

    Ok((cert_chain, key))
}

/// Returns the default path to the CA certificate file
/// used by the Mailsis infrastructure.
pub fn ca_cert_path() -> Result<PathBuf, Box<dyn Error>> {
    let crate_root = get_crate_root().unwrap_or(PathBuf::from_str(".")?);
    let ca_path = crate_root.join("certs").join("ca.cert.pem");
    Ok(ca_path)
}

/// Loads the CA certificate from the default path.
pub fn load_default_ca_cert() -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
    let cert_chain = load_ca_cert(
        ca_cert_path()?
            .to_str()
            .ok_or("Failed to get CA certificate path")?,
    )?;
    Ok(cert_chain)
}

/// Loads the CA certificate from the given path.
fn load_ca_cert(cert_path: &str) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
    let cert_file = &mut BufReader::new(File::open(cert_path)?);
    let cert_chain = certs(cert_file)?
        .into_iter()
        .map(|der| CertificateDer::from_pem(SectionKind::Certificate, der).unwrap())
        .collect::<Vec<_>>();
    Ok(cert_chain)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;

    fn install_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    fn generate_test_certs(dir: &Path) -> (PathBuf, PathBuf) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_path = dir.join("test.cert.pem");
        let key_path = dir.join("test.key.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
        (cert_path, key_path)
    }

    #[test]
    fn test_load_tls_server_config() {
        install_crypto_provider();
        let temp_dir = TempDir::new().unwrap();
        let (cert_path, key_path) = generate_test_certs(temp_dir.path());

        let result =
            load_tls_server_config(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_tls_server_config_invalid_cert() {
        let result = load_tls_server_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_tls_server_config_invalid_key() {
        let temp_dir = TempDir::new().unwrap();
        let (cert_path, _) = generate_test_certs(temp_dir.path());

        let result = load_tls_server_config(cert_path.to_str().unwrap(), "/nonexistent/key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_chain_and_key() {
        let temp_dir = TempDir::new().unwrap();
        let (cert_path, key_path) = generate_test_certs(temp_dir.path());

        let (chain, _key) =
            load_chain_and_key(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn test_load_chain_and_key_invalid_path() {
        let result = load_chain_and_key("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_ca_cert_path() {
        let path = ca_cert_path().unwrap();
        assert!(path.ends_with("certs/ca.cert.pem") || path.ends_with("certs\\ca.cert.pem"));
    }

    #[test]
    fn test_load_ca_cert() {
        let temp_dir = TempDir::new().unwrap();
        let (cert_path, _) = generate_test_certs(temp_dir.path());

        let certs = load_ca_cert(cert_path.to_str().unwrap()).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_load_ca_cert_invalid_path() {
        let result = load_ca_cert("/nonexistent/ca.cert.pem");
        assert!(result.is_err());
    }
}
