use rustls::{server::ServerSessionMemoryCache, ClientConfig, RootCertStore};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::rustls::{Certificate, ServerConfig};

use std::{error::Error, fs::File, io::BufReader};

use tokio_rustls::rustls::PrivateKey;

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
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    // Allow multiple sessions per client, making it possible to
    // re-use the same TLS connection for multiple SMTP sessions
    config.session_storage = ServerSessionMemoryCache::new(256);
    Ok(config)
}

pub fn load_tls_client_config() -> Result<ClientConfig, Box<dyn Error>> {
    let root_store: RootCertStore = RootCertStore::empty();

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

pub fn load_tls_client_config_cert(
    cert_path: &str,
    key_path: &str,
) -> Result<ClientConfig, Box<dyn Error>> {
    // Create a new server config with the certificate chain and private key
    let root_store: RootCertStore = RootCertStore::empty();
    let (cert_chain, key) = load_chain_and_key(cert_path, key_path)?;
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, key)?;

    Ok(config)
}

fn load_chain_and_key(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<Certificate>, PrivateKey), Box<dyn Error>> {
    // Load the certificate chain from the cert file
    let cert_file = &mut BufReader::new(File::open(cert_path)?);
    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();

    // Load the private key from the key file as PKCS8
    let key_file = &mut BufReader::new(File::open(key_path)?);
    let mut keys = pkcs8_private_keys(key_file)?;

    Ok((cert_chain, PrivateKey(keys.remove(0))))
}
