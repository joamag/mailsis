use rustls::server::ServerSessionMemoryCache;
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::rustls::{Certificate, ServerConfig};

use std::{error::Error, fs::File, io::BufReader};

use tokio_rustls::rustls::PrivateKey;

/// Loads the TLS configuration from the files and returns a ServerConfig.
///
/// The files should be structured as follows:
/// cert.pem: The certificate file.
/// key.pem: The private key file.
pub fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig, Box<dyn Error>> {
    let cert_file = &mut BufReader::new(File::open(cert_path)?);
    let key_file = &mut BufReader::new(File::open(key_path)?);

    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();

    // Load the private key from the key file as PKCS8
    let mut keys = pkcs8_private_keys(key_file)?;
    let key = PrivateKey(keys.remove(0));

    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    // Allow multiple sessions per client, making it possible to
    // re-use the same TLS connection for multiple SMTP sessions
    config.session_storage = ServerSessionMemoryCache::new(256);
    Ok(config)
}
