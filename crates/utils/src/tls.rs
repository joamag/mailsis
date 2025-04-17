use rustls::{
    pki_types::{
        pem::{PemObject, SectionKind},
        CertificateDer, PrivateKeyDer,
    },
    server::ServerSessionMemoryCache,
    ClientConfig, RootCertStore, ServerConfig,
};
use rustls_pemfile::certs;

use std::{error::Error, fs::File, io::BufReader};

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
    let crate_root = get_crate_root().unwrap();
    let ca_path = crate_root.join("certs").join("ca.cert.pem");
    println!("CA certificate path: {:?}", ca_path);
    let cert_chain = load_ca_cert(
        ca_path
            .to_str()
            .ok_or("Failed to get CA certificate path")?,
    )?;
    println!("CA certificate path: {:?}", ca_path);
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
    let cert_chain = load_ca_cert("ca.cert.pem")?;
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

fn load_ca_cert(cert_path: &str) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
    let cert_file = &mut BufReader::new(File::open(cert_path)?);
    let cert_chain = certs(cert_file)?
        .into_iter()
        .map(|der| CertificateDer::from_pem(SectionKind::Certificate, der).unwrap())
        .collect::<Vec<_>>();
    Ok(cert_chain)
}
