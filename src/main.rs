use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use rustls::server::ServerSessionMemoryCache;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{
    collections::{HashMap, HashSet},
    fs::File as StdFile,
    io::BufReader as StdBufReader,
    sync::Arc,
};
use tokio::{
    fs::{self, File},
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::{
    rustls::{Certificate, PrivateKey, ServerConfig},
    TlsAcceptor, TlsStream,
};
use uuid::Uuid;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:2525").await?;
    let tls_config = Arc::new(load_tls_config());
    let tls_acceptor = TlsAcceptor::from(tls_config);
    let credentials = Arc::new(load_credentials("users.txt"));
    let (tx, mut rx) = mpsc::channel::<(String, HashSet<String>, String)>(100);

    tokio::spawn(async move {
        while let Some((from, rcpts, body)) = rx.recv().await {
            for rcpt in rcpts {
                let safe_rcpt = rcpt.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
                let path = format!("mailbox/{}", safe_rcpt);
                if fs::create_dir_all(&path).await.is_ok() {
                    let filename = format!("{}/{}.eml", path, Uuid::new_v4());
                    if let Ok(mut file) = File::create(&filename).await {
                        let _ = file
                            .write_all(format!("From: {}\r\n", from).as_bytes())
                            .await;
                        let _ = file.write_all(format!("To: {}\r\n", rcpt).as_bytes()).await;
                        let _ = file
                            .write_all(
                                format!("Date: {}\r\n\r\n", Utc::now().to_rfc2822()).as_bytes(),
                            )
                            .await;
                        let _ = file.write_all(body.as_bytes()).await;
                        println!("Stored: {}", filename);
                    }
                }
            }
        }
    });

    println!("Mailsis SMTP running on port 2525");

    loop {
        let (stream, _) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let tx = tx.clone();
        let credentials = credentials.clone();
        tokio::spawn(async move {
            handle_smtp_session(stream, tls_acceptor, tx, credentials).await;
        });
    }
}

/// Loads the TLS configuration from the files and returns a ServerConfig.
///
/// The files should be structured as follows:
/// cert.pem: The certificate file.
/// key.pem: The private key file.
fn load_tls_config() -> ServerConfig {
    let cert_file = &mut StdBufReader::new(StdFile::open("cert.pem").unwrap());
    let key_file = &mut StdBufReader::new(StdFile::open("key.pem").unwrap());

    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();

    // Load the private key from the key file as PKCS8
    let mut keys = pkcs8_private_keys(key_file).unwrap();
    let key = PrivateKey(keys.remove(0));

    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .unwrap();

    // Allow multiple sessions per client, making it possible to
    // re-use the same TLS connection for multiple SMTP sessions
    config.session_storage = ServerSessionMemoryCache::new(256);
    config
}

/// Loads the credentials from the file and returns a HashMap of usernames and passwords.
///
/// The file should be formatted as follows:
/// username:password
/// username2:password2
/// username3:password3
/// ...
fn load_credentials(path: &str) -> HashMap<String, String> {
    let mut creds = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            if let Some((user, pass)) = line.split_once(':') {
                creds.insert(user.trim().to_string(), pass.trim().to_string());
            }
        }
    }
    creds
}


async fn handle_smtp_session(
    stream: TcpStream,
    tls_acceptor: TlsAcceptor,
    tx: mpsc::Sender<(String, HashSet<String>, String)>,
    credentials: Arc<HashMap<String, String>>,
) {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    let _ = writer.write_all(b"220 localhost SimpleSMTP\r\n").await;

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await.unwrap_or(0);
        if bytes == 0 {
            break;
        }

        let cmd = line.trim_end();
        let mut parts = cmd.split_whitespace();
        let command = parts.next().unwrap_or("").to_uppercase();
        let arg = parts.next();

        println!("> {}", cmd);

        match command.as_str() {
            "EHLO" | "HELO" => {
                writer.write_all(b"250-localhost greets you\r\n").await.ok();
                writer.write_all(b"250-STARTTLS\r\n").await.ok();
                writer.write_all(b"250 AUTH LOGIN\r\n").await.ok();
            }
            "MAIL" => {
                writer.write_all(b"250 OK\r\n").await.ok();
            }
            "RCPT" => {
                writer.write_all(b"250 OK\r\n").await.ok();
            }
            "DATA" => {
                writer.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n").await.ok();
            }
            "STARTTLS" => {
                writer.write_all(b"220 Ready to start TLS\r\n").await.ok();
                let stream = tokio::io::ReadHalf::unsplit(reader.into_inner(), writer);
                match tls_acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        println!("TLS handshake complete");
                        return handle_tls_session(
                            tokio_rustls::TlsStream::Server(tls_stream),
                            tx,
                            credentials,
                        )
                        .await;
                    }
                    Err(e) => {
                        eprintln!("TLS handshake failed: {:?}", e);
                        return;
                    }
                }
            }
            _ => {
                println!("Unknown command: {}", command);
                writer
                    .write_all(b"502 Command not implemented\r\n")
                    .await
                    .ok();
            }
        }
    }
}

async fn handle_tls_session(
    stream: TlsStream<TcpStream>,
    tx: mpsc::Sender<(String, HashSet<String>, String)>,
    credentials: Arc<HashMap<String, String>>,
) {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    let mut mail_from = String::new();
    let mut rcpt_to = HashSet::new();
    let mut authenticated = false;

    let _ = writer.write_all(b"220 TLS secured SMTP\r\n").await;

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await.unwrap_or(0);
        if bytes == 0 {
            break;
        }

        let cmd = line.trim_end();
        println!("(TLS) > {}", cmd);

        let mut parts = cmd.split_whitespace();
        let command = parts.next().unwrap_or("").to_uppercase();
        let arg = parts.next();

        match command.as_str() {
            "AUTH" if arg == Some("LOGIN") => {
                writer.write_all(b"334 VXNlcm5hbWU6\r\n").await.ok();

                line.clear();
                reader.read_line(&mut line).await.ok();
                let username = general_purpose::STANDARD
                    .decode(line.trim())
                    .unwrap_or_default();
                let username = String::from_utf8_lossy(&username);

                writer.write_all(b"334 UGFzc3dvcmQ6\r\n").await.ok();

                line.clear();
                reader.read_line(&mut line).await.ok();
                let password = general_purpose::STANDARD
                    .decode(line.trim())
                    .unwrap_or_default();
                let password = String::from_utf8_lossy(&password);

                if credentials.get(username.trim()) == Some(&password.trim().to_string()) {
                    writer
                        .write_all(b"235 Authentication successful\r\n")
                        .await
                        .ok();
                    authenticated = true;
                } else {
                    writer
                        .write_all(b"535 Authentication failed\r\n")
                        .await
                        .ok();
                }
            }
            "AUTH" => {
                if let Some(arg) = arg {
                    if let Some(encoded_user) = arg.strip_prefix("LOGIN") {
                        let username = general_purpose::STANDARD
                            .decode(encoded_user.trim())
                            .unwrap_or_default();
                        let username = String::from_utf8_lossy(&username);

                        writer.write_all(b"334 UGFzc3dvcmQ6\r\n").await.ok();

                        line.clear();
                        reader.read_line(&mut line).await.ok();
                        let password = general_purpose::STANDARD
                            .decode(line.trim())
                            .unwrap_or_default();
                        let password = String::from_utf8_lossy(&password);

                        if credentials.get(username.trim()) == Some(&password.trim().to_string()) {
                            writer
                                .write_all(b"235 Authentication successful\r\n")
                                .await
                                .ok();
                            authenticated = true;
                        } else {
                            writer
                                .write_all(b"535 Authentication failed\r\n")
                                .await
                                .ok();
                        }
                    } else {
                        writer
                            .write_all(b"504 Unrecognized authentication type\r\n")
                            .await
                            .ok();
                    }
                } else {
                    writer
                        .write_all(b"504 Unrecognized authentication type\r\n")
                        .await
                        .ok();
                }
            }
            "DATA" => {
                if !authenticated {
                    writer
                        .write_all(b"530 Authentication required\r\n")
                        .await
                        .ok();
                    continue;
                }
                if rcpt_to.is_empty() {
                    writer.write_all(b"554 No valid recipients\r\n").await.ok();
                    continue;
                }

                writer
                    .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    .await
                    .ok();

                let mut data = String::new();
                loop {
                    line.clear();
                    reader.read_line(&mut line).await.ok();
                    if line == ".\r\n" {
                        break;
                    }
                    data.push_str(&line);
                }

                let _ = tx.send((mail_from.clone(), rcpt_to.clone(), data)).await;
                writer.write_all(b"250 Message accepted\r\n").await.ok();

                mail_from.clear();
                rcpt_to.clear();
            }
            "QUIT" => {
                writer.write_all(b"221 Bye\r\n").await.ok();
                break;
            }
            _ => {
                if let Some(value) = cmd.strip_prefix("MAIL FROM:") {
                    if !authenticated {
                        writer
                            .write_all(b"530 Authentication required\r\n")
                            .await
                            .ok();
                        continue;
                    }
                    mail_from = value.trim().to_string();
                    writer.write_all(b"250 OK\r\n").await.ok();
                } else if let Some(value) = cmd.strip_prefix("RCPT TO:") {
                    if !authenticated {
                        writer
                            .write_all(b"530 Authentication required\r\n")
                            .await
                            .ok();
                        continue;
                    }
                    rcpt_to.insert(value.trim().to_string());
                    writer.write_all(b"250 OK\r\n").await.ok();
                } else {
                    println!("Unknown command: {}", command);
                    writer
                        .write_all(b"502 Command not implemented\r\n")
                        .await
                        .ok();
                }
            }
        }
    }
}
