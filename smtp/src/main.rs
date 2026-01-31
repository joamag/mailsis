use std::{
    collections::HashSet, error::Error, mem::take, net::IpAddr, path::PathBuf, str::FromStr,
    sync::Arc,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use mailsis_utils::{
    determine_match_type, extract_pattern, get_crate_root, load_config, load_tls_server_config,
    AuthEngine, FileStorageHandler, HandlerConfig, IncomingMessage, MemoryAuthEngine,
    MessageHandler, MessageIdTransformer, MessageRouter, MessageTransformer, RoutingRule,
    TransformerConfig,
};
use tokio::{
    io::{
        split, AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
        BufReader, ReadHalf, WriteHalf,
    },
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::{TlsAcceptor, TlsStream};
use tracing::{debug, error, info, warn};

/// Represents a single SMTP session, created for each incoming connection.
///
/// This struct is used to store the state of the SMTP session, including the
/// from address, the recipients, whether the session is authenticated, whether
/// TLS is required, and the authentication engine.
#[derive(Debug)]
struct SMTPSession<A: AuthEngine> {
    from: String,
    rcpts: HashSet<String>,
    authenticated: bool,
    auth_required: bool,
    starttls: bool,
    auth_engine: Arc<A>,
    router: Arc<MessageRouter>,
    client_ip: Option<IpAddr>,
    helo_domain: Option<String>,
}

impl<A: AuthEngine + Default> SMTPSession<A> {
    /// Creates a new SMTP session with default values.
    pub fn new(
        auth_engine: Arc<A>,
        auth_required: bool,
        router: Arc<MessageRouter>,
        client_ip: Option<IpAddr>,
    ) -> Self {
        Self {
            from: String::new(),
            rcpts: HashSet::new(),
            authenticated: false,
            auth_required,
            starttls: false,
            auth_engine,
            router,
            client_ip,
            helo_domain: None,
        }
    }

    /// Base handler for the SMTP commands, should concentrate all the
    /// command handling in a single place for better maintainability.
    pub async fn handle_command<R: AsyncRead + AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        tx: &mpsc::Sender<IncomingMessage>,
        line: &mut String,
        command: &str,
        arg: Option<&str>,
    ) -> Result<(), Box<dyn Error>> {
        match command {
            "EHLO" | "HELO" => {
                self.helo_domain = arg.map(|s| s.to_string());
                self.handle_ehlo_helo(writer).await?;
            }
            "AUTH" if arg == Some("LOGIN") => {
                self.handle_auth_login(reader, writer, line).await?;
            }
            "AUTH" => {
                if let Some(arg) = arg {
                    if let Some(encoded_user) = arg.strip_prefix("LOGIN") {
                        self.handle_auth_with_username(reader, writer, line, encoded_user)
                            .await?;
                    } else {
                        self.write_response(writer, 504, "Unrecognized authentication type")
                            .await;
                    }
                } else {
                    self.write_response(writer, 504, "Unrecognized authentication type")
                        .await;
                }
            }
            "MAIL" => {
                if let Some(value) = arg {
                    self.handle_mail(writer, value).await?;
                }
            }
            "RCPT" => {
                if let Some(value) = arg {
                    self.handle_rcpt(writer, value).await?;
                }
            }
            "DATA" => {
                self.handle_data(reader, writer, tx).await?;
            }
            "RSET" => {
                self.handle_rset(writer).await?;
            }
            "QUIT" => {
                self.handle_quit(writer).await?;
            }
            _ => {
                self.handle_unknown(writer).await?;
            }
        }
        Ok(())
    }

    async fn handle_ehlo_helo<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), Box<dyn Error>> {
        self.write_multiple(
            writer,
            250,
            &["localhost greets you", "STARTTLS", "AUTH LOGIN"],
        )
        .await;
        Ok(())
    }

    async fn handle_auth_login<R: AsyncRead + AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        line: &mut String,
    ) -> Result<(), Box<dyn Error>> {
        self.write_response(writer, 334, "VXNlcm5hbWU6").await;

        line.clear();
        reader.read_line(line).await.ok();
        let username = STANDARD.decode(line.trim()).unwrap_or_default();
        let username = String::from_utf8_lossy(&username);

        self.write_response(writer, 334, "UGFzc3dvcmQ6").await;

        line.clear();
        reader.read_line(line).await.ok();
        let password = STANDARD.decode(line.trim()).unwrap_or_default();
        let password = String::from_utf8_lossy(&password);

        if self
            .auth_engine
            .authenticate(username.trim(), password.trim())
            .is_ok()
        {
            info!(username = %username.trim(), "Authentication successful");
            self.write_response(writer, 235, "Authentication successful")
                .await;
            self.authenticated = true;
        } else {
            warn!(username = %username.trim(), "Authentication failed");
            self.write_response(writer, 535, "Authentication failed")
                .await;
        }
        Ok(())
    }

    async fn handle_auth_with_username<
        R: AsyncRead + AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    >(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        line: &mut String,
        encoded_user: &str,
    ) -> Result<(), Box<dyn Error>> {
        let username = STANDARD.decode(encoded_user.trim()).unwrap_or_default();
        let username = String::from_utf8_lossy(&username);

        self.write_response(writer, 334, "UGFzc3dvcmQ6").await;

        line.clear();
        reader.read_line(line).await.ok();
        let password = STANDARD.decode(line.trim()).unwrap_or_default();
        let password = String::from_utf8_lossy(&password);

        if self
            .auth_engine
            .authenticate(username.trim(), password.trim())
            .is_ok()
        {
            info!(username = %username.trim(), "Authentication successful");
            self.write_response(writer, 235, "Authentication successful")
                .await;
            self.authenticated = true;
        } else {
            warn!(username = %username.trim(), "Authentication failed");
            self.write_response(writer, 535, "Authentication failed")
                .await;
        }

        Ok(())
    }

    async fn handle_mail<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        value: &str,
    ) -> Result<(), Box<dyn Error>> {
        // Ensure that the user is authenticated before sending the mail
        if !self.authenticated && self.auth_required {
            self.write_response(writer, 530, "Authentication required")
                .await;
            return Ok(());
        }

        // SMTP is case-insensitive, check prefix without allocation
        if value.len() >= 5 && value[..5].eq_ignore_ascii_case("FROM:") {
            // Sanitize the from address, removing the prefix and suffix <>
            let original_rest = &value[5..];
            self.from = original_rest
                .trim()
                .strip_prefix("<")
                .and_then(|s| s.strip_suffix(">"))
                .unwrap_or(original_rest.trim())
                .to_string();
            info!(from = %self.from, "MAIL FROM accepted");
            self.write_response(writer, 250, "OK").await;
        } else {
            self.write_response(writer, 501, "Syntax error in parameters or arguments")
                .await;
        }
        Ok(())
    }

    async fn handle_rcpt<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        value: &str,
    ) -> Result<(), Box<dyn Error>> {
        // SMTP is case-insensitive, check prefix without allocation
        if value.len() >= 3 && value[..3].eq_ignore_ascii_case("TO:") {
            let original_rest = &value[3..];
            let rcpt = original_rest
                .trim()
                .strip_prefix("<")
                .and_then(|s| s.strip_suffix(">"))
                .unwrap_or(original_rest.trim())
                .to_string();

            // Check per-rule auth requirement for this recipient,
            // falling back to the global auth_required setting
            let auth_needed = self.router.resolve_auth_required(&rcpt, self.auth_required);
            if !self.authenticated && auth_needed {
                warn!(rcpt = %rcpt, "RCPT TO rejected: authentication required");
                self.write_response(writer, 530, "Authentication required")
                    .await;
                return Ok(());
            }

            info!(rcpt = %rcpt, "RCPT TO accepted");
            self.rcpts.insert(rcpt);
            self.write_response(writer, 250, "OK").await;
        } else {
            self.write_response(writer, 501, "Syntax error in parameters or arguments")
                .await;
        }

        Ok(())
    }

    async fn handle_data<R: AsyncRead + AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        tx: &mpsc::Sender<IncomingMessage>,
    ) -> Result<(), Box<dyn Error>> {
        if !self.authenticated && self.auth_required {
            self.write_response(writer, 530, "Authentication required")
                .await;
            return Ok(());
        }
        if self.rcpts.is_empty() {
            self.write_response(writer, 554, "No valid recipients")
                .await;
            return Ok(());
        }

        self.write_response(writer, 354, "End data with <CR><LF>.<CR><LF>")
            .await;

        let mut buffer = [0u8; 8192];
        let mut buffer_data = Vec::<u8>::with_capacity(64 * 1024); // Pre-allocate 64KB for typical emails
        let mut last_bytes = [0u8; 5];
        let mut last_bytes_len = 0usize;

        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = &buffer[..n];
                    buffer_data.extend_from_slice(chunk);

                    // Update sliding window with new bytes (fixed-size array, no allocation)
                    for &byte in chunk {
                        if last_bytes_len < 5 {
                            last_bytes[last_bytes_len] = byte;
                            last_bytes_len += 1;
                        } else {
                            last_bytes.rotate_left(1);
                            last_bytes[4] = byte;
                        }
                    }

                    // Check for termination sequence
                    if last_bytes_len == 5 && &last_bytes == b"\r\n.\r\n" {
                        buffer_data.truncate(buffer_data.len() - 5);
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        let data = String::from_utf8_lossy(&buffer_data).into_owned();
        let from = take(&mut self.from);
        let rcpts = take(&mut self.rcpts);

        info!(
            from = %from,
            recipients = rcpts.len(),
            size = buffer_data.len(),
            "Message received"
        );

        tx.send(IncomingMessage {
            from,
            rcpts,
            raw: data,
            client_ip: self.client_ip,
            helo_domain: self.helo_domain.clone(),
        })
        .await?;
        self.write_response(writer, 250, "Message accepted").await;

        Ok(())
    }

    async fn handle_rset<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> Result<(), Box<dyn Error>> {
        debug!("Session reset");
        self.from.clear();
        self.rcpts.clear();
        self.write_response(writer, 250, "OK").await;
        Ok(())
    }

    async fn handle_quit<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), Box<dyn Error>> {
        debug!("Client quit");
        self.write_response(writer, 221, "Bye").await;
        Ok(())
    }

    async fn handle_unknown<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), Box<dyn Error>> {
        warn!("Unrecognized command");
        self.write_response(writer, 502, "Command not implemented")
            .await;
        Ok(())
    }

    async fn read_command<R: AsyncRead + AsyncBufRead + Unpin>(
        &mut self,
        reader: &mut R,
        line: &mut String,
    ) -> (String, Option<String>) {
        line.clear();
        reader.read_line(line).await.unwrap_or(0);

        let mut parts = line.split_whitespace();
        let command = parts.next().unwrap_or("").to_uppercase();
        let argument = parts.next().map(|arg| arg.to_string());

        (command, argument)
    }

    async fn write_inner<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        code: u16,
        message: &str,
        separator: &str,
    ) {
        debug!(
            tls = self.starttls,
            code = code,
            ">> {code}{separator}{message}"
        );
        writer
            .write_all(format!("{code}{separator}{message}\r\n").as_bytes())
            .await
            .ok();
    }

    async fn write_response<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        code: u16,
        message: &str,
    ) {
        self.write_inner(writer, code, message, " ").await;
    }

    async fn write_multiple<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        code: u16,
        messages: &[&str],
    ) {
        for (index, message) in messages.iter().enumerate() {
            let is_last = index == messages.len() - 1;
            let separator = if is_last { " " } else { "-" };
            self.write_inner(writer, code, message, separator).await;
        }
    }
}

/// Builds a message router from the SMTP configuration.
///
/// Creates handler instances from the config and wires up routing rules.
async fn build_router(
    config: &mailsis_utils::SmtpConfig,
    crate_root: &std::path::Path,
) -> Result<MessageRouter, Box<dyn Error>> {
    let mut handlers: std::collections::HashMap<String, Arc<dyn MessageHandler>> =
        std::collections::HashMap::new();

    // Build handler instances from config
    for (name, handler_config) in &config.handlers {
        let handler: Arc<dyn MessageHandler> = match handler_config {
            HandlerConfig::FileStorage { path, metadata } => {
                let base_path = crate_root.join(path);
                Arc::new(FileStorageHandler::new(base_path, *metadata)) as Arc<dyn MessageHandler>
            }
            #[cfg(feature = "redis")]
            HandlerConfig::Redis { url, queue } => {
                Arc::new(mailsis_utils::RedisQueueHandler::new(url, queue.clone())?)
                    as Arc<dyn MessageHandler>
            }
            #[cfg(not(feature = "redis"))]
            HandlerConfig::Redis { .. } => {
                return Err(
                    format!("Handler '{name}' requires the 'redis' feature to be enabled").into(),
                );
            }
        };
        info!(name = %name, "Registered handler");
        handlers.insert(name.clone(), handler);
    }

    // Resolve default handler
    let default_handler = handlers
        .get(&config.routing.default)
        .cloned()
        .ok_or_else(|| {
            format!(
                "Default handler '{}' not found in handlers config",
                config.routing.default
            )
        })?;

    // Build default transformers from config
    let default_transformers =
        build_transformers(&config.routing.transformers, &config.hostname).await;

    // Build routing rules
    let mut rules = Vec::new();
    for rule_config in &config.routing.rules {
        let handler = handlers.get(&rule_config.handler).cloned().ok_or_else(|| {
            format!(
                "Handler '{}' referenced in routing rule not found",
                rule_config.handler
            )
        })?;

        let match_type = determine_match_type(&rule_config.address, &rule_config.domain);
        let pattern = extract_pattern(&rule_config.address, &rule_config.domain);
        let transformers = rule_config
            .transformers
            .as_ref()
            .map(|t| build_transformers(t, &config.hostname));
        let transformers = match transformers {
            Some(fut) => fut.await,
            None => Vec::new(),
        };

        rules.push(RoutingRule {
            match_type,
            pattern,
            handler,
            transformers,
            auth_required: rule_config.auth_required,
        });
    }

    info!(
        rules = rules.len(),
        default = %config.routing.default,
        "Router configured"
    );
    Ok(MessageRouter::new(
        rules,
        default_handler,
        default_transformers,
    ))
}

/// Builds transformer instances from their configuration.
///
/// The `hostname` parameter is used as the default `authserv_id` for the
/// `email_auth` transformer when none is explicitly configured.
async fn build_transformers(
    configs: &[TransformerConfig],
    hostname: &str,
) -> Vec<Box<dyn MessageTransformer>> {
    let mut transformers: Vec<Box<dyn MessageTransformer>> = Vec::with_capacity(configs.len());
    for config in configs {
        let transformer: Box<dyn MessageTransformer> = match config {
            TransformerConfig::MessageId { domain } => {
                Box::new(MessageIdTransformer::new(domain.clone()))
            }
            #[cfg(feature = "email-auth")]
            TransformerConfig::EmailAuth { authserv_id } => {
                let id = if authserv_id.is_empty() {
                    hostname.to_string()
                } else {
                    authserv_id.clone()
                };
                Box::new(mailsis_utils::EmailAuthTransformer::new(id).await)
            }
            #[cfg(not(feature = "email-auth"))]
            TransformerConfig::EmailAuth { .. } => {
                let _ = hostname;
                warn!("email_auth transformer requires the 'email-auth' feature to be enabled, skipping");
                continue;
            }
        };
        transformers.push(transformer);
    }
    transformers
}

/// Main function for the Mailsis SMTP server.
///
/// It will listen for incoming connections on the specified port and handle them
/// using the [`handle_smtp_session`] function.
///
/// It will also spawn a task to handle the email routing, this is a long running
/// task that will run until the program is terminated.
#[tokio::main(flavor = "multi_thread", worker_threads = 16)]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::ChronoLocal::new(
            "%Y-%m-%d %H:%M:%S".to_string(),
        ))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let crate_root = get_crate_root().unwrap_or(PathBuf::from_str(".").unwrap());

    // Load configuration from file
    let config_path = std::env::var("MAILSIS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| crate_root.join("config.toml"));

    let config = load_config(&config_path).unwrap_or_else(|error| {
        warn!(
            path = %config_path.display(),
            error = %error,
            "Could not load config, using defaults"
        );
        toml::from_str("[smtp]").unwrap()
    });

    let smtp = &config.smtp;

    let cert_path = crate_root.join(&smtp.tls.cert);
    let key_path = crate_root.join(&smtp.tls.key);

    let tls_config = Arc::new(
        load_tls_server_config(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).map_err(
            |error| {
                error!(
                    cert = %cert_path.display(),
                    key = %key_path.display(),
                    error = %error,
                    "Failed to load TLS configuration"
                );
                error
            },
        )?,
    );

    let host = std::env::var("HOST").unwrap_or_else(|_| smtp.host.clone());
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(smtp.port);
    let listening = format!("{host}:{port}");
    let listener = TcpListener::bind(&listening).await.map_err(|error| {
        error!(address = %listening, error = %error, "Failed to bind TCP listener");
        error
    })?;

    let tls_acceptor = TlsAcceptor::from(tls_config);
    let auth_engine = Arc::new(
        load_credentials(&smtp.auth.credentials_file).map_err(|error| {
            error!(
                file = %smtp.auth.credentials_file,
                error = %error,
                "Failed to load credentials"
            );
            error
        })?,
    );

    // Build the message router from config
    let router = Arc::new(build_router(smtp, &crate_root).await.map_err(|error| {
        error!(error = %error, "Failed to build message router");
        error
    })?);

    let (tx, mut rx) = mpsc::channel::<IncomingMessage>(100);

    // Spawn a task to handle the email routing, this is a long running
    // task that will run until the program is terminated
    let router_handle = router.clone();
    tokio::spawn(async move {
        while let Some(incoming) = rx.recv().await {
            for rcpt in &incoming.rcpts {
                let handler = router_handle.resolve(rcpt);
                info!(
                    from = %incoming.from,
                    recipient = %rcpt,
                    handler = handler.name(),
                    "Routing email"
                );
                let mut message = incoming.to_email_message(rcpt);
                if let Err(error) = router_handle.route(&mut message).await {
                    error!(recipient = %rcpt, error = %error, "Failed to route email");
                }
            }
        }
    });

    let auth_required = smtp.auth_required;
    info!(address = %listening, hostname = %smtp.hostname, "Mailsis-SMTP started");

    loop {
        let (stream, addr) = listener.accept().await.map_err(|error| {
            error!(error = %error, "Failed to accept connection");
            error
        })?;
        let tls_acceptor = tls_acceptor.clone();
        let tx = tx.clone();
        let auth_engine = auth_engine.clone();
        let router = router.clone();
        tokio::spawn(async move {
            info!(peer = %addr, "Connection accepted");
            match handle_smtp_session(stream, tls_acceptor, tx, auth_engine, auth_required, router)
                .await
            {
                Ok(()) => info!(peer = %addr, "Connection closed"),
                Err(error) => {
                    error!(peer = %addr, error = %error, "SMTP session failed")
                }
            }
        });
    }
}

async fn handle_smtp_session<A: AuthEngine + 'static>(
    stream: TcpStream,
    tls_acceptor: TlsAcceptor,
    tx: mpsc::Sender<IncomingMessage>,
    auth_engine: Arc<A>,
    auth_required: bool,
    router: Arc<MessageRouter>,
) -> Result<(), Box<dyn Error>> {
    // Optimize TCP settings, removing the delay and setting the TTL to 64
    stream.set_nodelay(true).expect("Failed to set TCP_NODELAY");
    stream.set_ttl(64).expect("Failed to set TTL");

    // Create a new SMTP session with default values, split the stream into reader and writer
    // and handle the loop starting the SMTP session
    let client_ip = stream.peer_addr().ok().map(|addr| addr.ip());
    let mut session = SMTPSession::new(auth_engine, auth_required, router, client_ip);
    let (reader, writer) = split(stream);
    handle_stream(reader, writer, tls_acceptor, tx, &mut session).await?;
    Ok(())
}

async fn handle_stream<A: AuthEngine + 'static>(
    reader: ReadHalf<TcpStream>,
    mut writer: WriteHalf<TcpStream>,
    tls_acceptor: TlsAcceptor,
    tx: mpsc::Sender<IncomingMessage>,
    session: &mut SMTPSession<A>,
) -> Result<(), Box<dyn Error>> {
    let mut line = String::with_capacity(4096);
    let mut reader = BufReader::new(reader);

    session
        .write_response(&mut writer, 220, "localhost Mailsis SMTP")
        .await;

    loop {
        let (command, argument) = session.read_command(&mut reader, &mut line).await;
        if line.is_empty() {
            break;
        }

        debug!("<< {}", line.trim());

        match command.as_str() {
            "STARTTLS" => {
                session
                    .write_response(&mut writer, 220, "Ready to start TLS")
                    .await;
                let stream = ReadHalf::unsplit(reader.into_inner(), writer);
                match tls_acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        info!("TLS handshake complete");
                        session.starttls = true;
                        return handle_tls_stream(TlsStream::Server(tls_stream), tx, session).await;
                    }
                    Err(error) => {
                        error!(error = ?error, "TLS handshake failed");
                        return Ok(());
                    }
                }
            }
            _ => {
                session
                    .handle_command(
                        &mut reader,
                        &mut writer,
                        &tx,
                        &mut line,
                        &command,
                        argument.as_deref(),
                    )
                    .await?;
            }
        }
    }
    Ok(())
}

async fn handle_tls_stream<A: AuthEngine + 'static>(
    stream: TlsStream<TcpStream>,
    tx: mpsc::Sender<IncomingMessage>,
    session: &mut SMTPSession<A>,
) -> Result<(), Box<dyn Error>> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::with_capacity(4096);

    loop {
        let (command, argument) = session.read_command(&mut reader, &mut line).await;
        if line.is_empty() {
            break;
        }

        debug!("<< [TLS] {}", line.trim());

        session
            .handle_command(
                &mut reader,
                &mut writer,
                &tx,
                &mut line,
                &command,
                argument.as_deref(),
            )
            .await?;
    }
    Ok(())
}

/// Loads the credentials from the file and return a MemoryAuthEngine.
///
/// The file should be formatted as follows:
/// ```text
/// username:password
/// username2:password2
/// ```
fn load_credentials(path: &str) -> std::io::Result<MemoryAuthEngine> {
    MemoryAuthEngine::from_file(path)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tokio::io::duplex;

    use super::*;

    fn test_router() -> Arc<MessageRouter> {
        Arc::new(MessageRouter::new(
            vec![],
            Arc::new(mailsis_utils::FileStorageHandler::new(
                std::path::PathBuf::from("test_mailbox"),
                false,
            )),
            vec![],
        ))
    }

    #[tokio::test]
    async fn test_handle_ehlo_helo_writes_greeting() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let session = SMTPSession::new(auth_engine, false, test_router(), None);

        let (mut client, mut server) = duplex(1024);
        session.handle_ehlo_helo(&mut server).await.unwrap();
        drop(server);

        let mut output = String::new();
        client.read_to_string(&mut output).await.unwrap();
        assert_eq!(
            output,
            "250-localhost greets you\r\n250-STARTTLS\r\n250 AUTH LOGIN\r\n"
        );
    }

    #[tokio::test]
    async fn test_handle_auth_login_success() {
        let mut map = HashMap::new();
        map.insert("user".to_string(), "pass".to_string());
        let auth_engine = Arc::new(MemoryAuthEngine::from_map(map));
        let mut session = SMTPSession::new(auth_engine, false, test_router(), None);

        let encoded_user = STANDARD.encode("user");
        let encoded_pass = STANDARD.encode("pass");
        let input = format!("{encoded_user}\r\n{encoded_pass}\r\n");

        let (client, server) = duplex(1024);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (server_read, mut server_write) = tokio::io::split(server);
        let mut reader = BufReader::new(server_read);
        let write_task = tokio::spawn(async move {
            client_write.write_all(input.as_bytes()).await.unwrap();
            drop(client_write);
        });

        let mut line = String::new();
        session
            .handle_auth_login(&mut reader, &mut server_write, &mut line)
            .await
            .unwrap();
        drop(server_write);
        drop(reader);
        write_task.await.unwrap();

        let mut output = String::new();
        client_read.read_to_string(&mut output).await.unwrap();
        assert!(session.authenticated);
        assert_eq!(
            output,
            "334 VXNlcm5hbWU6\r\n334 UGFzc3dvcmQ6\r\n235 Authentication successful\r\n"
        );
    }

    #[tokio::test]
    async fn test_handle_mail_and_rcpt_adds_addresses() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let mut session = SMTPSession::new(auth_engine, false, test_router(), None);

        let (mut client, mut server) = duplex(1024);
        session
            .handle_mail(&mut server, "FROM:<sender@example.com>")
            .await
            .unwrap();
        session
            .handle_rcpt(&mut server, "TO:<recipient@example.com>")
            .await
            .unwrap();
        drop(server);

        let mut output = String::new();
        client.read_to_string(&mut output).await.unwrap();

        assert_eq!(session.from, "sender@example.com");
        assert!(session.rcpts.contains("recipient@example.com"));
        assert_eq!(output, "250 OK\r\n250 OK\r\n");
    }

    #[tokio::test]
    async fn test_handle_auth_login_failure() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let mut session = SMTPSession::new(auth_engine, false, test_router(), None);

        let encoded_user = STANDARD.encode("user");
        let encoded_pass = STANDARD.encode("wrong");
        let input = format!("{encoded_user}\r\n{encoded_pass}\r\n");

        let (client, server) = duplex(1024);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (server_read, mut server_write) = tokio::io::split(server);
        let mut reader = BufReader::new(server_read);
        let write_task = tokio::spawn(async move {
            client_write.write_all(input.as_bytes()).await.unwrap();
            drop(client_write);
        });

        let mut line = String::new();
        session
            .handle_auth_login(&mut reader, &mut server_write, &mut line)
            .await
            .unwrap();
        drop(server_write);
        drop(reader);
        write_task.await.unwrap();

        let mut output = String::new();
        client_read.read_to_string(&mut output).await.unwrap();
        assert!(!session.authenticated);
        assert!(output.contains("535 Authentication failed"));
    }

    #[tokio::test]
    async fn test_handle_auth_with_username() {
        let mut map = HashMap::new();
        map.insert("admin".to_string(), "secret".to_string());
        let auth_engine = Arc::new(MemoryAuthEngine::from_map(map));
        let mut session = SMTPSession::new(auth_engine, false, test_router(), None);

        let encoded_user = STANDARD.encode("admin");
        let encoded_pass = STANDARD.encode("secret");
        let input = format!("{encoded_pass}\r\n");

        let (client, server) = duplex(1024);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (server_read, mut server_write) = tokio::io::split(server);
        let mut reader = BufReader::new(server_read);
        let write_task = tokio::spawn(async move {
            client_write.write_all(input.as_bytes()).await.unwrap();
            drop(client_write);
        });

        let mut line = String::new();
        session
            .handle_auth_with_username(
                &mut reader,
                &mut server_write,
                &mut line,
                &format!(" {encoded_user}"),
            )
            .await
            .unwrap();
        drop(server_write);
        drop(reader);
        write_task.await.unwrap();

        let mut output = String::new();
        client_read.read_to_string(&mut output).await.unwrap();
        assert!(session.authenticated);
        assert!(output.contains("235 Authentication successful"));
    }

    #[tokio::test]
    async fn test_handle_mail_auth_required() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let mut session = SMTPSession::new(auth_engine, true, test_router(), None);

        let (mut client, mut server) = duplex(1024);
        session
            .handle_mail(&mut server, "FROM:<sender@example.com>")
            .await
            .unwrap();
        drop(server);

        let mut output = String::new();
        client.read_to_string(&mut output).await.unwrap();
        assert!(output.contains("530 Authentication required"));
    }

    #[tokio::test]
    async fn test_handle_mail_syntax_error() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let mut session = SMTPSession::new(auth_engine, false, test_router(), None);

        let (mut client, mut server) = duplex(1024);
        session.handle_mail(&mut server, "INVALID").await.unwrap();
        drop(server);

        let mut output = String::new();
        client.read_to_string(&mut output).await.unwrap();
        assert!(output.contains("501 Syntax error"));
    }

    #[tokio::test]
    async fn test_handle_rcpt_syntax_error() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let mut session = SMTPSession::new(auth_engine, false, test_router(), None);

        let (mut client, mut server) = duplex(1024);
        session.handle_rcpt(&mut server, "INVALID").await.unwrap();
        drop(server);

        let mut output = String::new();
        client.read_to_string(&mut output).await.unwrap();
        assert!(output.contains("501 Syntax error"));
    }

    #[tokio::test]
    async fn test_handle_data_no_recipients() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let mut session = SMTPSession::new(auth_engine, false, test_router(), None);

        let (client, server) = duplex(1024);
        let (mut client_read, _client_write) = tokio::io::split(client);
        let (server_read, mut server_write) = tokio::io::split(server);
        let mut reader = BufReader::new(server_read);
        let (tx, _rx) = mpsc::channel(10);

        session
            .handle_data(&mut reader, &mut server_write, &tx)
            .await
            .unwrap();
        drop(server_write);
        drop(reader);

        let mut output = String::new();
        client_read.read_to_string(&mut output).await.unwrap();
        assert!(output.contains("554 No valid recipients"));
    }

    #[tokio::test]
    async fn test_handle_data_auth_required() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let mut session = SMTPSession::new(auth_engine, true, test_router(), None);

        let (client, server) = duplex(1024);
        let (mut client_read, _client_write) = tokio::io::split(client);
        let (server_read, mut server_write) = tokio::io::split(server);
        let mut reader = BufReader::new(server_read);
        let (tx, _rx) = mpsc::channel(10);

        session
            .handle_data(&mut reader, &mut server_write, &tx)
            .await
            .unwrap();
        drop(server_write);
        drop(reader);

        let mut output = String::new();
        client_read.read_to_string(&mut output).await.unwrap();
        assert!(output.contains("530 Authentication required"));
    }

    #[tokio::test]
    async fn test_handle_data_success() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let mut session = SMTPSession::new(auth_engine, false, test_router(), None);
        session.from = "sender@example.com".to_string();
        session.rcpts.insert("rcpt@example.com".to_string());

        let body = "Subject: Hello\r\n\r\nBody text\r\n.\r\n";

        let (client, server) = duplex(4096);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (server_read, mut server_write) = tokio::io::split(server);
        let mut reader = BufReader::new(server_read);
        let (tx, mut rx) = mpsc::channel(10);

        let write_task = tokio::spawn(async move {
            client_write.write_all(body.as_bytes()).await.unwrap();
            drop(client_write);
        });

        session
            .handle_data(&mut reader, &mut server_write, &tx)
            .await
            .unwrap();
        drop(server_write);
        drop(reader);
        write_task.await.unwrap();

        let mut output = String::new();
        client_read.read_to_string(&mut output).await.unwrap();
        assert!(output.contains("354 End data"));
        assert!(output.contains("250 Message accepted"));

        let incoming = rx.recv().await.unwrap();
        assert!(incoming.rcpts.contains("rcpt@example.com"));
        assert_eq!(incoming.from, "sender@example.com");
        assert!(incoming.raw.contains("Body text"));
    }

    #[tokio::test]
    async fn test_handle_rset() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let mut session = SMTPSession::new(auth_engine, false, test_router(), None);
        session.from = "sender@example.com".to_string();
        session.rcpts.insert("rcpt@example.com".to_string());

        let (mut client, mut server) = duplex(1024);
        session.handle_rset(&mut server).await.unwrap();
        drop(server);

        let mut output = String::new();
        client.read_to_string(&mut output).await.unwrap();
        assert_eq!(output, "250 OK\r\n");
        assert!(session.from.is_empty());
        assert!(session.rcpts.is_empty());
    }

    #[tokio::test]
    async fn test_handle_quit() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let session = SMTPSession::new(auth_engine, false, test_router(), None);

        let (mut client, mut server) = duplex(1024);
        session.handle_quit(&mut server).await.unwrap();
        drop(server);

        let mut output = String::new();
        client.read_to_string(&mut output).await.unwrap();
        assert_eq!(output, "221 Bye\r\n");
    }

    #[tokio::test]
    async fn test_handle_unknown() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let session = SMTPSession::new(auth_engine, false, test_router(), None);

        let (mut client, mut server) = duplex(1024);
        session.handle_unknown(&mut server).await.unwrap();
        drop(server);

        let mut output = String::new();
        client.read_to_string(&mut output).await.unwrap();
        assert_eq!(output, "502 Command not implemented\r\n");
    }

    #[tokio::test]
    async fn test_handle_command_dispatch_rset() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let mut session = SMTPSession::new(auth_engine, false, test_router(), None);
        session.from = "test@example.com".to_string();
        let (tx, _rx) = mpsc::channel(10);

        let (client, server) = duplex(1024);
        let (mut client_read, _client_write) = tokio::io::split(client);
        let (server_read, mut server_write) = tokio::io::split(server);
        let mut reader = BufReader::new(server_read);
        let mut line = String::new();

        session
            .handle_command(&mut reader, &mut server_write, &tx, &mut line, "RSET", None)
            .await
            .unwrap();
        drop(server_write);
        drop(reader);

        let mut output = String::new();
        client_read.read_to_string(&mut output).await.unwrap();
        assert_eq!(output, "250 OK\r\n");
        assert!(session.from.is_empty());
    }

    #[tokio::test]
    async fn test_read_command() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let mut session = SMTPSession::new(auth_engine, false, test_router(), None);

        let input = b"MAIL FROM:<sender@example.com>\r\n";
        let mut reader = BufReader::new(&input[..]);
        let mut line = String::new();

        let (command, argument) = session.read_command(&mut reader, &mut line).await;
        assert_eq!(command, "MAIL");
        assert_eq!(argument.as_deref(), Some("FROM:<sender@example.com>"));
    }

    #[tokio::test]
    async fn test_write_response_format() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let session = SMTPSession::new(auth_engine, false, test_router(), None);

        let (mut client, mut server) = duplex(1024);
        session.write_response(&mut server, 250, "OK").await;
        drop(server);

        let mut output = String::new();
        client.read_to_string(&mut output).await.unwrap();
        assert_eq!(output, "250 OK\r\n");
    }

    #[tokio::test]
    async fn test_build_transformers_message_id() {
        let configs = vec![TransformerConfig::MessageId {
            domain: "example.com".to_string(),
        }];
        let transformers = build_transformers(&configs, "localhost").await;
        assert_eq!(transformers.len(), 1);
    }

    #[test]
    fn test_load_credentials_not_found() {
        let result = load_credentials("/nonexistent/path.txt");
        assert!(result.is_err());
    }
}
