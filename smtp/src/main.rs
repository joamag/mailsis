use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use mailsis_utils::{
    get_crate_root, is_mime_valid, load_tls_server_config, parse_mime_headers, AuthEngine,
    EmailMetadata, MemoryAuthEngine,
};
use std::{collections::HashSet, error::Error, mem::take, path::PathBuf, str::FromStr, sync::Arc};
use tokio::{
    fs::{self, File},
    io::{
        split, AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
        BufReader, ReadHalf, WriteHalf,
    },
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::{TlsAcceptor, TlsStream};
use uuid::Uuid;

const HOST: &str = "127.0.0.1";
const PORT: u16 = 2525;

/// Represents a single SMTP session, created for each incoming connection.
///
/// This struct is used to store the state of the SMTP session, including the
/// from address, the recipients, whether the session is authenticated, whether
/// TLS is required, and the authentication engine.
#[derive(Debug, Default)]
struct SMTPSession<A: AuthEngine> {
    from: String,
    rcpts: HashSet<String>,
    authenticated: bool,
    auth_required: bool,
    starttls: bool,
    auth_engine: Arc<A>,
}

impl<A: AuthEngine + Default> SMTPSession<A> {
    /// Create a new SMTP session with default values.
    pub fn new(auth_engine: Arc<A>, auth_required: bool) -> Self {
        Self {
            auth_required,
            auth_engine,
            ..Default::default()
        }
    }

    /// Base handler for the SMTP commands, should concentrate all the
    /// command handling in a single place for better maintainability.
    pub async fn handle_command<R: AsyncRead + AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        tx: &mpsc::Sender<(String, HashSet<String>, String)>,
        line: &mut String,
        command: &str,
        arg: Option<&str>,
    ) -> Result<(), Box<dyn Error>> {
        match command {
            "EHLO" | "HELO" => {
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
            self.write_response(writer, 235, "Authentication successful")
                .await;
            self.authenticated = true;
        } else {
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
            self.write_response(writer, 235, "Authentication successful")
                .await;
            self.authenticated = true;
        } else {
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
        // Ensure that the user is authenticated before sending the mail
        if !self.authenticated && self.auth_required {
            self.write_response(writer, 530, "Authentication required")
                .await;
            return Ok(());
        }

        // SMTP is case-insensitive, check prefix without allocation
        if value.len() >= 3 && value[..3].eq_ignore_ascii_case("TO:") {
            let original_rest = &value[3..];
            let rcpt = original_rest
                .trim()
                .strip_prefix("<")
                .and_then(|s| s.strip_suffix(">"))
                .unwrap_or(original_rest.trim())
                .to_string();
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
        tx: &mpsc::Sender<(String, HashSet<String>, String)>,
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

        tx.send((from, rcpts, data)).await?;
        self.write_response(writer, 250, "Message accepted").await;

        Ok(())
    }

    async fn handle_rset<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> Result<(), Box<dyn Error>> {
        self.from.clear();
        self.rcpts.clear();
        self.write_response(writer, 250, "OK").await;
        Ok(())
    }

    async fn handle_quit<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), Box<dyn Error>> {
        self.write_response(writer, 221, "Bye").await;
        Ok(())
    }

    async fn handle_unknown<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), Box<dyn Error>> {
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
        println!(
            ">> {}{}{}{}",
            if self.starttls { "[TLS] " } else { "" },
            code,
            separator,
            message
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

/// Main function for the SMTP server.
///
/// It will listen for incoming connections on the specified port and handle them
/// using the [`handle_smtp_session`] function.
///
/// It will also spawn a task to handle the email storage, this is a long running
/// task that will run until the program is terminated.
#[tokio::main(flavor = "multi_thread", worker_threads = 16)]
async fn main() -> Result<(), Box<dyn Error>> {
    let crate_root = get_crate_root().unwrap_or(PathBuf::from_str(".").unwrap());

    let cert_path = crate_root.join("certs").join("server.cert.pem");
    let key_path = crate_root.join("certs").join("server.key.pem");

    let tls_config = Arc::new(
        load_tls_server_config(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap(),
    );

    let host = std::env::var("HOST").unwrap_or_else(|_| HOST.to_string());
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| PORT.to_string())
        .parse()
        .unwrap();
    let listening = format!("{host}:{port}");
    let listener = TcpListener::bind(&listening).await?;

    let tls_acceptor = TlsAcceptor::from(tls_config);
    let auth_engine = Arc::new(load_credentials("passwords/example.txt")?);
    let (tx, mut rx) = mpsc::channel::<(String, HashSet<String>, String)>(100);

    // Spawn a task to handle the email storage, this is a long running
    // task that will run until the program is terminated
    tokio::spawn(async move {
        while let Some((from, rcpts, body)) = rx.recv().await {
            for rcpt in rcpts {
                if let Err(error) = store_email(&from, &rcpt, &body, true).await {
                    println!("Error storing email: {error}");
                }
            }
        }
    });

    println!("Mailsis-SMTP running on {}", &listening);

    loop {
        let (stream, _) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let tx = tx.clone();
        let auth_engine = auth_engine.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_smtp_session(stream, tls_acceptor, tx, auth_engine).await {
                eprintln!("Error: {e}");
            }
        });
    }
}

async fn handle_smtp_session<A: AuthEngine + 'static>(
    stream: TcpStream,
    tls_acceptor: TlsAcceptor,
    tx: mpsc::Sender<(String, HashSet<String>, String)>,
    auth_engine: Arc<A>,
) -> Result<(), Box<dyn Error>> {
    // Optimize TCP settings, removing the delay and setting the TTL to 64
    stream.set_nodelay(true).expect("Failed to set TCP_NODELAY");
    stream.set_ttl(64).expect("Failed to set TTL");

    // Create a new SMTP session with default values, split the stream into reader and writer
    // and handle the loop starting the SMTP session
    let mut session = SMTPSession::new(auth_engine, false);
    let (reader, writer) = split(stream);
    handle_stream(reader, writer, tls_acceptor, tx, &mut session).await?;
    Ok(())
}

async fn handle_stream<A: AuthEngine + 'static>(
    reader: ReadHalf<TcpStream>,
    mut writer: WriteHalf<TcpStream>,
    tls_acceptor: TlsAcceptor,
    tx: mpsc::Sender<(String, HashSet<String>, String)>,
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

        println!("<< {}", line.trim());

        match command.as_str() {
            "STARTTLS" => {
                session
                    .write_response(&mut writer, 220, "Ready to start TLS")
                    .await;
                let stream = ReadHalf::unsplit(reader.into_inner(), writer);
                match tls_acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        println!("TLS handshake complete");
                        session.starttls = true;
                        return handle_tls_stream(TlsStream::Server(tls_stream), tx, session).await;
                    }
                    Err(e) => {
                        eprintln!("TLS handshake failed: {e:?}");
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
    tx: mpsc::Sender<(String, HashSet<String>, String)>,
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

        println!("<< [TLS] {}", line.trim());

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

/// Loads the credentials from the file and returns a MemoryAuthEngine.
///
/// The file should be formatted as follows:
/// ```text
/// username:password
/// username2:password2
/// ```
fn load_credentials(path: &str) -> std::io::Result<MemoryAuthEngine> {
    MemoryAuthEngine::from_file(path)
}

/// Stores the email in the mailbox directory, creates the directory if it doesn't exist.
///
/// Each user has their own directory, and each email is stored in a file named with a UUID.
///
/// There's no limit to the number of emails that can be stored.
async fn store_email(
    from: &str,
    rcpt: &str,
    body: &str,
    store_meta: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let safe_rcpt = rcpt.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
    let crate_root = get_crate_root().unwrap_or(PathBuf::from_str(".").unwrap());
    let path = crate_root.join("mailbox").join(&safe_rcpt);
    fs::create_dir_all(&path).await?;
    let message_id = Uuid::new_v4().to_string();
    let file_path = path.join(format!("{message_id}.eml"));
    let file_path_str = file_path.to_str().unwrap();
    let mut file = File::create(&file_path).await?;
    println!("Started storing email to {file_path_str}");
    if !is_mime_valid(body).await {
        file.write_all(format!("From: {from}\r\n").as_bytes())
            .await?;
        file.write_all(format!("To: {rcpt}\r\n").as_bytes()).await?;
        file.write_all(format!("Date: {}\r\n\r\n", Utc::now().to_rfc2822()).as_bytes())
            .await?;
    }
    file.write_all(body.as_bytes()).await?;
    println!("Stored: {file_path_str}");

    // checks if the metadata should be stored, if so, it will
    // parse the headers and store the metadata in the database
    if store_meta {
        let headers = parse_mime_headers(body).unwrap_or_default();
        let subject = headers.get("Subject").cloned().unwrap_or_default();
        let metadata = EmailMetadata::new(
            message_id,
            from.to_string(),
            rcpt.to_string(),
            subject,
            file_path.clone(),
        );
        let db_path = crate_root.join("mailbox").join("metadata.db");
        metadata.store_sqlite(db_path).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use mailsis_utils::MemoryAuthEngine;
    use std::{collections::HashMap, sync::Arc};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, BufReader};

    use super::SMTPSession;

    #[tokio::test]
    async fn test_handle_ehlo_helo_writes_greeting() {
        let auth_engine = Arc::new(MemoryAuthEngine::new());
        let session = SMTPSession::new(auth_engine, false);

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
        let mut session = SMTPSession::new(auth_engine, false);

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
        let mut session = SMTPSession::new(auth_engine, false);

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
}
