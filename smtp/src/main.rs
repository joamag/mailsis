use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use mailsis_utils::{get_crate_root, is_mime_valid, load_tls_server_config};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    path::PathBuf,
    str::{FromStr, SplitWhitespace},
    sync::Arc,
};
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

struct SMTPSession {
    from: String,
    rcpts: HashSet<String>,
    authenticated: bool,
    auth_required: bool,
    starttls: bool,
    credentials: Arc<HashMap<String, String>>,
}

impl Default for SMTPSession {
    fn default() -> Self {
        Self {
            from: String::new(),
            rcpts: HashSet::new(),
            authenticated: false,
            auth_required: false,
            starttls: false,
            credentials: Arc::new(HashMap::new()),
        }
    }
}

impl SMTPSession {
    /// Create a new SMTP session with default values.
    pub fn new(credentials: Arc<HashMap<String, String>>, auth_required: bool) -> Self {
        Self {
            credentials,
            auth_required,
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
        command: &String,
        arg: Option<&str>,
    ) -> Result<(), Box<dyn Error>> {
        match command.as_str() {
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
        let username = general_purpose::STANDARD
            .decode(line.trim())
            .unwrap_or_default();
        let username = String::from_utf8_lossy(&username);

        self.write_response(writer, 334, "UGFzc3dvcmQ6").await;

        line.clear();
        reader.read_line(line).await.ok();
        let password = general_purpose::STANDARD
            .decode(line.trim())
            .unwrap_or_default();
        let password = String::from_utf8_lossy(&password);

        if self.credentials.get(username.trim()) == Some(&password.trim().to_string()) {
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
        let username = general_purpose::STANDARD
            .decode(encoded_user.trim())
            .unwrap_or_default();
        let username = String::from_utf8_lossy(&username);

        self.write_response(writer, 334, "UGFzc3dvcmQ6").await;

        line.clear();
        reader.read_line(line).await.ok();
        let password = general_purpose::STANDARD
            .decode(line.trim())
            .unwrap_or_default();
        let password = String::from_utf8_lossy(&password);

        if self.credentials.get(username.trim()) == Some(&password.trim().to_string()) {
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
        if !self.authenticated && self.auth_required {
            self.write_response(writer, 530, "Authentication required")
                .await;
        }
        if let Some(value) = value.strip_prefix("FROM:") {
            // Sanitize the from address, removing the prefix and suffix <>
            self.from = value
                .trim()
                .strip_prefix("<")
                .and_then(|s| s.strip_suffix(">"))
                .unwrap()
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
        if !self.authenticated && self.auth_required {
            self.write_response(writer, 530, "Authentication required")
                .await;
            return Ok(());
        }
        if let Some(value) = value.strip_prefix("TO:") {
            self.rcpts.insert(
                value
                    .trim()
                    .strip_prefix("<")
                    .and_then(|s| s.strip_suffix(">"))
                    .unwrap()
                    .to_string(),
            );
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

        let mut buffer = [0u8; 1024];
        let mut buffer_all = Vec::<u8>::new();

        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = &buffer[..n];
                    buffer_all.extend_from_slice(chunk);
                    if chunk.ends_with(b".\r\n") {
                        buffer_all.truncate(buffer_all.len() - 3);
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        let data = String::from_utf8_lossy(&buffer_all).into_owned();

        let _ = tx.send((self.from.clone(), self.rcpts.clone(), data)).await;
        self.write_response(writer, 250, "Message accepted").await;

        self.from.clear();
        self.rcpts.clear();

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

    async fn read_command<'a, R: AsyncRead + AsyncBufRead + Unpin>(
        &mut self,
        reader: &mut R,
        line: &'a mut String,
    ) -> (String, String, Option<String>) {
        line.clear();

        reader.read_line(line).await.unwrap_or(0);

        let line_clone = line.clone();

        let mut parts: SplitWhitespace<'_> = line.split_whitespace();
        let command = parts.next().unwrap_or("").trim_end().to_uppercase();
        let argument = match parts.next() {
            Some(arg) => Some(arg.trim_end().to_string()),
            None => None,
        };

        return (line_clone, command, argument);
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
            .write_all(format!("{}{}{}\r\n", code, separator, message).as_bytes())
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

#[tokio::main(flavor = "multi_thread", worker_threads = 16)]
async fn main() -> Result<(), Box<dyn Error>> {
    let crate_root = get_crate_root().unwrap_or(PathBuf::from_str(".").unwrap());

    let cert_path = crate_root.join("certs").join("server.cert.pem");
    let key_path = crate_root.join("certs").join("server.key.pem");

    let tls_config = Arc::new(
        load_tls_server_config(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap(),
    );

    let listening = format!("{}:{}", HOST, PORT);
    let listener = TcpListener::bind(&listening).await?;
    let tls_acceptor = TlsAcceptor::from(tls_config);
    let credentials = Arc::new(load_credentials("users.txt"));
    let (tx, mut rx) = mpsc::channel::<(String, HashSet<String>, String)>(100);

    // Spawn a task to handle the email storage, this is a long running
    // task that will run until the program is terminated
    tokio::spawn(async move {
        while let Some((from, rcpts, body)) = rx.recv().await {
            for rcpt in rcpts {
                if let Err(error) = store_email(from.clone(), rcpt, body.clone()).await {
                    println!("Error storing email: {}", error);
                }
            }
        }
    });

    println!("Mailsis-SMTP running on {}", &listening);

    loop {
        let (stream, _) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let tx = tx.clone();
        let credentials = credentials.clone();
        tokio::spawn(async move {
            handle_smtp_session(stream, tls_acceptor, tx, credentials)
                .await
                .unwrap();
        });
    }
}

async fn handle_smtp_session(
    stream: TcpStream,
    tls_acceptor: TlsAcceptor,
    tx: mpsc::Sender<(String, HashSet<String>, String)>,
    credentials: Arc<HashMap<String, String>>,
) -> Result<(), Box<dyn Error>> {
    // Optimize TCP settings, removing the delay and setting the TTL to 64
    stream.set_nodelay(true).expect("Failed to set TCP_NODELAY");
    stream.set_linger(None).expect("Failed to set SO_LINGER");
    stream.set_ttl(64).expect("Failed to set TTL");

    // Create a new SMTP session with default values, split the stream into reader and writer
    // and handle the loop starting the SMTP session
    let mut session = SMTPSession::new(credentials.clone(), false);
    let (reader, writer) = split(stream);
    handle_stream(reader, writer, tls_acceptor, tx, &mut session).await?;
    Ok(())
}

async fn handle_stream(
    reader: ReadHalf<TcpStream>,
    mut writer: WriteHalf<TcpStream>,
    tls_acceptor: TlsAcceptor,
    tx: mpsc::Sender<(String, HashSet<String>, String)>,
    session: &mut SMTPSession,
) -> Result<(), Box<dyn Error>> {
    let mut line = String::with_capacity(4096);
    let mut reader = BufReader::new(reader);

    session
        .write_response(&mut writer, 220, "localhost Mailsis SMTP")
        .await;

    loop {
        let (_, command, argument) = session.read_command(&mut reader, &mut line).await;
        if line == "" {
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
                        eprintln!("TLS handshake failed: {:?}", e);
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

async fn handle_tls_stream(
    stream: TlsStream<TcpStream>,
    tx: mpsc::Sender<(String, HashSet<String>, String)>,
    session: &mut SMTPSession,
) -> Result<(), Box<dyn Error>> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::with_capacity(4096);

    loop {
        let (_, command, argument) = session.read_command(&mut reader, &mut line).await;
        if line == "" {
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

/// Stores the email in the mailbox directory, creates the directory if it doesn't exist.
/// Each user has their own directory, and each email is stored in a file named with a UUID.
///
/// There's no limit to the number of emails that can be stored.
async fn store_email(from: String, rcpt: String, body: String) -> Result<(), Box<dyn Error>> {
    let safe_rcpt = rcpt.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
    let crate_root = get_crate_root().unwrap_or(PathBuf::from_str(".").unwrap());
    let path = crate_root.join("mailbox").join(safe_rcpt);
    fs::create_dir_all(&path).await?;
    let file_path = path.join(format!("{}.eml", Uuid::new_v4()));
    let file_path_str = file_path.to_str().unwrap();
    let mut file = File::create(&file_path).await?;
    println!("Started storing email to {}", file_path_str);
    if !is_mime_valid(&body).await {
        file.write_all(format!("From: {}\r\n", from).as_bytes())
            .await?;
        file.write_all(format!("To: {}\r\n", rcpt).as_bytes())
            .await?;
        file.write_all(format!("Date: {}\r\n\r\n", Utc::now().to_rfc2822()).as_bytes())
            .await?;
    }
    file.write_all(body.as_bytes()).await?;
    println!("Stored: {}", file_path_str);
    Ok(())
}
