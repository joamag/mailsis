use std::{error::Error, path::PathBuf, sync::Arc};

use mailsis_utils::{
    get_crate_root, uid_fetch_range_str, AuthEngine, FileStorageEngine, MemoryAuthEngine,
    StorageEngine,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info};

const HOST: &str = "127.0.0.1";
const PORT: u16 = 1430;

struct IMAPSession<A: AuthEngine, S: StorageEngine> {
    authenticated: bool,
    username: Option<String>,
    mailbox: Option<String>,
    safe_username: Option<String>,
    auth_engine: Arc<A>,
    storage_engine: Arc<S>,
}

impl<A: AuthEngine, S: StorageEngine> IMAPSession<A, S> {
    fn new(auth_engine: Arc<A>, storage_engine: Arc<S>) -> Self {
        Self {
            authenticated: false,
            username: None,
            mailbox: None,
            safe_username: None,
            auth_engine,
            storage_engine,
        }
    }
}

impl<A: AuthEngine, S: StorageEngine> IMAPSession<A, S> {
    async fn handle_command<R: AsyncRead + AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        &mut self,
        _reader: &mut R,
        writer: &mut W,
        tag: &str,
        command: &str,
        parts: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        match command {
            "LOGIN" => self.handle_login(writer, tag, parts).await,
            "LOGOUT" => self.handle_logout(writer, tag).await,
            "LIST" => self.handle_list(writer, tag, parts).await,
            "SELECT" | "EXAMINE" => self.handle_select(writer, tag, parts).await,
            "SEARCH" => self.handle_search(writer, tag, parts).await,
            "FETCH" => self.handle_fetch(writer, tag, parts).await,
            "STATUS" => self.handle_status(writer, tag, parts).await,
            "CREATE" => self.handle_create(writer, tag, parts).await,
            "UID" => self.handle_uid(writer, tag, parts).await,
            "CAPABILITY" => self.handle_capability(writer, tag).await,
            "NOOP" => self.handle_noop(writer, tag).await,
            _ => {
                self.write_response(
                    writer,
                    tag,
                    "BAD",
                    format!("Unknown command ({command})").as_str(),
                )
                .await
            }
        }
    }

    async fn handle_login<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        parts: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        if parts.len() >= 4 {
            let username = parts[2].trim_matches('"');
            let password = parts[3].trim_matches('"');

            if self.auth_engine.authenticate(username, password).is_ok() {
                self.authenticated = true;
                self.safe_username =
                    Some(username.replace(|c: char| !c.is_ascii_alphanumeric(), "_"));
                self.username = Some(username.to_string());
                self.write_response(writer, tag, "OK", "LOGIN completed")
                    .await?;
            } else {
                self.write_response(writer, tag, "NO", "Invalid credentials")
                    .await?;
            }
        } else {
            self.write_response(writer, tag, "BAD", "Invalid login syntax")
                .await?;
        }
        Ok(())
    }

    async fn handle_logout<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.authenticated = false;
        self.username = None;
        self.mailbox = None;
        self.safe_username = None;
        self.write_response(writer, tag, "OK", "LOGOUT completed")
            .await?;
        Ok(())
    }

    async fn handle_list<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        parts: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        if parts.len() >= 3 {
            if parts[3] == "\"*\"" {
                self.write_response(writer, "*", "LIST", "(\\HasNoChildren) \"/\" \"INBOX\"")
                    .await?;
            }
            self.write_response(writer, tag, "OK", "LIST completed")
                .await?;
        } else {
            self.write_response(writer, tag, "BAD", "Invalid mailbox name")
                .await?;
        }
        Ok(())
    }

    async fn handle_select<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        parts: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        if parts.len() >= 2 {
            let mailbox_name = parts[2].trim_matches('"').to_string();
            self.mailbox = Some(mailbox_name.clone());
            let messages = match self.search_messages("").await.ok() {
                Some(messages) => messages,
                None => {
                    self.mailbox = None;
                    self.write_response(
                        writer,
                        tag,
                        "NO",
                        &format!("mailbox \"{mailbox_name}\" does not exist"),
                    )
                    .await?;
                    return Ok(());
                }
            };
            self.write_response(writer, "*", "FLAGS", "(\\Seen)")
                .await?;
            self.write_response(writer, "*", &messages.len().to_string(), "EXISTS")
                .await?;
            self.write_response(writer, tag, "OK", "SELECT completed")
                .await?;
        } else {
            self.write_response(writer, tag, "BAD", "Invalid mailbox name")
                .await?;
        }
        Ok(())
    }

    async fn handle_search<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        parts: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        if parts.len() >= 2 {
            let criteria = parts[1].to_string();
            let messages = self.search_messages(&criteria).await?;
            let messages_str = messages
                .into_iter()
                .map(|m| m.to_string())
                .collect::<Vec<String>>()
                .join(" ");
            self.write_response(writer, "*", "SEARCH", &messages_str)
                .await?;
            self.write_response(writer, tag, "OK", "SEARCH completed")
                .await?;
        } else {
            self.write_response(writer, tag, "BAD", "Invalid search criteria")
                .await?;
        }
        Ok(())
    }

    async fn handle_fetch<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        parts: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        if parts.len() >= 4 {
            let message_id = parts[2];
            let message_sequence = 1;
            let format_inner = &parts[3][1..parts[3].len() - 1];
            let message = self.fetch_message(message_id).await?;
            self.write_response(
                writer,
                "*",
                &message_sequence.to_string(),
                format!("FETCH ({} {{{}}}", format_inner, message.len()).as_str(),
            )
            .await?;
            self.write_raw(writer, &message).await;
            self.write_raw(writer, ")\r\n").await;
            self.write_response(writer, tag, "OK", "FETCH completed")
                .await?;
        } else {
            self.write_response(writer, tag, "BAD", "Invalid message ID")
                .await?;
        }
        Ok(())
    }

    async fn handle_status<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        parts: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        if parts.len() >= 2 {
            let mailbox = parts[1].to_string();
            let messages = self.search_messages("").await?;
            self.write_response(
                writer,
                "*",
                "STATUS",
                &format!(
                    "\"{}\" (UIDNEXT {} MESSAGES {} UNSEEN 0 RECENT 0)",
                    messages.len() + 1,
                    messages.len(),
                    mailbox
                ),
            )
            .await?;
            self.write_response(writer, tag, "OK", "STATUS completed")
                .await?;
        } else {
            self.write_response(writer, tag, "BAD", "Invalid mailbox name")
                .await?;
        }

        Ok(())
    }

    async fn handle_create<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        parts: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        if parts.len() >= 2 {
            let mailbox = parts[2].trim_matches('"').to_string();
            self.storage_engine
                .create_mailbox(self.safe_username(), &mailbox)
                .await
                .map_err(|error| format!("Failed to create mailbox: {error}"))?;
            self.write_response(writer, tag, "OK", "CREATE completed")
                .await?;
        } else {
            self.write_response(writer, tag, "BAD", "Invalid mailbox name")
                .await?;
        }
        Ok(())
    }

    async fn handle_uid<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        parts: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        let uid_command = parts[2].to_uppercase();
        match uid_command.as_str() {
            "FETCH" => self.handle_uid_fetch(writer, tag, parts).await?,
            _ => {
                self.write_response(
                    writer,
                    tag,
                    "BAD",
                    &format!("Invalid UID command {uid_command}"),
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn handle_uid_fetch<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        parts: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        let messages = self.search_messages("").await?;

        // Obtain the range of UIDs that are meant to be fetched, converting
        // the string based IMAP range into a rust one
        let range = uid_fetch_range_str(parts[3], messages.len() as u32).ok_or("Invalid range")?;
        let (start, end) = ((*range.start() - 1) as usize, (*range.end() - 1) as usize);
        let messages_range = &messages[start..=end];

        // Save the message indices in a hashmap for faster lookup
        let message_indices: std::collections::HashMap<_, _> = messages
            .iter()
            .enumerate()
            .map(|(idx, msg)| (msg, idx))
            .collect();

        for message in messages_range {
            let index = message_indices[&message];
            let contents = self.fetch_message(message).await.unwrap();
            let slices = parts[4..]
                .iter()
                .filter_map(|s| {
                    let trimmed = s.trim_matches(['(', ')']);
                    match trimmed {
                        "FLAGS" => Some("FLAGS (\\Unseen)".to_string()),
                        "RFC822.SIZE" => Some(format!("RFC822.SIZE {}", message.len())),
                        "BODY.PEEK[HEADER.FIELDS" => Some(format!(
                            "BODY[HEADER.FIELDS (To From Subject)] {{{}}}\r\n{}",
                            contents.len(),
                            contents
                        )),
                        "BODY[]" => Some(format!("BODY[] {{{}}}\r\n{}", contents.len(), contents)),
                        _ => None,
                    }
                })
                .collect::<Vec<String>>()
                .join(" ");
            self.write_response(
                writer,
                "*",
                &(index + 1).to_string(),
                format!("FETCH (UID {} {})", index + 1, slices).as_str(),
            )
            .await?;
        }
        self.write_response(writer, tag, "OK", "UID FETCH completed")
            .await?;
        Ok(())
    }

    async fn handle_capability<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.write_response(writer, "*", "CAPABILITY", "IMAP4rev1 AUTH=PLAIN")
            .await?;
        self.write_response(writer, tag, "OK", "CAPABILITY completed")
            .await?;
        Ok(())
    }

    async fn handle_noop<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.write_response(writer, tag, "OK", "NOOP completed")
            .await?;
        Ok(())
    }

    async fn search_messages(&self, _criteria: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let messages = self
            .storage_engine
            .list(self.safe_username())
            .await
            .map_err(|error| format!("Failed to list messages: {error}"))?;
        Ok(messages)
    }

    async fn fetch_message(&self, message_id: &str) -> Result<String, Box<dyn Error>> {
        let content = self
            .storage_engine
            .retrieve(self.safe_username(), message_id)
            .await
            .map_err(|error| format!("Failed to fetch message: {error}"))?;
        Ok(content)
    }

    async fn write_raw<W: AsyncWrite + Unpin>(&self, writer: &mut W, data: &str) {
        debug!(bytes = data.len(), ">> [DATA]");
        writer.write_all(data.as_bytes()).await.ok();
    }

    async fn write_inner<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        tag: &str,
        result: &str,
        message: &str,
    ) {
        writer
            .write_all(format!("{tag} {result} {message}\r\n").as_bytes())
            .await
            .ok();
    }

    async fn write_response<W: AsyncWrite + Unpin>(
        &self,
        w: &mut W,
        tag: &str,
        result: &str,
        message: &str,
    ) -> Result<(), Box<dyn Error>> {
        debug!(">> {tag} {result} {message}");
        self.write_inner(w, tag, result, message).await;
        Ok(())
    }

    fn safe_username(&self) -> &str {
        self.safe_username.as_deref().unwrap_or("")
    }
}

/// The main entry point of the Mailsis IMAP server.
///
/// It initializes the server, listens for incoming connections,
/// and spawns a new task to handle each client.
#[tokio::main]
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

    let crate_root = get_crate_root().unwrap_or_else(|_| PathBuf::from("."));
    let host = std::env::var("HOST").unwrap_or_else(|_| HOST.to_string());
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| PORT.to_string())
        .parse()
        .unwrap();
    let listening = format!("{host}:{port}");
    let listener = TcpListener::bind(&listening).await.map_err(|error| {
        error!(address = %listening, error = %error, "Failed to bind TCP listener");
        error
    })?;

    let auth_engine = Arc::new(load_credentials("passwords/example.txt").map_err(|error| {
        error!(error = %error, "Failed to load credentials");
        error
    })?);
    let storage_engine = Arc::new(FileStorageEngine::new(crate_root.join("mailbox")));

    info!(address = %listening, "Mailsis-IMAP started");

    loop {
        let (stream, _) = listener.accept().await.map_err(|error| {
            error!(error = %error, "Failed to accept connection");
            error
        })?;
        let auth_engine = auth_engine.clone();
        let storage_engine = storage_engine.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_client(stream, auth_engine, storage_engine).await {
                error!(error = %error, "IMAP session failed");
            }
        });
    }
}

async fn handle_client<A: AuthEngine + 'static, S: StorageEngine + 'static>(
    stream: TcpStream,
    auth_engine: Arc<A>,
    storage_engine: Arc<S>,
) -> Result<(), Box<dyn Error>> {
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    let mut session = IMAPSession::new(auth_engine, storage_engine);

    session
        .write_response(&mut w, "*", "OK", "Mailsis IMAP ready")
        .await?;

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }

        let raw = line.trim_end();
        debug!("<< {raw}");

        let parts: Vec<&str> = raw.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let tag = parts[0].to_string();
        let command = parts[1].to_uppercase();

        session
            .handle_command(&mut reader, &mut w, &tag, &command, &parts)
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
