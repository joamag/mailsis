use mailsis_utils::{get_crate_root, uid_fetch_range_str};
use std::{error::Error, path::PathBuf, str::FromStr};
use tokio::{
    fs::{create_dir_all, read_dir, read_to_string},
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

const HOST: &str = "127.0.0.1";
const PORT: u16 = 1430;

struct IMAPSession {
    authenticated: bool,
    username: Option<String>,
    mailbox: Option<String>,
}

impl Default for IMAPSession {
    fn default() -> Self {
        Self {
            authenticated: false,
            username: None,
            mailbox: None,
        }
    }
}

impl IMAPSession {
    async fn handle_command<R: AsyncRead + AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        &mut self,
        reader: &mut R,
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
                    format!("Unknown command ({})", command).as_str(),
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
            self.authenticated = true;
            self.username = Some(parts[2].to_string().trim_matches('"').to_string());
            self.write_response(writer, tag, "OK", "LOGIN completed")
                .await?;
        } else {
            self.write_response(writer, tag, "BAD", "Invalid login")
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
            self.mailbox = Some(parts[1].to_string());
            let messages = self.search_messages("").await?;
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
            let message_id = parts[2].to_string();
            let message_sequence = 1;
            let format = parts[3].to_string();
            let format_inner = format[1..format.len() - 1].to_string();
            let message = self.fetch_message(&message_id).await?;
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
            let path = self.mailbox_path().join(format!("{}.mbox", mailbox));
            create_dir_all(path).await?;
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
                    &format!("Invalid UID command {}", uid_command),
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
        let range = uid_fetch_range_str(&parts[3].to_string(), messages.len() as u32)
            .ok_or("Invalid range")?;
        let (start, end) = ((*range.start() - 1) as usize, (*range.end() - 1) as usize);
        let messages_range = messages[start..=end].to_vec();

        // Save the message indices in a hashmap for faster lookup
        let message_indices: std::collections::HashMap<_, _> = messages
            .iter()
            .enumerate()
            .map(|(idx, msg)| (msg, idx))
            .collect();

        for message in messages_range {
            let index = message_indices[&message];
            let contents = self.fetch_message(&message).await.unwrap();
            let slices = parts[4..parts.len()]
                .iter()
                .map(|p| {
                    let c = p.to_string();
                    let a = c.trim_matches('(').trim_matches(')');
                    match a {
                        "FLAGS" => return "FLAGS (\\Unseen)".to_string(),
                        "RFC822.SIZE" => return format!("RFC822.SIZE {}", message.len()),
                        "BODY.PEEK[HEADER.FIELDS" => {
                            return format!(
                                "BODY[HEADER.FIELDS (To From Subject)] {{{}}}\r\n{}",
                                contents.len(),
                                contents
                            )
                        }
                        "BODY[]" => {
                            return format!("BODY[] {{{}}}\r\n{}", contents.len(), contents)
                        }
                        _ => "".to_string(),
                    }
                })
                .collect::<Vec<String>>()
                .iter()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
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

    async fn search_messages(&self, criteria: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let mut messages = Vec::new();
        let mut entries = read_dir(&self.mailbox_path()).await?;

        while let Some(entry) = entries.next_entry().await? {
            let entry_path = entry.path();
            let path_str = entry_path.to_str().unwrap();
            if path_str.ends_with(".eml") {
                let file_stem = entry_path.file_stem().unwrap().to_str().unwrap();
                messages.push(file_stem.to_string());
            }
        }

        Ok(messages)
    }

    async fn fetch_message(&self, message_id: &str) -> Result<String, Box<dyn Error>> {
        let path = self.mailbox_path().join(format!("{}.eml", message_id));
        let content = read_to_string(path).await?;
        Ok(content)
    }

    async fn write_raw<W: AsyncWrite + Unpin>(&self, writer: &mut W, data: &str) {
        println!(">> [DATA] {} bytes", data.len());
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
            .write_all(format!("{} {} {}\r\n", tag, result, message).as_bytes())
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
        println!(">> {} {} {}", tag, result, message);
        self.write_inner(w, tag, result, message).await;
        Ok(())
    }

    fn mailbox_path(&self) -> PathBuf {
        let crate_root = get_crate_root().unwrap_or(PathBuf::from_str(".").unwrap());
        crate_root.join("mailbox").join(self.safe_username())
    }

    fn safe_username(&self) -> String {
        self.username
            .clone()
            .unwrap_or_default()
            .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listening = format!("{}:{}", HOST, PORT);
    let listener = TcpListener::bind(&listening).await?;

    println!("Mailsis-IMAP running on {}", &listening);

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                eprintln!("Error: {e}");
            }
        });
    }
}

async fn handle_client(stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    let mut session = IMAPSession::default();

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
        println!("<< {raw}");

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
