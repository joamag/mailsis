use std::{collections::HashMap, error::Error};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

#[derive(Debug, Clone)]
struct Message {
    content: String,
    flags: Vec<String>,
}

#[derive(Debug)]
struct Mailbox {
    messages: HashMap<u32, Message>,
    next_uid: u32,
}

impl Mailbox {
    fn new() -> Self {
        Self {
            messages: HashMap::new(),
            next_uid: 1,
        }
    }

    fn add_message(&mut self, content: String) -> u32 {
        let uid = self.next_uid;
        self.messages.insert(
            uid,
            Message {
                content,
                flags: vec!["\\Recent".to_string()],
            },
        );
        self.next_uid += 1;
        uid
    }
}

struct IMAPSession {
    authenticated: bool,
    auth_required: bool,
    mailboxes: Option<Mailbox>,
}

impl Default for IMAPSession {
    fn default() -> Self {
        Self {
            authenticated: false,
            auth_required: false,
            mailboxes: None,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:1430").await?;
    println!("IMAP server listening on 1430");

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                eprintln!("Error: {e}");
            }
        });
    }
}

async fn handle_client(stream: TcpStream) -> anyhow::Result<()> {
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut line = String::new();

    let mut authenticated = false;
    let mut selected_mailbox: Option<Mailbox> = None;
    let mut tag = "*".to_string();

    w.write_all(b"* OK Mailsis IMAP ready\r\n").await?;

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }

        let raw = line.trim_end();
        println!(">> {raw}");

        let parts: Vec<&str> = raw.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        tag = parts[0].to_string();
        let command = parts[1].to_uppercase();

        match command.as_str() {
            "LOGIN" => {
                if parts.len() >= 4 {
                    authenticated = true;
                    w.write_all(format!("{} OK LOGIN completed\r\n", tag).as_bytes())
                        .await?;
                } else {
                    w.write_all(format!("{} BAD Invalid login\r\n", tag).as_bytes())
                        .await?;
                }
            }
            "LIST" => {
                w.write_all(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n")
                    .await?;
                w.write_all(format!("{} OK LIST completed\r\n", tag).as_bytes())
                    .await?;
            }
            "SELECT" => {
                if let Some(mbox) = parts.get(2) {
                    if mbox.to_uppercase() == "INBOX" {
                        selected_mailbox = Some(Mailbox::new());
                        let count = selected_mailbox.as_ref().unwrap().messages.len();
                        w.write_all(format!("* {count} EXISTS\r\n").as_bytes())
                            .await?;
                        w.write_all(b"* OK [UIDVALIDITY 1] UIDs valid\r\n").await?;
                        w.write_all(format!("{} OK SELECT completed\r\n", tag).as_bytes())
                            .await?;
                    } else {
                        w.write_all(format!("{} NO Mailbox does not exist\r\n", tag).as_bytes())
                            .await?;
                    }
                } else {
                    w.write_all(format!("{} BAD Missing mailbox name\r\n", tag).as_bytes())
                        .await?;
                }
            }
            "FETCH" => {
                if let Some(mailbox) = &selected_mailbox {
                    if let Ok(seq) = parts[2].parse::<u32>() {
                        if let Some(msg) = mailbox.messages.get(&seq) {
                            w.write_all(
                                format!("* {seq} FETCH (FLAGS ({}))\r\n", msg.flags.join(" "))
                                    .as_bytes(),
                            )
                            .await?;
                            w.write_all(format!("{} OK FETCH completed\r\n", tag).as_bytes())
                                .await?;
                        } else {
                            w.write_all(format!("{} NO No such message\r\n", tag).as_bytes())
                                .await?;
                        }
                    } else {
                        w.write_all(format!("{} BAD Invalid message number\r\n", tag).as_bytes())
                            .await?;
                    }
                } else {
                    w.write_all(format!("{} NO No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                }
            }
            "STORE" => {
                if let Some(mailbox) = &mut selected_mailbox {
                    if parts.len() >= 5 {
                        if let Ok(seq) = parts[2].parse::<u32>() {
                            if let Some(msg) = mailbox.messages.get_mut(&seq) {
                                let mode = parts[3];
                                let flags: Vec<String> = parts[4..]
                                    .join(" ")
                                    .replace(['(', ')'], "")
                                    .split_whitespace()
                                    .map(|s| s.to_string())
                                    .collect();

                                match mode {
                                    "+FLAGS" => msg.flags.extend(flags),
                                    "-FLAGS" => msg.flags.retain(|f| !flags.contains(f)),
                                    "FLAGS" => msg.flags = flags,
                                    _ => {}
                                }
                                w.write_all(
                                    format!("* {seq} FETCH (FLAGS ({}))\r\n", msg.flags.join(" "))
                                        .as_bytes(),
                                )
                                .await?;
                                w.write_all(format!("{} OK STORE completed\r\n", tag).as_bytes())
                                    .await?;
                            } else {
                                w.write_all(format!("{} NO No such message\r\n", tag).as_bytes())
                                    .await?;
                            }
                        } else {
                            w.write_all(
                                format!("{} BAD Invalid message number\r\n", tag).as_bytes(),
                            )
                            .await?;
                        }
                    } else {
                        w.write_all(format!("{} BAD STORE syntax\r\n", tag).as_bytes())
                            .await?;
                    }
                } else {
                    w.write_all(format!("{} NO No mailbox selected\r\n", tag).as_bytes())
                        .await?;
                }
            }
            "LOGOUT" => {
                w.write_all(b"* BYE Logging out\r\n").await?;
                w.write_all(format!("{} OK LOGOUT completed\r\n", tag).as_bytes())
                    .await?;
                break;
            }
            _ => {
                w.write_all(format!("{} BAD Unknown command\r\n", tag).as_bytes())
                    .await?;
            }
        }
    }

    Ok(())
}
