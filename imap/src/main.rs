use std::error::Error;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

const HOST: &str = "127.0.0.1";
const PORT: u16 = 1430;

struct IMAPSession {
    authenticated: bool,
    mailbox: Option<String>,
}

impl Default for IMAPSession {
    fn default() -> Self {
        Self {
            authenticated: false,
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
            "SELECT" | "EXAMINE" => self.handle_select(writer, tag, parts).await,
            "CAPABILITY" => self.handle_capability(writer, tag).await,
            _ => {
                self.write_response(writer, tag, "BAD", "Unknown command")
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
        self.write_response(writer, tag, "OK", "LOGOUT completed")
            .await?;
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
            self.write_response(writer, tag, "OK", "SELECT completed")
                .await?;
        } else {
            self.write_response(writer, tag, "BAD", "Invalid mailbox name")
                .await?;
        }
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
