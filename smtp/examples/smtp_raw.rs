use base64::{engine::general_purpose, Engine as _};
use mailsis_utils::{generate_random_bytes, load_tls_client_config};
use std::{env::args, error::Error, path::Path, sync::Arc};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_rustls::{rustls::pki_types::ServerName, TlsConnector, TlsStream};
use uuid::Uuid;

/// Size of the random file in bytes
const RANDOM_FILE_SIZE: usize = 100 * 1024 * 1024;

/// Size of the chunks to send in bytes
const CHUNK_SIZE: usize = 16384;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect("127.0.0.1:2525").await?;
    stream.set_nodelay(true)?;

    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let mut response = String::new();

    // Read server greeting
    read_response(&mut reader, &mut response).await?;

    // Send EHLO command
    write_command(&mut writer, "EHLO localhost").await?;
    read_response(&mut reader, &mut response).await?;

    // Read additional EHLO response lines
    while response.starts_with("250-") {
        read_response(&mut reader, &mut response).await?;
    }

    // Upgrade to TLS
    write_command(&mut writer, "STARTTLS").await?;
    read_response(&mut reader, &mut response).await?;

    let tls_stream = upgrade_to_tls(stream, "localhost").await?;
    let (reader_ssl, writer_ssl) = tokio::io::split(tls_stream);
    let mut reader = BufReader::new(reader_ssl);
    let mut writer = writer_ssl;

    // Send MAIL FROM command
    write_command(&mut writer, "MAIL FROM:<sender@example.com>").await?;
    read_response(&mut reader, &mut response).await?;

    // Send RCPT TO command
    write_command(&mut writer, "RCPT TO:<recipient@example.com>").await?;
    read_response(&mut reader, &mut response).await?;

    // Send DATA command
    write_command(&mut writer, "DATA").await?;
    read_response(&mut reader, &mut response).await?;

    let (file_data, filename) = if args().len() > 1 {
        let path = args().nth(1).unwrap();
        println!("Reading file from {}", path);
        let filename = Path::new(&path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        (tokio::fs::read(&path).await?, filename)
    } else {
        println!("Generating random data...");
        let file_data = generate_random_bytes(RANDOM_FILE_SIZE).await?;
        (file_data, "random.bin".to_string())
    };

    println!("Encoding data...");
    let encoded_data = general_purpose::STANDARD.encode(&file_data);

    // Send email headers
    let boundary = format!("boundary-{}", Uuid::new_v4());
    write_data(
        &mut writer,
        &format!(
            "MIME-Version: 1.0\r\n\
                  From: sender@example.com\r\n\
                  To: recipient@example.com\r\n\
                  Subject: Test Email with Large Attachment\r\n\
                  Content-Type: multipart/mixed; boundary=\"{}\"\r\n\
                  \r\n\
                  \r\n\
                  --{}\r\n\
                  Content-Type: text/plain\r\n\
                  \r\n\
                  This is a test email with a large attachment.\r\n\
                  \r\n\
                  --{}\r\n\
                  Content-Type: application/octet-stream\r\n\
                  Content-Transfer-Encoding: base64\r\n\
                  Content-Disposition: attachment; filename=\"{}\"\r\n\
                  \r\n",
            boundary, boundary, boundary, filename
        ),
    )
    .await?;

    println!("Sending data...");
    let send_start = std::time::Instant::now();
    for chunk in encoded_data.as_bytes().chunks(CHUNK_SIZE) {
        writer.write_all(chunk).await?;
        writer.write_all(b"\r\n").await?;
    }
    println!("Data sent in {:?}", send_start.elapsed());

    // Send the final boundary and end of message
    writer.write_all(b"\r\n--boundary123--\r\n.\r\n").await?;
    read_response(&mut reader, &mut response).await?;

    // Send QUIT command
    write_command(&mut writer, "QUIT").await?;
    read_response(&mut reader, &mut response).await?;

    Ok(())
}

async fn write_command<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &str,
) -> Result<(), Box<dyn Error>> {
    println!("[Client] > {}", message);
    writer
        .write_all(format!("{}\r\n", message).as_bytes())
        .await?;
    Ok(())
}

async fn write_data<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &str,
) -> Result<(), Box<dyn Error>> {
    writer.write_all(message.as_bytes()).await?;
    Ok(())
}

async fn read_response<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    response: &mut String,
) -> Result<(), Box<dyn Error>> {
    response.clear();
    reader.read_line(response).await?;
    println!("[Server] > {}", response.trim());
    Ok(())
}

async fn upgrade_to_tls(
    plain_stream: TcpStream,
    domain: &str,
) -> Result<TlsStream<TcpStream>, Box<dyn std::error::Error>> {
    let config = load_tls_client_config()?;

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(domain)?.to_owned();

    let tls_stream = TlsStream::Client(connector.connect(server_name, plain_stream).await?);

    Ok(tls_stream)
}
