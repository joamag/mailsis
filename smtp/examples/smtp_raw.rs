use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use std::{env::args, error::Error, path::Path};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

const FILE_SIZE: usize = 100 * 1024 * 1024;
const CHUNK_SIZE: usize = 16384;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect("127.0.0.1:2525").await?;
    stream.set_nodelay(true)?;

    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    // Read server greeting
    let mut response = String::new();
    reader.read_line(&mut response).await?;
    println!("Server: {}", response.trim());

    // Send EHLO command
    writer.write_all(b"EHLO localhost\r\n").await?;
    response.clear();
    reader.read_line(&mut response).await?;
    println!("Server: {}", response.trim());

    // Read additional EHLO response lines
    while response.starts_with("250-") {
        response.clear();
        reader.read_line(&mut response).await?;
        println!("Server: {}", response.trim());
    }

    // Send MAIL FROM command
    writer
        .write_all(b"MAIL FROM:<sender@example.com>\r\n")
        .await?;
    response.clear();
    reader.read_line(&mut response).await?;
    println!("Server: {}", response.trim());

    // Send RCPT TO command
    writer
        .write_all(b"RCPT TO:<recipient@example.com>\r\n")
        .await?;
    response.clear();
    reader.read_line(&mut response).await?;
    println!("Server: {}", response.trim());

    // Send DATA command
    writer.write_all(b"DATA\r\n").await?;
    response.clear();
    reader.read_line(&mut response).await?;
    println!("Server: {}", response.trim());

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
        let mut rng = rand::thread_rng();
        let chunk = (0..128).map(|_| rng.gen()).collect::<Vec<u8>>();
        let num_chunks = FILE_SIZE / 128;
        let mut file_data = Vec::with_capacity(FILE_SIZE);
        for _ in 0..num_chunks {
            file_data.extend_from_slice(&chunk);
        }
        file_data.extend((0..FILE_SIZE % 128).map(|_| rng.gen::<u8>()));
        (file_data, "random.bin".to_string())
    };

    println!("Encoding data...");
    let encoded_data = general_purpose::STANDARD.encode(&file_data);

    // Send email headers
    let headers = format!(
        "MIME-Version: 1.0\r\n\
                  From: sender@example.com\r\n\
                  To: recipient@example.com\r\n\
                  Subject: Test Email with Large Attachment\r\n\
                  Content-Type: multipart/mixed; boundary=boundary123\r\n\
                  \r\n\
                  \r\n\
                  --boundary123\r\n\
                  Content-Type: text/plain\r\n\
                  \r\n\
                  This is a test email with a large attachment.\r\n\
                  \r\n\
                  --boundary123\r\n\
                  Content-Type: application/octet-stream\r\n\
                  Content-Transfer-Encoding: base64\r\n\
                  Content-Disposition: attachment; filename=\"{}\"\r\n\
                  \r\n",
        filename
    );

    writer.write_all(headers.as_bytes()).await?;

    println!("Sending data...");
    let send_start = std::time::Instant::now();
    for chunk in encoded_data.as_bytes().chunks(CHUNK_SIZE) {
        writer.write_all(chunk).await?;
        writer.write_all(b"\r\n").await?;
    }
    println!("Data sent in {:?}", send_start.elapsed());

    // Send the final boundary and end of message
    writer.write_all(b"\r\n--boundary123--\r\n.\r\n").await?;
    response.clear();
    reader.read_line(&mut response).await?;
    println!("Server: {}", response.trim());

    // Send QUIT command
    writer.write_all(b"QUIT\r\n").await?;
    response.clear();
    reader.read_line(&mut response).await?;
    println!("Server: {}", response.trim());

    Ok(())
}
