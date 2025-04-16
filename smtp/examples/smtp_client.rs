use lettre::{
    message::{header, Message, MultiPart},
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};
use rand::Rng;
use std::path::Path;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::{fs::File, io::AsyncWriteExt};

/// Size of the random file in MB
const FILE_SIZE_MB: usize = 100;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    // Generate random file
    println!("Generating random file of {} MB...", FILE_SIZE_MB);
    let file_path = "random_data.bin";
    generate_random_file(file_path, FILE_SIZE_MB).await?;
    println!("File generated in {:?}", start_time.elapsed());

    // SMTP server configuration
    let smtp_server = "localhost";
    let smtp_port = 2525;

    println!("Connecting to SMTP server...");
    let connect_start = Instant::now();

    let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(smtp_server)
        .port(smtp_port)
        //.tls(Tls::Required(tls_parameters))
        //.credentials(creds)
        .build();

    println!(
        "SMTP connection established in {:?}",
        connect_start.elapsed()
    );

    println!("Preparing email message...");
    let email_start = Instant::now();

    // Create email message
    let email = Message::builder()
        .from("Test User <test@example.com>".parse()?)
        .to("Recipient <recipient@example.com>".parse()?)
        .subject("Large File Test")
        .multipart(
            MultiPart::mixed()
                .singlepart(
                    lettre::message::SinglePart::builder()
                        .header(header::ContentType::TEXT_PLAIN)
                        .body(format!(
                            "This is a test email with a {} MB file attachment.",
                            FILE_SIZE_MB
                        )),
                )
                .singlepart(
                    lettre::message::SinglePart::builder()
                        .header(header::ContentType::parse("application/octet-stream")?)
                        .header(header::ContentDisposition::attachment("random_data.bin"))
                        .body(read_large_file(file_path).await?),
                ),
        )?;

    println!("Email prepared in {:?}", email_start.elapsed());

    println!("Sending email...");
    let send_start = Instant::now();
    transport.send(email).await?;
    println!("Email sent successfully in {:?}", send_start.elapsed());
    println!("Total time: {:?}", start_time.elapsed());

    tokio::fs::remove_file(file_path).await?;

    Ok(())
}

async fn read_large_file(path: impl AsRef<Path>) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path).await?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await?;
    Ok(buffer)
}

async fn generate_random_file(
    path: impl AsRef<Path>,
    size_mb: usize,
) -> Result<(), std::io::Error> {
    let mut file = File::create(path).await?;
    let mut rng = rand::thread_rng();
    let chunk_size = 1024 * 1024;
    let total_chunks = size_mb;

    for _ in 0..total_chunks {
        let mut chunk = vec![0u8; chunk_size];
        rng.fill(&mut chunk[..]);
        AsyncWriteExt::write_all(&mut file, &chunk).await?;
    }

    Ok(())
}
