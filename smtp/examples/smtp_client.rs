use std::{error::Error, path::PathBuf, str::FromStr, time::Instant};

use lettre::{
    message::{header, Message, MultiPart},
    transport::smtp::client::{Certificate, Tls, TlsParameters},
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};
use mailsis_utils::{generate_random_file, get_crate_root, read_large_file};
use tokio::fs::remove_file;

/// Size of the random file in MB
const FILE_SIZE_MB: usize = 100;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let start_time = Instant::now();

    // Generate random file
    println!("Generating random file of {FILE_SIZE_MB} MB...");
    let file_path = "random_data.bin";
    generate_random_file(file_path, FILE_SIZE_MB).await?;
    println!("File generated in {:?}", start_time.elapsed());

    // SMTP server configuration
    let smtp_server = "localhost";
    let smtp_port = 2525;

    println!("Connecting to SMTP server...");
    let connect_start = Instant::now();

    let crate_root = get_crate_root().unwrap_or(PathBuf::from_str(".")?);
    let ca_path = crate_root.join("certs").join("ca.cert.pem");
    let ca_cert = read_large_file(ca_path.to_str().unwrap()).await?;

    let tls_parameters = TlsParameters::builder(smtp_server.to_string())
        .add_root_certificate(Certificate::from_pem(&ca_cert)?)
        .build()?;

    let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(smtp_server)
        .port(smtp_port)
        .tls(Tls::Required(tls_parameters))
        .build();

    println!(
        "SMTP connection established in {:?}",
        connect_start.elapsed()
    );

    println!("Preparing email message...");
    let email_start = Instant::now();

    // Create email message
    let email = Message::builder()
        .from("Test User <sender@localhost>".parse()?)
        .to("Recipient <recipient@localhost>".parse()?)
        .subject("Large File Test")
        .multipart(
            MultiPart::mixed()
                .singlepart(
                    lettre::message::SinglePart::builder()
                        .header(header::ContentType::TEXT_PLAIN)
                        .body(format!(
                            "This is a test email with a {FILE_SIZE_MB} MB file attachment."
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

    remove_file(file_path).await?;

    Ok(())
}
