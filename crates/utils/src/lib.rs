use std::path::Path;

use rand::Rng;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

pub async fn read_large_file(path: impl AsRef<Path>) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path).await?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await?;
    Ok(buffer)
}

pub async fn generate_random_file(
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

pub async fn generate_random_bytes(size: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; size];
    rng.fill(&mut bytes[..]);
    Ok(bytes)
}
