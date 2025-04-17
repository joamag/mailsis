/// Checks if the email is a valid MIME email.
///
/// A valid MIME email starts with a line that contains "MIME-Version:".
pub async fn is_mime_valid(body: &str) -> bool {
    let mut lines = body.lines();
    let first_line = lines.next().unwrap_or("");
    let mime_type = first_line.split_whitespace().next().unwrap_or("");
    mime_type == "MIME-Version:"
}
