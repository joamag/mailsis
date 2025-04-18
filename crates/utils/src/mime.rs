/// Checks if the email is a valid MIME email.
///
/// A valid MIME email contains a "MIME-Version:" header in the headers section.
pub async fn is_mime_valid(body: &str) -> bool {
    for line in body.lines() {
        if line.trim().is_empty() {
            break;
        }
        if line.trim().starts_with("MIME-Version:") {
            return true;
        }
    }
    false
}
