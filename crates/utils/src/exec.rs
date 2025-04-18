use std::{env, error::Error, path::PathBuf};

/// Returns the root directory of the crate, using the current executable path
/// as reference.
///
/// It works by going up the directory tree until it finds a directory that
/// ends with "target", which is not the case for the root directory.
pub fn get_crate_root() -> Result<PathBuf, Box<dyn Error>> {
    let exe_path = env::current_exe().expect("Failed to get executable path");
    let mut crate_root = exe_path
        .parent()
        .ok_or("Failed to get parent directory")?
        .parent()
        .ok_or("Failed to get crate root directory")?
        .to_path_buf();

    loop {
        let is_final = crate_root.ends_with("target");
        crate_root = crate_root
            .parent()
            .ok_or("Failed to get crate root directory")?
            .to_path_buf();
        if is_final {
            break;
        }
    }

    Ok(crate_root)
}
