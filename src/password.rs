use std::fs;
use std::io::{self, BufRead};
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("failed to open password file \"{path}\": {source}")]
    FileOpen { path: PathBuf, source: io::Error },
    #[error("environment variable \"{var}\" is not set")]
    EnvNotSet { var: String },
    #[error("failed to read password from stdin: {0}")]
    StdinRead(io::Error),
    #[cfg(unix)]
    #[error("failed to read password from fd {fd}: {source}")]
    FdRead { fd: i32, source: io::Error },
}

#[derive(Debug)]
pub enum PasswordSource {
    Stdin,
    File(PathBuf),
    #[cfg(unix)]
    Fd(i32),
    Direct(String),
    Env(String),
}

pub fn resolve_password(source: &PasswordSource) -> Result<String, PasswordError> {
    match source {
        PasswordSource::Direct(pw) => Ok(pw.clone()),
        PasswordSource::Env(var) => {
            let pw =
                std::env::var(var).map_err(|_| PasswordError::EnvNotSet { var: var.clone() })?;
            // SAFETY: We are single-threaded at this point
            unsafe { std::env::remove_var(var) };
            Ok(pw)
        }
        PasswordSource::File(path) => {
            let content = fs::read_to_string(path).map_err(|e| PasswordError::FileOpen {
                path: path.clone(),
                source: e,
            })?;
            Ok(first_line(&content))
        }
        PasswordSource::Stdin => {
            let mut line = String::new();
            io::stdin()
                .lock()
                .read_line(&mut line)
                .map_err(PasswordError::StdinRead)?;
            Ok(first_line(&line))
        }
        #[cfg(unix)]
        PasswordSource::Fd(fd) => read_from_fd(*fd),
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
}

#[cfg(unix)]
fn read_from_fd(fd: i32) -> Result<String, PasswordError> {
    use std::os::unix::io::FromRawFd;

    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut reader = io::BufReader::new(&file);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| PasswordError::FdRead { fd, source: e })?;
    std::mem::forget(file);
    Ok(first_line(&line))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn direct_password() {
        let source = PasswordSource::Direct("secret".into());
        assert_eq!(resolve_password(&source).unwrap(), "secret");
    }

    #[test]
    fn env_password() {
        std::env::set_var("SSHPASS_TEST_VAR", "envpass");
        let source = PasswordSource::Env("SSHPASS_TEST_VAR".into());
        assert_eq!(resolve_password(&source).unwrap(), "envpass");
        assert!(std::env::var("SSHPASS_TEST_VAR").is_err());
    }

    #[test]
    fn env_not_set() {
        let source = PasswordSource::Env("NONEXISTENT_VAR_12345".into());
        assert!(resolve_password(&source).is_err());
    }

    #[test]
    fn file_password() {
        let dir = std::env::temp_dir().join("sshpass_test_pw");
        let mut f = std::fs::File::create(&dir).unwrap();
        writeln!(f, "filepass").unwrap();
        writeln!(f, "second line").unwrap();
        drop(f);

        let source = PasswordSource::File(dir.clone());
        assert_eq!(resolve_password(&source).unwrap(), "filepass");
        std::fs::remove_file(dir).unwrap();
    }

    #[test]
    fn file_not_found() {
        let source = PasswordSource::File("/nonexistent/path/pw.txt".into());
        assert!(resolve_password(&source).is_err());
    }

    #[test]
    fn file_empty() {
        let dir = std::env::temp_dir().join("sshpass_test_empty");
        std::fs::write(&dir, "").unwrap();

        let source = PasswordSource::File(dir.clone());
        assert_eq!(resolve_password(&source).unwrap(), "");
        std::fs::remove_file(dir).unwrap();
    }
}
