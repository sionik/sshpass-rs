use anyhow::Context;
use std::fs;
use std::io::{self, BufRead};
use std::path::PathBuf;

#[derive(Debug)]
pub enum PasswordSource {
    Stdin,
    File(PathBuf),
    #[cfg(unix)]
    Fd(i32),
    Direct(String),
    Env(String),
}

pub fn resolve_password(source: &PasswordSource) -> anyhow::Result<String> {
    match source {
        PasswordSource::Direct(pw) => Ok(pw.clone()),
        PasswordSource::Env(var) => {
            let pw = std::env::var(var)
                .map_err(|_| anyhow::anyhow!("environment variable \"{var}\" is not set"))?;
            // SAFETY: We remove the environment variable here to prevent child processes
            //         from inheriting it. This is safe because this app is strictly
            //         single-threaded at this point and no other threads access the environment.
            unsafe { std::env::remove_var(var) };
            Ok(pw)
        }
        PasswordSource::File(path) => {
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read password file \"{}\"", path.display()))?;
            Ok(first_line(&content))
        }
        PasswordSource::Stdin => {
            let mut line = String::new();
            io::stdin()
                .lock()
                .read_line(&mut line)
                .context("failed to read password from stdin")?;
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
fn read_from_fd(fd: i32) -> anyhow::Result<String> {
    use std::os::unix::io::FromRawFd;

    let file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    let mut reader = io::BufReader::new(&*file);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .with_context(|| format!("failed to read password from fd {fd}"))?;
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
        // SAFETY: This test runs in isolation; no other threads access this env var.
        unsafe { std::env::set_var("SSHPASS_TEST_VAR", "envpass") };
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
