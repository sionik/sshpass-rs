use anyhow::Context;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

const RETURN_INCORRECT_PASSWORD: i32 = 5;
const RETURN_HOST_KEY_UNKNOWN: i32 = 6;
const RETURN_HOST_KEY_CHANGED: i32 = 7;

pub struct RunConfig {
    pub command: Vec<String>,
    pub password: String,
    pub prompt: String,
}

/// Entry point when running as the SSH_ASKPASS helper.
///
/// SSH invokes us with the prompt text as argv[1]. We read the password
/// from a file in `SSHPASS_STATE_DIR`,
/// then decide whether to provide the password or signal an error.
pub fn askpass_main() -> ! {
    let state_dir = std::env::var("SSHPASS_STATE_DIR").unwrap_or_default();
    let expected_prompt = std::env::var("SSHPASS_PROMPT").unwrap_or_default();
    let prompt = std::env::args().nth(1).unwrap_or_default();

    let state_dir = PathBuf::from(state_dir);
    let password_file = state_dir.join("password");
    let password_sent_file = state_dir.join("password_sent");
    let exit_code_file = state_dir.join("exit_code");

    let password = fs::read_to_string(password_file).unwrap_or_default();

    // Host key confirmation prompt
    if prompt.contains("yes/no") || prompt.contains("fingerprint") {
        let _ = fs::write(&exit_code_file, RETURN_HOST_KEY_UNKNOWN.to_string());
        std::process::exit(1);
    }

    // Second password prompt means first password was wrong
    if password_sent_file.exists() {
        let _ = fs::write(&exit_code_file, RETURN_INCORRECT_PASSWORD.to_string());
        std::process::exit(1);
    }

    // Default case: unknown prompt, or user/password not matching expected
    if !prompt.contains(&expected_prompt) {
        let _ = fs::write(&exit_code_file, "1");
        std::process::exit(1);
    }

    // First password prompt: provide the password
    let _ = fs::write(&password_sent_file, "");
    println!("{password}");
    std::process::exit(0);
}

/// Run the ssh command using SSH_ASKPASS for password injection.
pub fn run(config: RunConfig) -> anyhow::Result<i32> {
    let state_dir = tempfile::tempdir().context("failed to create state directory")?;
    let state_path = state_dir.path();

    let password_file = state_path.join("password");
    fs::write(&password_file, &config.password)
        .context("failed to write password to state file")?;

    let self_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("sshpass-rs"));

    let mut child = Command::new(&config.command[0])
        .args(&config.command[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .env("SSH_ASKPASS", &self_exe)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env(
            "DISPLAY",
            std::env::var("DISPLAY").unwrap_or_else(|_| ":0".into()),
        )
        .env("SSHPASS_ASKPASS_MODE", "1")
        .env("SSHPASS_STATE_DIR", state_path)
        .env("SSHPASS_PROMPT", &config.prompt)
        .spawn()
        .context("failed to spawn command")?;

    // Forward stderr, scanning the first 20 lines for host key changed warning.
    // SSH prints this at connection time, well before any session output.
    let stderr_pipe = child.stderr.take();
    let host_key_changed = Arc::new(AtomicBool::new(false));
    let hkc_flag = Arc::clone(&host_key_changed);
    let state_path_copy = state_path.to_path_buf();

    let stderr_handle = thread::spawn(move || {
        let Some(pipe) = stderr_pipe else { return };
        let mut reader = BufReader::new(pipe);
        let mut stderr_out = std::io::stderr();
        let needle = b"differs from the key for the IP address";

        let password_sent = state_path_copy.join("password_sent");
        let mut line = Vec::new();

        // Process lines continuously until authentication starts (password_sent exists),
        // or up to a maximum number of lines, then switch to fast std::io::copy.
        for _ in 0..20 {
            line.clear();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) => return, // EOF
                Ok(_) => {
                    if line.windows(needle.len()).any(|w| w == needle) {
                        hkc_flag.store(true, Ordering::Relaxed);
                    }
                    let _ = stderr_out.write_all(&line);
                    let _ = stderr_out.flush();

                    // Once ASKPASS is involved, host key phase is definitely done
                    if password_sent.exists() {
                        break;
                    }
                }
                Err(_) => return,
            }
        }

        // After initial lines or after password sent, just forward without scanning
        let _ = std::io::copy(&mut reader, &mut stderr_out);
    });

    let status = child.wait().context("failed to wait for command")?;
    let _ = stderr_handle.join();

    if host_key_changed.load(Ordering::Relaxed) {
        return Ok(RETURN_HOST_KEY_CHANGED);
    }

    // Check state directory for askpass-reported exit codes
    if let Some(code) = read_exit_code(state_path) {
        return Ok(code);
    }

    // Otherwise use the child's exit code
    Ok(status.code().unwrap_or(255))
}

fn read_exit_code(state_dir: &Path) -> Option<i32> {
    let path = state_dir.join("exit_code");
    fs::read_to_string(path).ok()?.trim().parse().ok()
}
