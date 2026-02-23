use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::thread;

use crate::matcher::Matcher;

const RETURN_INCORRECT_PASSWORD: i32 = 5;
const RETURN_HOST_KEY_UNKNOWN: i32 = 6;
const RETURN_HOST_KEY_CHANGED: i32 = 7;

#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    #[error("failed to open pseudo terminal: {0}")]
    OpenFailed(String),
    #[error("failed to spawn command: {0}")]
    SpawnFailed(String),
    #[error("failed to get pty reader: {0}")]
    ReaderFailed(String),
    #[error("failed to get pty writer: {0}")]
    WriterFailed(String),
}

pub struct RunConfig {
    pub command: Vec<String>,
    pub password: String,
    pub prompt: String,
    pub verbose: bool,
}

pub fn run(config: RunConfig) -> Result<i32, PtyError> {
    let pty_system = native_pty_system();

    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| PtyError::OpenFailed(e.to_string()))?;

    let mut cmd = CommandBuilder::new(&config.command[0]);
    for arg in &config.command[1..] {
        cmd.arg(arg);
    }

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| PtyError::SpawnFailed(e.to_string()))?;

    drop(pair.slave);

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| PtyError::ReaderFailed(e.to_string()))?;

    let writer = pair
        .master
        .take_writer()
        .map_err(|e| PtyError::WriterFailed(e.to_string()))?;

    let exit_code = Arc::new(AtomicI32::new(0));

    setup_signal_handler(&pair.master, &exit_code);

    let read_handle = {
        let password = config.password;
        let prompt = config.prompt;
        let verbose = config.verbose;
        let exit_code = Arc::clone(&exit_code);
        let mut writer = writer;

        thread::spawn(move || {
            let mut pw_matcher = Matcher::new(&prompt);
            let mut hk_matcher = Matcher::new("The authenticity of host ");
            let mut hkc_matcher = Matcher::new("differs from the key for the IP address");
            let mut password_sent = false;
            let mut buf = [0u8; 256];

            if verbose {
                eprintln!(
                    "SSHPASS: searching for password prompt using match \"{}\"",
                    prompt
                );
            }

            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = &buf[..n];
                        if verbose {
                            eprintln!(
                                "SSHPASS: read: {}",
                                String::from_utf8_lossy(data)
                            );
                        }

                        if pw_matcher.feed(data) {
                            if !password_sent {
                                if verbose {
                                    eprintln!(
                                        "SSHPASS: detected prompt. Sending password."
                                    );
                                }
                                let payload =
                                    format!("{}\n", password);
                                let _ = writer.write_all(payload.as_bytes());
                                let _ = writer.flush();
                                password_sent = true;
                                pw_matcher.reset();
                            } else {
                                if verbose {
                                    eprintln!("SSHPASS: detected prompt, again. Wrong password. Terminating.");
                                }
                                exit_code.store(
                                    RETURN_INCORRECT_PASSWORD,
                                    Ordering::SeqCst,
                                );
                                break;
                            }
                        }

                        if hk_matcher.feed(data) {
                            if verbose {
                                eprintln!("SSHPASS: detected host authentication prompt. Exiting.");
                            }
                            exit_code.store(
                                RETURN_HOST_KEY_UNKNOWN,
                                Ordering::SeqCst,
                            );
                            break;
                        }

                        if hkc_matcher.feed(data) {
                            exit_code.store(
                                RETURN_HOST_KEY_CHANGED,
                                Ordering::SeqCst,
                            );
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })
    };

    let child_status = child.wait().ok();
    let _ = read_handle.join();

    let sshpass_code = exit_code.load(Ordering::SeqCst);
    if sshpass_code != 0 {
        return Ok(sshpass_code);
    }

    match child_status {
        Some(status) => Ok(status
            .exit_code()
            .try_into()
            .unwrap_or(255)),
        None => Ok(255),
    }
}

fn setup_signal_handler(
    _master: &Box<dyn MasterPty + Send>,
    _exit_code: &Arc<AtomicI32>,
) {
    #[cfg(unix)]
    setup_unix_signals(_master);

    let _ = ctrlc::set_handler(|| {});
}

#[cfg(unix)]
fn setup_unix_signals(master: &Box<dyn MasterPty + Send>) {
    use signal_hook::consts::{SIGHUP, SIGTERM};
    use signal_hook::iterator::Signals;

    let mut writer = match master.take_writer() {
        Ok(w) => w,
        Err(_) => return,
    };

    let mut signals = match Signals::new([SIGHUP, SIGTERM]) {
        Ok(s) => s,
        Err(_) => return,
    };

    thread::spawn(move || {
        for sig in signals.forever() {
            match sig {
                SIGHUP | SIGTERM => {
                    let _ = writer.flush();
                    break;
                }
                _ => {}
            }
        }
    });
}
