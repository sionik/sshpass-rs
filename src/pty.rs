use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
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

    let initial_size = get_terminal_size().unwrap_or(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    });

    let pair = pty_system
        .openpty(initial_size)
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

    let writer = Arc::new(Mutex::new(writer));
    #[allow(unused_variables)]
    let master = Arc::new(Mutex::new(pair.master));
    let exit_code = Arc::new(AtomicI32::new(0));

    #[cfg(unix)]
    let _signal_handle =
        setup_unix_signals(Arc::clone(&writer), Arc::clone(&master));

    #[cfg(not(unix))]
    {
        let w = Arc::clone(&writer);
        let _ = ctrlc::set_handler(move || {
            if let Ok(mut w) = w.lock() {
                let _ = w.write_all(b"\x03");
                let _ = w.flush();
            }
        });
    }

    let read_handle = {
        let password = config.password;
        let prompt = config.prompt;
        let verbose = config.verbose;
        let exit_code = Arc::clone(&exit_code);
        let writer = Arc::clone(&writer);

        thread::spawn(move || {
            let mut pw_matcher = Matcher::new(&prompt);
            let mut hk_matcher = Matcher::new("The authenticity of host ");
            let mut hkc_matcher =
                Matcher::new("differs from the key for the IP address");
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
                                    eprintln!("SSHPASS: detected prompt. Sending password.");
                                }
                                if let Ok(mut w) = writer.lock() {
                                    let payload = format!("{}\n", password);
                                    let _ = w.write_all(payload.as_bytes());
                                    let _ = w.flush();
                                }
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

    #[cfg(unix)]
    if let Some(handle) = _signal_handle {
        handle.close();
    }

    let _ = read_handle.join();

    let sshpass_code = exit_code.load(Ordering::SeqCst);
    if sshpass_code != 0 {
        return Ok(sshpass_code);
    }

    match child_status {
        Some(status) => Ok(status.exit_code().try_into().unwrap_or(255)),
        None => Ok(255),
    }
}

#[cfg(unix)]
fn get_terminal_size() -> Option<PtySize> {
    unsafe {
        let mut ws = std::mem::MaybeUninit::<libc::winsize>::zeroed().assume_init();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 {
            Some(PtySize {
                rows: ws.ws_row,
                cols: ws.ws_col,
                pixel_width: ws.ws_xpixel,
                pixel_height: ws.ws_ypixel,
            })
        } else {
            None
        }
    }
}

#[cfg(not(unix))]
fn get_terminal_size() -> Option<PtySize> {
    None
}

#[cfg(unix)]
fn setup_unix_signals(
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    master: Arc<Mutex<Box<dyn portable_pty::MasterPty + Send>>>,
) -> Option<signal_hook::iterator::backend::Handle> {
    use signal_hook::consts::*;
    use signal_hook::iterator::Signals;

    let mut signals =
        Signals::new([SIGINT, SIGTSTP, SIGWINCH, SIGTERM, SIGHUP]).ok()?;
    let handle = signals.handle();

    thread::spawn(move || {
        for sig in signals.forever() {
            match sig {
                SIGINT => {
                    if let Ok(mut w) = writer.lock() {
                        let _ = w.write_all(b"\x03");
                        let _ = w.flush();
                    }
                }
                SIGTSTP => {
                    if let Ok(mut w) = writer.lock() {
                        let _ = w.write_all(b"\x1a");
                        let _ = w.flush();
                    }
                }
                SIGWINCH => {
                    if let Some(size) = get_terminal_size() {
                        if let Ok(m) = master.lock() {
                            let _ = m.resize(size);
                        }
                    }
                }
                SIGTERM | SIGHUP => break,
                _ => {}
            }
        }
    });

    Some(handle)
}
