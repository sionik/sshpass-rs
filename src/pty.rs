use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::matcher::Matcher;

const RETURN_INCORRECT_PASSWORD: i32 = 5;
const RETURN_HOST_KEY_UNKNOWN: i32 = 6;
const RETURN_HOST_KEY_CHANGED: i32 = 7;

type SharedWriter = Arc<Mutex<Option<Box<dyn Write + Send>>>>;
type SharedMaster = Arc<Mutex<Option<Box<dyn MasterPty + Send>>>>;

#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    #[error("failed to open pseudo terminal: {0}")]
    Open(String),
    #[error("failed to spawn command: {0}")]
    Spawn(String),
    #[error("failed to get pty reader: {0}")]
    Reader(String),
    #[error("failed to get pty writer: {0}")]
    Writer(String),
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
        .map_err(|e| PtyError::Open(e.to_string()))?;

    let mut cmd = CommandBuilder::new(&config.command[0]);
    for arg in &config.command[1..] {
        cmd.arg(arg);
    }

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| PtyError::Spawn(e.to_string()))?;

    drop(pair.slave);

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| PtyError::Reader(e.to_string()))?;

    let writer: SharedWriter = Arc::new(Mutex::new(Some(
        pair.master
            .take_writer()
            .map_err(|e| PtyError::Writer(e.to_string()))?,
    )));
    let master: SharedMaster = Arc::new(Mutex::new(Some(pair.master)));
    let exit_code = Arc::new(AtomicI32::new(0));

    let _raw_guard = RawModeGuard::enter();

    #[cfg(unix)]
    let _signal_handle = setup_unix_signals(Arc::clone(&writer), Arc::clone(&master));

    #[cfg(not(unix))]
    {
        let w = Arc::clone(&writer);
        let _ = ctrlc::set_handler(move || {
            write_to_pty(&w, b"\x03");
        });
    }

    let stdin_handle = {
        let writer = Arc::clone(&writer);
        thread::spawn(move || {
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 1024];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => write_to_pty(&writer, &buf[..n]),
                    Err(_) => break,
                }
            }
        })
    };

    let read_handle = {
        let password = config.password;
        let prompt = config.prompt;
        let verbose = config.verbose;
        let exit_code = Arc::clone(&exit_code);
        let writer = Arc::clone(&writer);
        let master = Arc::clone(&master);

        thread::spawn(move || {
            let mut stdout = std::io::stdout();
            let mut pw_matcher = Matcher::new(&prompt);
            let mut hk_matcher = Matcher::new("The authenticity of host ");
            let mut hkc_matcher = Matcher::new("differs from the key for the IP address");
            let mut password_sent = false;
            let mut suppress_until_newline = false;
            let mut buf = [0u8; 4096];

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
                            eprintln!("SSHPASS: read: {}", String::from_utf8_lossy(data));
                        }

                        if pw_matcher.feed(data) {
                            if !password_sent {
                                if verbose {
                                    eprintln!("SSHPASS: detected prompt. Sending password.");
                                }
                                let payload = format!("{}\n", password);
                                write_to_pty(&writer, payload.as_bytes());
                                password_sent = true;
                                suppress_until_newline = true;
                                pw_matcher.reset();
                            } else {
                                if verbose {
                                    eprintln!(
                                        "SSHPASS: detected prompt, again. Wrong password. Terminating."
                                    );
                                }
                                exit_code.store(RETURN_INCORRECT_PASSWORD, Ordering::SeqCst);
                                close_pty(&writer, &master);
                                break;
                            }
                        }

                        if hk_matcher.feed(data) {
                            if verbose {
                                eprintln!("SSHPASS: detected host authentication prompt. Exiting.");
                            }
                            exit_code.store(RETURN_HOST_KEY_UNKNOWN, Ordering::SeqCst);
                            close_pty(&writer, &master);
                            break;
                        }

                        if hkc_matcher.feed(data) {
                            exit_code.store(RETURN_HOST_KEY_CHANGED, Ordering::SeqCst);
                            close_pty(&writer, &master);
                            break;
                        }

                        if suppress_until_newline {
                            if let Some(pos) = data.iter().position(|&b| b == b'\n') {
                                suppress_until_newline = false;
                                let remaining = &data[pos + 1..];
                                if !remaining.is_empty() {
                                    let _ = stdout.write_all(remaining);
                                    let _ = stdout.flush();
                                }
                            }
                        } else {
                            let _ = stdout.write_all(data);
                            let _ = stdout.flush();
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
    drop(stdin_handle);

    let sshpass_code = exit_code.load(Ordering::SeqCst);
    if sshpass_code != 0 {
        return Ok(sshpass_code);
    }

    match child_status {
        Some(status) => Ok(status.exit_code().try_into().unwrap_or(255)),
        None => Ok(255),
    }
}

fn write_to_pty(writer: &SharedWriter, data: &[u8]) {
    if let Ok(mut guard) = writer.lock()
        && let Some(ref mut w) = *guard {
            let _ = w.write_all(data);
            let _ = w.flush();
        }
}

fn close_pty(writer: &SharedWriter, master: &SharedMaster) {
    if let Ok(mut w) = writer.lock() {
        w.take();
    }
    if let Ok(mut m) = master.lock() {
        m.take();
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

struct RawModeGuard {
    #[cfg(unix)]
    original: Option<libc::termios>,
}

impl RawModeGuard {
    fn enter() -> Self {
        #[cfg(unix)]
        {
            let original = unsafe {
                let mut termios = std::mem::MaybeUninit::<libc::termios>::zeroed().assume_init();
                if libc::isatty(libc::STDIN_FILENO) != 0
                    && libc::tcgetattr(libc::STDIN_FILENO, &mut termios) == 0
                {
                    let original = termios;
                    libc::cfmakeraw(&mut termios);
                    termios.c_lflag |= libc::ISIG;
                    libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &termios);
                    Some(original)
                } else {
                    None
                }
            };
            Self { original }
        }
        #[cfg(not(unix))]
        Self {}
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(ref original) = self.original {
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, original);
            }
        }
    }
}

#[cfg(unix)]
fn setup_unix_signals(
    writer: SharedWriter,
    master: SharedMaster,
) -> Option<signal_hook::iterator::backend::Handle> {
    use signal_hook::consts::*;
    use signal_hook::iterator::Signals;

    let mut signals = Signals::new([SIGWINCH, SIGTERM, SIGHUP, SIGINT, SIGTSTP]).ok()?;
    let handle = signals.handle();

    thread::spawn(move || {
        for sig in signals.forever() {
            match sig {
                SIGWINCH => {
                    if let Some(size) = get_terminal_size()
                        && let Ok(m) = master.lock()
                            && let Some(ref m) = *m {
                                let _ = m.resize(size);
                            }
                }
                SIGINT => write_to_pty(&writer, b"\x03"),
                SIGTSTP => write_to_pty(&writer, b"\x1a"),
                SIGTERM | SIGHUP => break,
                _ => {}
            }
        }
    });

    Some(handle)
}
