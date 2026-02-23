mod matcher;
mod password;
mod pty;

use clap::Parser;
use password::{PasswordSource, resolve_password};
use std::path::PathBuf;
use std::process;

const DEFAULT_PROMPT: &str = "assword:";
const DEFAULT_ENV_VAR: &str = "SSHPASS";

const EXIT_CONFLICTING_ARGUMENTS: i32 = 2;
const EXIT_RUNTIME_ERROR: i32 = 3;

#[derive(Parser)]
#[command(
    name = "sshpass",
    about = "Non-interactive ssh password authentication",
    version,
    override_usage = "sshpass [-f|-d|-p|-e[env_var]] [-hV] command parameters"
)]
struct Cli {
    /// Provide password as argument (security unwise)
    #[arg(short = 'p', value_name = "password")]
    password: Option<String>,

    /// Password is passed as env-var (default: SSHPASS)
    #[arg(short = 'e', value_name = "env_var", num_args = 0..=1, default_missing_value = DEFAULT_ENV_VAR, require_equals = true)]
    env: Option<String>,

    /// Take password to use from file
    #[arg(short = 'f', value_name = "filename")]
    file: Option<PathBuf>,

    /// Use number as file descriptor for getting password
    #[cfg(unix)]
    #[arg(short = 'd', value_name = "number")]
    fd: Option<i32>,

    /// Which string sshpass searches for to detect a password prompt
    #[arg(short = 'P', value_name = "prompt", default_value = DEFAULT_PROMPT)]
    prompt: String,

    /// Be verbose about what you're doing
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    /// Command and arguments to run
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

fn main() {
    let code = run();
    process::exit(code);
}

fn run() -> i32 {
    let cli = Cli::parse();

    let source = match determine_password_source(&cli) {
        Ok(s) => s,
        Err(code) => return code,
    };

    let password = match resolve_password(&source) {
        Ok(pw) => pw,
        Err(e) => {
            eprintln!("SSHPASS: {e}");
            return EXIT_RUNTIME_ERROR;
        }
    };

    let config = pty::RunConfig {
        command: cli.command,
        password,
        prompt: cli.prompt,
        verbose: cli.verbose > 0,
    };

    match pty::run(config) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("SSHPASS: {e}");
            EXIT_RUNTIME_ERROR
        }
    }
}

fn determine_password_source(cli: &Cli) -> Result<PasswordSource, i32> {
    let mut sources: Vec<PasswordSource> = Vec::new();

    if let Some(ref pw) = cli.password {
        sources.push(PasswordSource::Direct(pw.clone()));
    }
    if let Some(ref var) = cli.env {
        sources.push(PasswordSource::Env(var.clone()));
    }
    if let Some(ref path) = cli.file {
        sources.push(PasswordSource::File(path.clone()));
    }
    #[cfg(unix)]
    if let Some(fd) = cli.fd {
        sources.push(PasswordSource::Fd(fd));
    }

    match sources.len() {
        0 => Ok(PasswordSource::Stdin),
        1 => Ok(sources.into_iter().next().unwrap()),
        _ => {
            eprintln!("SSHPASS: conflicting password source");
            Err(EXIT_CONFLICTING_ARGUMENTS)
        }
    }
}
