mod askpass;
mod password;

use anyhow::bail;
use clap::Parser;
use password::{PasswordSource, resolve_password};
use std::path::PathBuf;
use std::process;

const DEFAULT_PROMPT: &str = "assword:";
const DEFAULT_ENV_VAR: &str = "SSHPASS";

const EXIT_RUNTIME_ERROR: i32 = 3;

#[derive(Parser)]
#[command(
    name = "sshpass-rs",
    about = "Non-interactive ssh password authentication",
    version,
    author
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

    /// Command and arguments to run
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

fn main() {
    // If we're being invoked as the SSH_ASKPASS helper, handle that and exit
    if std::env::var_os("SSHPASS_ASKPASS_MODE").is_some() {
        askpass::askpass_main();
    }

    let retcode = run().unwrap_or_else(|e| {
        eprintln!("sshpass-rs {e:#}");
        EXIT_RUNTIME_ERROR
    });

    process::exit(retcode);
}

fn run() -> anyhow::Result<i32> {
    let cli = Cli::parse();
    let source = determine_password_source(&cli)?;
    let password = resolve_password(&source)?;

    let config = askpass::RunConfig {
        command: cli.command,
        password,
        prompt: cli.prompt,
    };

    askpass::run(config)
}

fn determine_password_source(cli: &Cli) -> anyhow::Result<PasswordSource> {
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
        _ => bail!("conflicting password source"),
    }
}
