mod ssh_server;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const TEST_USER: &str = "testuser";
const TEST_PASS: &str = "testpass123";
const WRONG_PASS: &str = "wrongpassword";

fn sshpass_bin() -> String {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove "deps"
    if cfg!(windows) {
        path.push("sshpass-rs.exe");
    } else {
        path.push("sshpass-rs");
    }
    path.to_string_lossy().to_string()
}

fn null_device() -> &'static str {
    if cfg!(windows) { "NUL" } else { "/dev/null" }
}

fn ssh_args() -> Vec<String> {
    let port = ssh_server::ensure_server().port;
    vec![
        "ssh".into(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", null_device()),
        "-o".into(),
        "PreferredAuthentications=password".into(),
        "-o".into(),
        "PubkeyAuthentication=no".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-p".into(),
        port.to_string(),
        format!("{}@127.0.0.1", TEST_USER),
    ]
}

#[test]
fn correct_password_runs_command() {
    let mut args = vec!["-p".to_string(), TEST_PASS.to_string()];
    args.extend(ssh_args());
    args.push("echo".into());
    args.push("hello".into());

    let output = Command::new(sshpass_bin())
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run sshpass");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello"),
        "expected 'hello' in stdout, got: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn wrong_password_returns_exit_5() {
    let mut args = vec!["-p".to_string(), WRONG_PASS.to_string()];
    args.extend(ssh_args());
    args.push("echo".into());
    args.push("hello".into());

    let output = Command::new(sshpass_bin())
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run sshpass");

    assert_eq!(
        output.status.code(),
        Some(5),
        "expected exit code 5 for wrong password, got: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_password_works() {
    let mut args = ssh_args();
    args.insert(0, "-e".to_string());
    args.push("echo".into());
    args.push("env_works".into());

    let output = Command::new(sshpass_bin())
        .env("SSHPASS", TEST_PASS)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run sshpass");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("env_works"),
        "expected 'env_works' in stdout, got: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn file_password_works() {
    let pw_file = std::env::temp_dir().join("sshpass_test_integration_pw");
    std::fs::write(&pw_file, format!("{}\n", TEST_PASS)).unwrap();

    let mut args = vec!["-f".to_string(), pw_file.to_string_lossy().to_string()];
    args.extend(ssh_args());
    args.push("echo".into());
    args.push("file_works".into());

    let output = Command::new(sshpass_bin())
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run sshpass");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("file_works"),
        "expected 'file_works' in stdout, got: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0));

    std::fs::remove_file(pw_file).ok();
}

#[test]
fn host_key_unknown_returns_exit_6() {
    let port = ssh_server::ensure_server().port;
    let mut args = vec!["-p".to_string(), TEST_PASS.to_string()];
    args.extend(vec![
        "ssh".into(),
        "-o".into(),
        "StrictHostKeyChecking=ask".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", null_device()),
        "-o".into(),
        "PreferredAuthentications=password".into(),
        "-o".into(),
        "PubkeyAuthentication=no".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-p".into(),
        port.to_string(),
        format!("{}@127.0.0.1", TEST_USER),
        "echo".into(),
        "hello".into(),
    ]);

    let output = Command::new(sshpass_bin())
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run sshpass");

    assert_eq!(
        output.status.code(),
        Some(6),
        "expected exit code 6 for unknown host key, got: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn exit_code_from_remote_command_is_forwarded() {
    let mut args = vec!["-p".to_string(), TEST_PASS.to_string()];
    args.extend(ssh_args());
    args.push("exit".into());
    args.push("42".into());

    let output = Command::new(sshpass_bin())
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run sshpass");

    assert_eq!(
        output.status.code(),
        Some(42),
        "expected exit code 42 from remote command, got: {:?}",
        output.status.code()
    );
}

#[test]
fn stdin_is_forwarded_to_remote() {
    let mut args = vec!["-p".to_string(), TEST_PASS.to_string()];
    args.extend(ssh_args());
    args.push("head".into());
    args.push("-1".into());

    let mut child = Command::new(sshpass_bin())
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn sshpass");

    let mut stdin = child.stdin.take().unwrap();

    std::thread::sleep(Duration::from_secs(2));

    stdin.write_all(b"stdin_test\n").unwrap();
    stdin.flush().unwrap();
    drop(stdin);

    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("stdin_test"),
        "expected 'stdin_test' in stdout, got: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn eof_closes_session() {
    let mut args = vec!["-p".to_string(), TEST_PASS.to_string()];
    args.extend(ssh_args());

    let start = Instant::now();

    let mut child = Command::new(sshpass_bin())
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn sshpass");

    let stdin = child.stdin.take().unwrap();

    std::thread::sleep(Duration::from_secs(2));

    // Close stdin to send EOF
    drop(stdin);

    let output = child.wait_with_output().expect("failed to wait");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "expected quick exit after EOF, took {:?}",
        elapsed
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "expected clean exit after EOF, got: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn password_is_not_leaked_to_stdout() {
    let mut args = vec!["-p".to_string(), TEST_PASS.to_string()];
    args.extend(ssh_args());
    args.push("echo".into());
    args.push("hello".into());

    let output = Command::new(sshpass_bin())
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run sshpass");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(TEST_PASS),
        "password leaked to stdout: {}",
        stdout
    );
}

#[test]
fn custom_prompt_matching_works() {
    // SSH sends a prompt like "user@host's password: " — the substring "assword"
    // (the default -P value) is present, so authentication should succeed.
    let mut args = vec![
        "-p".to_string(),
        TEST_PASS.to_string(),
        "-P".to_string(),
        "assword".to_string(),
    ];
    args.extend(ssh_args());
    args.push("echo".into());
    args.push("prompt_ok".into());

    let output = Command::new(sshpass_bin())
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run sshpass");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("prompt_ok"),
        "expected 'prompt_ok' in stdout, got: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn custom_prompt_nonmatching_rejects() {
    // Using a -P value that does NOT appear in SSH's password prompt.
    // The askpass helper must reject the prompt, so the connection should fail.
    // (Before the fix, -P was ignored and "password" was hardcoded, so this
    // would have incorrectly succeeded.)
    let mut args = vec![
        "-p".to_string(),
        TEST_PASS.to_string(),
        "-P".to_string(),
        "NONEXISTENT_PROMPT_STRING".to_string(),
    ];
    args.extend(ssh_args());
    args.push("echo".into());
    args.push("should_not_appear".into());

    let output = Command::new(sshpass_bin())
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run sshpass");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("should_not_appear"),
        "command should not have succeeded with non-matching prompt, stdout: {}",
        stdout
    );
    assert_ne!(
        output.status.code(),
        Some(0),
        "expected non-zero exit with non-matching prompt, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
