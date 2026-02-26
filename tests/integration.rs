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
        "expected 'hello' in stdout, got: {}",
        stdout
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
        "expected 'env_works' in stdout, got: {}",
        stdout
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
        "expected 'file_works' in stdout, got: {}",
        stdout
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
        "expected 'stdin_test' in stdout, got: {}",
        stdout
    );
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn ctrl_c_terminates_remote_command() {
    let mut args = vec!["-p".to_string(), TEST_PASS.to_string()];
    args.extend(ssh_args());
    args.push("sleep".into());
    args.push("30".into());

    let start = Instant::now();

    let mut child = Command::new(sshpass_bin())
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn sshpass");

    let mut stdin = child.stdin.take().unwrap();

    std::thread::sleep(Duration::from_secs(2));

    stdin.write_all(b"\x03").unwrap();
    stdin.flush().unwrap();
    drop(stdin);

    let _output = child.wait_with_output().expect("failed to wait");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "expected quick exit after Ctrl+C, took {:?}",
        elapsed
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
fn ctrl_d_closes_session() {
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

    let mut stdin = child.stdin.take().unwrap();

    std::thread::sleep(Duration::from_secs(2));

    stdin.write_all(b"\x04").unwrap();
    stdin.flush().unwrap();
    drop(stdin);

    let output = child.wait_with_output().expect("failed to wait");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "expected quick exit after Ctrl+D, took {:?}",
        elapsed
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "expected clean exit after Ctrl+D, got: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}
