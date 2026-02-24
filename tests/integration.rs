use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::time::{Duration, Instant};

const CONTAINER_NAME: &str = "sshpass-rs-test-sshd";
const SSH_PORT: &str = "2222";
const TEST_USER: &str = "testuser";
const TEST_PASS: &str = "testpass123";
const WRONG_PASS: &str = "wrongpassword";

static CONTAINER_INIT: Once = Once::new();

fn sshpass_bin() -> String {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove "deps"
    path.push("sshpass-rs");
    path.to_string_lossy().to_string()
}

fn ensure_container() {
    CONTAINER_INIT.call_once(|| {
        let inspect = Command::new("podman")
            .args(["inspect", CONTAINER_NAME])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if inspect.is_ok() && inspect.unwrap().success() {
            let _ = Command::new("podman")
                .args(["start", CONTAINER_NAME])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            std::thread::sleep(Duration::from_secs(1));
            return;
        }

        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let dockerfile = format!("{}/tests/Dockerfile.sshd", manifest_dir);

        let image_name = "sshpass-rs-test-sshd:latest";
        let build_status = Command::new("podman")
            .args(["build", "-t", image_name, "-f", &dockerfile, "."])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("failed to build container image");
        assert!(build_status.success(), "container image build failed");

        let run_status = Command::new("podman")
            .args([
                "run",
                "-d",
                "--name",
                CONTAINER_NAME,
                "-p",
                &format!("{}:22", SSH_PORT),
                image_name,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("failed to start container");
        assert!(run_status.success(), "container start failed");

        std::thread::sleep(Duration::from_secs(2));
    });
}

fn ssh_args() -> Vec<String> {
    vec![
        "ssh".into(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-p".into(),
        SSH_PORT.into(),
        format!("{}@127.0.0.1", TEST_USER),
    ]
}

#[test]
fn correct_password_runs_command() {
    ensure_container();

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
    ensure_container();

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
    ensure_container();

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
    ensure_container();

    let pw_file = std::env::temp_dir().join("sshpass_test_integration_pw");
    std::fs::write(&pw_file, format!("{}\n", TEST_PASS)).unwrap();

    let mut args = vec![
        "-f".to_string(),
        pw_file.to_string_lossy().to_string(),
    ];
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
    ensure_container();

    let mut args = vec!["-p".to_string(), TEST_PASS.to_string()];
    args.extend(vec![
        "ssh".into(),
        "-o".into(),
        "StrictHostKeyChecking=ask".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-p".into(),
        SSH_PORT.into(),
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
fn verbose_mode_shows_debug_output() {
    ensure_container();

    let mut args = vec![
        "-v".to_string(),
        "-p".to_string(),
        TEST_PASS.to_string(),
    ];
    args.extend(ssh_args());
    args.push("echo".into());
    args.push("verbose_test".into());

    let output = Command::new(sshpass_bin())
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run sshpass");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SSHPASS: searching for password prompt"),
        "expected verbose search message in stderr, got: {}",
        stderr
    );
    assert!(
        stderr.contains("SSHPASS: detected prompt"),
        "expected verbose prompt detection in stderr, got: {}",
        stderr
    );
}

#[test]
fn exit_code_from_remote_command_is_forwarded() {
    ensure_container();

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
    ensure_container();

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
    ensure_container();

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
    ensure_container();

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
    ensure_container();

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
