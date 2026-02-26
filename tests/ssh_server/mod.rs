use async_trait::async_trait;
use russh::server::Auth::Reject;
use russh::server::{Auth, Config, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodSet, Sig};
use russh_keys::key::KeyPair;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::oneshot;

const TEST_USER: &str = "testuser";
const TEST_PASS: &str = "testpass123";

pub struct TestSshServer {
    pub port: u16,
}

static SERVER: OnceLock<TestSshServer> = OnceLock::new();

pub fn ensure_server() -> &'static TestSshServer {
    SERVER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let config = std::sync::Arc::new(Config {
                    keys: vec![KeyPair::generate_ed25519()],
                    auth_rejection_time: Duration::from_millis(0),
                    auth_rejection_time_initial: Some(Duration::from_millis(0)),
                    ..Default::default()
                });

                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap().port()).unwrap();

                let mut server = SshTestServer;
                server.run_on_socket(config, &listener).await.unwrap();
            });
        });

        TestSshServer {
            port: rx.recv().unwrap(),
        }
    })
}

struct SshTestServer;

impl Server for SshTestServer {
    type Handler = SshHandler;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> SshHandler {
        SshHandler {
            channels: HashMap::new(),
        }
    }
}

enum ChannelMode {
    Done,
    HeadOne,
    Sleep(oneshot::Sender<()>),
    Shell,
}

struct SshHandler {
    channels: HashMap<ChannelId, ChannelMode>,
}

#[async_trait]
impl Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == TEST_USER && password == TEST_PASS {
            Ok(Auth::Accept)
        } else {
            Ok(Reject {
                proceed_with_methods: Some(MethodSet::PASSWORD),
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let handle = session.handle();
        let _ = handle.channel_success(channel).await;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let handle = session.handle();
        let _ = handle.channel_success(channel).await;
        self.channels.insert(channel, ChannelMode::Shell);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let handle = session.handle();
        let _ = handle.channel_success(channel).await;

        let cmd = String::from_utf8_lossy(data);
        let parts: Vec<&str> = cmd.split_whitespace().collect();

        match parts.first().copied() {
            Some("echo") => {
                let output = format!("{}\n", parts[1..].join(" "));
                let _ = handle
                    .data(channel, CryptoVec::from_slice(output.as_bytes()))
                    .await;
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                self.channels.insert(channel, ChannelMode::Done);
            }
            Some("exit") => {
                let code: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                let _ = handle.exit_status_request(channel, code).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                self.channels.insert(channel, ChannelMode::Done);
            }
            Some("head") if parts.get(1) == Some(&"-1") => {
                self.channels.insert(channel, ChannelMode::HeadOne);
            }
            Some("sleep") => {
                let secs: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
                let (cancel_tx, cancel_rx) = oneshot::channel();

                let h = handle.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(secs)) => {
                            let _ = h.exit_status_request(channel, 0).await;
                        }
                        _ = cancel_rx => {
                            let _ = h.exit_status_request(channel, 130).await;
                        }
                    }
                    let _ = h.eof(channel).await;
                    let _ = h.close(channel).await;
                });

                self.channels.insert(channel, ChannelMode::Sleep(cancel_tx));
            }
            _ => {
                let _ = handle.exit_status_request(channel, 127).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                self.channels.insert(channel, ChannelMode::Done);
            }
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.channels.get(&channel) {
            Some(ChannelMode::HeadOne) => {
                let handle = session.handle();
                let input = String::from_utf8_lossy(data);
                let line = input.lines().next().unwrap_or("");
                let output = format!("{}\n", line);
                let _ = handle
                    .data(channel, CryptoVec::from_slice(output.as_bytes()))
                    .await;
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                self.channels.insert(channel, ChannelMode::Done);
            }
            Some(ChannelMode::Sleep(_)) => {
                if data.contains(&0x03)
                    && let Some(ChannelMode::Sleep(cancel)) = self.channels.remove(&channel)
                {
                    let _ = cancel.send(());
                }
            }
            Some(ChannelMode::Shell) => {
                if data.contains(&0x04) {
                    let handle = session.handle();
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                    self.channels.insert(channel, ChannelMode::Done);
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if matches!(signal, Sig::INT)
            && let Some(ChannelMode::Sleep(cancel)) = self.channels.remove(&channel)
        {
            let _ = cancel.send(());
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if matches!(self.channels.get(&channel), Some(ChannelMode::Shell)) {
            let handle = session.handle();
            let _ = handle.exit_status_request(channel, 0).await;
            let _ = handle.close(channel).await;
            self.channels.insert(channel, ChannelMode::Done);
        }
        Ok(())
    }
}
