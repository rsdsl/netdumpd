use std::array;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use async_trait::async_trait;
use pcap::Capture;
use ringbuf::{HeapRb, Rb};
use rsdsl_netlinklib::blocking::Connection;
use russh::server::{Auth, Handle, Msg, Session};
use russh::{Channel, ChannelId, MethodSet};
use russh_keys::key::KeyPair;
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("can't receive from mpsc channel: {0}")]
    MpscRecv(#[from] mpsc::RecvError),
    #[error("can't send Vec<u8> to mpsc channel")]
    MpscSendU8Vec,
    #[error("can't convert slice to array: {0}")]
    ArrayTryFromSlice(#[from] array::TryFromSliceError),

    #[error("netlinklib error: {0}")]
    Netlinklib(#[from] rsdsl_netlinklib::Error),
    #[error("pcap error: {0}")]
    Pcap(#[from] pcap::Error),
    #[error("russh error: {0}")]
    Russh(#[from] russh::Error),
}

impl From<mpsc::SendError<Vec<u8>>> for Error {
    fn from(_: mpsc::SendError<Vec<u8>>) -> Self {
        Self::MpscSendU8Vec
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<HashMap<(usize, ChannelId), Handle>>>,
    id: usize,
}

impl russh::server::Server for Server {
    type Handler = Self;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
        let s = self.clone();
        self.id += 1;
        s
    }
}

#[async_trait]
impl russh::server::Handler for Server {
    type Error = Error;

    async fn channel_open_session(
        self,
        channel: Channel<Msg>,
        session: Session,
    ) -> Result<(Self, bool, Session)> {
        {
            let mut clients = self.clients.lock().await;
            clients.insert((self.id, channel.id()), session.handle());
        }

        Ok((self, true, session))
    }

    async fn auth_password(self, user: &str, password: &str) -> Result<(Self, Auth)> {
        let correct_password = fs::read("/data/admind.passwd")?;

        if user == "rustkrazy" && password.as_bytes() == correct_password {
            Ok((self, Auth::Accept))
        } else {
            Ok((
                self,
                Auth::Reject {
                    proceed_with_methods: None,
                },
            ))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Arc::new(russh::server::Config {
        methods: MethodSet::PASSWORD,
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![KeyPair::generate_ed25519().expect("ed25519 keypair generation")],
        ..Default::default()
    });

    let server = Server {
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: 0,
    };

    russh::server::run(config, "[::]:2222", server).await?;
    Ok(())
}
