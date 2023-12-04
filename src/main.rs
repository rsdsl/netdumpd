use std::array;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};
use tokio::time::Duration;

use async_trait::async_trait;
use byteorder::LittleEndian;
use pcap::{Capture, Device};
use pcap_file_tokio::pcap::{PcapHeader, PcapPacket};
use pcap_file_tokio::{Endianness, TsResolution};
use ringbuf::{HeapRb, Rb};
use russh::server::{Auth, Handle, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodSet};
use russh_keys::key::KeyPair;
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("can't convert slice to array: {0}")]
    ArrayTryFromSlice(#[from] array::TryFromSliceError),

    #[error("pcap error: {0}")]
    Pcap(#[from] pcap::Error),
    #[error("pcap_file_tokio error: {0}")]
    PcapFileTokio(#[from] pcap_file_tokio::PcapError),
    #[error("russh error: {0}")]
    Russh(#[from] russh::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<HashMap<(usize, ChannelId), Handle>>>,
    id: usize,

    packets: Arc<Mutex<HeapRb<Vec<u8>>>>,
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
        println!("[info] [{}] open session", channel.id());

        {
            let mut clients = self.clients.lock().await;
            clients.insert((self.id, channel.id()), session.handle());
        }

        Ok((self, true, session))
    }

    async fn auth_password(self, user: &str, password: &str) -> Result<(Self, Auth)> {
        let correct_password = fs::read("/data/admind.passwd")?;

        if user == "rustkrazy" && password.as_bytes() == correct_password {
            println!("[info] auth ok");
            Ok((self, Auth::Accept))
        } else {
            println!("[warn] auth err");
            Ok((
                self,
                Auth::Reject {
                    proceed_with_methods: None,
                },
            ))
        }
    }

    async fn exec_request(
        self,
        channel: ChannelId,
        _: &[u8],
        mut session: Session,
    ) -> Result<(Self, Session)> {
        println!("[info] [{}] exec", channel);

        let header = PcapHeader {
            endianness: Endianness::Little,
            ..Default::default()
        };

        let mut buf = Vec::new();
        header.write_to(&mut buf).await?;

        let s = session.handle();
        let _ = s.data(channel, CryptoVec::from(buf)).await;

        {
            let packets = self.packets.lock().await;
            for packet in packets.iter() {
                let _ = s.data(channel, CryptoVec::from(packet.clone())).await;
            }
        }

        Ok((self, session))
    }

    async fn channel_close(self, channel: ChannelId, session: Session) -> Result<(Self, Session)> {
        println!("[info] [{}] close session", channel);
        Ok((self, session))
    }
}

async fn capture(
    dev: Device,
    server: Server,
    live_tx: mpsc::UnboundedSender<Vec<u8>>,
) -> Result<()> {
    let mut cap = Capture::from_device(dev)?.immediate_mode(true).open()?;
    loop {
        let packet = cap.next_packet()?;

        {
            let pcap_packet = PcapPacket::new(
                Duration::new(
                    packet.header.ts.tv_sec as u64,
                    (packet.header.ts.tv_usec * 1000) as u32,
                ),
                packet.header.len,
                packet.data,
            );

            let mut buf = Vec::new();
            pcap_packet
                .write_to::<_, LittleEndian>(&mut buf, TsResolution::MicroSecond, 65535)
                .await?;

            let mut packets = server.packets.lock().await;
            packets.push_overwrite(buf.clone());

            let _ = live_tx.send(buf);
        }
    }
}

async fn live_push(server: Server, mut live_rx: mpsc::UnboundedReceiver<Vec<u8>>) -> Result<()> {
    while let Some(packet) = live_rx.recv().await {
        let clients = server.clients.lock().await;
        for ((_, channel), session) in clients.iter() {
            let _ = session
                .data(*channel, CryptoVec::from(packet.clone()))
                .await;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("[info] init");

    let config = Arc::new(russh::server::Config {
        methods: MethodSet::PASSWORD,
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![KeyPair::generate_ed25519().expect("ed25519 keypair generation")],
        ..Default::default()
    });

    let (live_tx, live_rx) = mpsc::unbounded_channel();

    let server = Server {
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: 0,

        packets: Arc::new(Mutex::new(HeapRb::new(64000))),
    };

    let devs = ["wlan0"];

    for dev in devs {
        if dev == "any" {
            continue;
        }

        println!("[info] capture on {}", dev);

        let server2 = server.clone();
        let live_tx2 = live_tx.clone();
        tokio::spawn(async move {
            match capture(dev.into(), server2, live_tx2).await {
                Ok(_) => {}
                Err(e) => println!("[fail] capture on {}: {}", dev, e),
            }
        });
    }

    let server2 = server.clone();
    tokio::spawn(async move {
        match live_push(server2, live_rx).await {
            Ok(_) => {}
            Err(e) => println!("[fail] live push: {}", e),
        }
    });

    russh::server::run(config, "[::]:22", server).await?;
    Ok(())
}
