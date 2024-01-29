use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::Wrapping;
use std::sync::Arc;
use std::{array, fs, io};

use tokio::sync::{mpsc, Mutex};
use tokio::time::Duration;

use async_trait::async_trait;
use byteorder::LittleEndian;
use futures::stream::TryStreamExt;
use pcap::{Capture, Device, Packet, PacketCodec};
use pcap_file_tokio::pcap::{PcapHeader, PcapPacket};
use pcap_file_tokio::{Endianness, TsResolution};
use ringbuf::{HeapRb, Rb};
use rsdsl_netlinklib::Connection;
use russh::server::{Auth, Handle, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodSet};
use russh_keys::key::KeyPair;
use thiserror::Error;

// Capture filter:
//
// * ARP
// * DHCPv4 (UDP port 67,  68)
// * DHCPv6 (UDP port 546, 547)
// * SIP    (UDP port 5060)
// * ICMPv4
// * ICMPv6 (-> NDP, RA)
// * PPPoED
// * PPP Control Protocols (ID > 0x4000, see RFC 1661 section 2)
const FILTER: &str = "arp or udp port 67 or udp port 68 or udp port 546 or udp port 547 or udp port 5060 or icmp or icmp6 or ether proto 0x8863 or (ether proto 0x8864 and ether[20:2] > 0x4000)";

const PPP_MAC_AC: &[u8] = &[0xcf, 0x72, 0x73, 0x00, 0x00, 0x01];
const PPP_MAC_HOST: &[u8] = &[0xcf, 0x72, 0x73, 0x00, 0x00, 0x02];

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

#[derive(Debug)]
struct NullCodec;

impl PacketCodec for NullCodec {
    type Item = PcapPacket<'static>;

    fn decode(&mut self, packet: Packet<'_>) -> Self::Item {
        PcapPacket::new_owned(
            Duration::new(
                packet.header.ts.tv_sec as u64,
                (packet.header.ts.tv_usec * 1000) as u32,
            ),
            packet.header.len,
            packet.data.to_vec(),
        )
    }
}

type HandleId = (Wrapping<usize>, ChannelId);

#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<HashMap<HandleId, Handle>>>,
    id: Wrapping<usize>,

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

        session.channel_success(channel);

        let header = PcapHeader {
            endianness: Endianness::Little,
            ..Default::default()
        };

        let mut buf = Vec::new();
        header.write_to(&mut buf).await?;

        session.data(channel, CryptoVec::from(buf));

        {
            let packets = self.packets.lock().await;
            for packet in packets.iter() {
                session.data(channel, CryptoVec::from(packet.clone()));
            }
        }

        Ok((self, session))
    }

    async fn channel_close(self, channel: ChannelId, session: Session) -> Result<(Self, Session)> {
        println!("[info] [{}] close session", channel);

        {
            let mut clients = self.clients.lock().await;

            let mut del_id = None;
            for ((id, ch), _) in clients.iter() {
                if *ch == channel {
                    del_id = Some(*id);
                }
            }

            if let Some(id) = del_id {
                clients.remove(&(id, channel));
            } else {
                println!("[warn] [{}] no session", channel);
            }
        }

        Ok((self, session))
    }
}

async fn capture(
    device: Device,
    server: Server,
    live_tx: mpsc::UnboundedSender<Vec<u8>>,
) -> Result<()> {
    let is_ppp = device.name.starts_with("ppp");

    let mut capture = Capture::from_device(device)?
        .immediate_mode(true)
        .open()?
        .setnonblock()?;

    capture.filter(FILTER, true)?;

    let mut packet_stream = capture.stream(NullCodec)?;

    while let Some(mut packet) = packet_stream.try_next().await? {
        // Format an Ethernet pseudo-header to make wireshark detect the EtherType correctly.
        if is_ppp {
            let data = packet.data.to_mut();

            // Remove invalid 0x0000 where EtherType is supposed to be.
            // The data that is shifted in its place is the correct EtherType.
            data.remove(13);
            data.remove(12);

            match u16::from_be_bytes(data[0..2].try_into()?) {
                // Outgoing packet:
                // sll_pkttype == PACKET_OUTGOING
                4 => {
                    // Destination: CF:72:73:00:00:01 (Access Concentrator)
                    data[0..6].copy_from_slice(PPP_MAC_AC);

                    // Source: CF:72:73:00:00:02 (Host)
                    data[6..12].copy_from_slice(PPP_MAC_HOST);
                }
                // Incoming (unicast) packet:
                // sll_pkttype == PACKET_HOST
                0 => {
                    // Destination: CF:72:73:00:00:02 (Host)
                    data[0..6].copy_from_slice(PPP_MAC_HOST);

                    // Source: CF:72:73:00:00:01 (Access Concentrator)
                    data[6..12].copy_from_slice(PPP_MAC_AC);
                }
                // Unknown or invalid packet type, make it available in wireshark.
                _ => {}
            }
        }

        let mut buf = Vec::new();
        packet
            .write_to::<_, LittleEndian>(&mut buf, TsResolution::MicroSecond, 65535)
            .await?;

        let mut packets = server.packets.lock().await;
        packets.push_overwrite(buf.clone());

        let _ = live_tx.send(buf);
    }

    Ok(())
}

async fn live_push(server: Server, live_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Result<()> {
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

    let (live_tx, mut live_rx) = mpsc::unbounded_channel();

    let server = Server {
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: Wrapping(0),

        packets: Arc::new(Mutex::new(HeapRb::new(64000))),
    };

    let devices = [
        "eth0", "eth0.10", "eth0.20", "eth0.30", "eth0.40", "eth1", "ppp0",
    ];

    for device in devices {
        if device == "any" {
            continue;
        }

        println!("[info] capture on {}", device);

        let server2 = server.clone();
        let live_tx2 = live_tx.clone();
        tokio::spawn(async move {
            let conn = Connection::new().await.expect("netlinklib connection");

            loop {
                println!("[info] wait for {}", device);
                conn.link_wait_up(device.to_string())
                    .await
                    .expect("link waiting");

                match capture(device.into(), server2.clone(), live_tx2.clone()).await {
                    Ok(_) => {}
                    Err(e) => println!("[fail] capture on {}: {}", device, e),
                }
            }
        });
    }

    let server2 = server.clone();
    tokio::spawn(async move {
        loop {
            match live_push(server2.clone(), &mut live_rx).await {
                Ok(_) => {}
                Err(e) => println!("[fail] live push: {}", e),
            }

            tokio::time::sleep(Duration::from_secs(8)).await;
        }
    });

    russh::server::run(config, "[::]:22", server).await?;
    Ok(())
}
