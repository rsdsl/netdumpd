use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::Wrapping;
use std::sync::Arc;
use std::{array, fmt, fs, io};

use tokio::sync::{mpsc, Mutex};
use tokio::time::Duration;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use async_trait::async_trait;
use byteorder::LittleEndian;
use pcap::{Capture, Device, Packet, PacketCodec};
use pcap_file_tokio::pcap::{PcapHeader, PcapPacket};
use pcap_file_tokio::{Endianness, TsResolution};
use ringbuf::{HeapRb, Rb};
use rsdsl_netlinklib::Connection;
use russh::server::{Auth, Handle, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodSet};
use russh_keys::key::KeyPair;

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

const DEVICES: &[&str] = &[
    "eth0", "eth0.10", "eth0.20", "eth0.30", "eth0.40", "eth1", "carrier0", "ppp0", "dslite0",
];

const PPP_MAC_AC: &[u8] = &[0xcf, 0x72, 0x73, 0x00, 0x00, 0x01];
const PPP_MAC_HOST: &[u8] = &[0xcf, 0x72, 0x73, 0x00, 0x00, 0x02];

const DSLITE_MAC_AFTR: &[u8] = &[0xce, 0x72, 0x73, 0x00, 0x00, 0x01];
const DSLITE_MAC_B4: &[u8] = &[0xce, 0x72, 0x73, 0x00, 0x00, 0x02];

const ETHERTYPE_IPV4: u16 = 0x800;

// The maximum number of packets held in the ring buffer.
const PACKET_BUFFER_SIZE: usize = 256000;

#[derive(Debug)]
enum Error {
    Io(io::Error),
    ArrayTryFromSlice(array::TryFromSliceError),

    Pcap(pcap::Error),
    PcapFileTokio(pcap_file_tokio::PcapError),
    Russh(russh::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {}", e)?,
            Self::ArrayTryFromSlice(e) => write!(f, "can't convert slice to array: {}", e)?,
            Self::Pcap(e) => write!(f, "pcap error: {}", e)?,
            Self::PcapFileTokio(e) => write!(f, "pcap_file_tokio error: {}", e)?,
            Self::Russh(e) => write!(f, "russh error: {}", e)?,
        }

        Ok(())
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<array::TryFromSliceError> for Error {
    fn from(e: array::TryFromSliceError) -> Error {
        Error::ArrayTryFromSlice(e)
    }
}

impl From<pcap::Error> for Error {
    fn from(e: pcap::Error) -> Error {
        Error::Pcap(e)
    }
}

impl From<pcap_file_tokio::PcapError> for Error {
    fn from(e: pcap_file_tokio::PcapError) -> Error {
        Error::PcapFileTokio(e)
    }
}

impl From<russh::Error> for Error {
    fn from(e: russh::Error) -> Error {
        Error::Russh(e)
    }
}

impl std::error::Error for Error {}

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

impl Server {
    fn verify_argon2id(self, password: &[u8], phc: &str) -> Result<(Self, Auth)> {
        let parsed_hash = match PasswordHash::new(phc) {
            Ok(p) => p,
            Err(e) => {
                println!("[warn] bad phc {}: {}", phc, e);
                return Ok((
                    self,
                    Auth::Reject {
                        proceed_with_methods: None,
                    },
                ));
            }
        };

        if Argon2::default()
            .verify_password(password, &parsed_hash)
            .is_ok()
        {
            println!("[info] auth ok argon2id");
            Ok((self, Auth::Accept))
        } else {
            println!("[warn] auth err argon2id");
            Ok((
                self,
                Auth::Reject {
                    proceed_with_methods: None,
                },
            ))
        }
    }

    fn verify_plain(self, password: &str) -> Result<(Self, Auth)> {
        let correct_password = match fs::read("/data/admind.passwd") {
            Ok(p) => p,
            Err(e) => {
                println!("[warn] read /data/admind.passwd: {}", e);
                return Ok((
                    self,
                    Auth::Reject {
                        proceed_with_methods: None,
                    },
                ));
            }
        };

        if password.as_bytes() == correct_password {
            println!("[info] auth ok plain");
            Ok((self, Auth::Accept))
        } else {
            println!("[warn] auth err plain");
            Ok((
                self,
                Auth::Reject {
                    proceed_with_methods: None,
                },
            ))
        }
    }
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
        if user != "rustkrazy" {
            println!("[warn] bad user {}", user);
            return Ok((
                self,
                Auth::Reject {
                    proceed_with_methods: None,
                },
            ));
        }

        match fs::read_to_string("/data/passwd.argon2id") {
            Ok(phc) => self.verify_argon2id(password.as_bytes(), &phc),
            Err(e) if e.kind() == io::ErrorKind::NotFound => self.verify_plain(password),
            Err(e) => {
                println!("[warn] read /data/passwd.argon2id: {}", e);
                Ok((
                    self,
                    Auth::Reject {
                        proceed_with_methods: None,
                    },
                ))
            }
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
    let mut null_codec = NullCodec;

    let is_ppp = device.name.starts_with("ppp");
    let is_dslite = device.name == "dslite0";

    let mut capture = Capture::from_device(device)?
        .immediate_mode(true)
        .open()?
        .setnonblock()?;

    capture.filter(FILTER, true)?;

    loop {
        match capture.next_packet() {
            Ok(packet) => {
                let mut packet = null_codec.decode(packet);

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
                } else if is_dslite {
                    let mut data = packet.data.into_owned();

                    let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&data[16..20])?);
                    if dst.is_private() {
                        // Incoming packet.
                        //
                        // Destination: CE:72:73:00:00:02 (B4)
                        // Source: CE:72:73:00:00:01 (AFTR)

                        data.splice(..0, DSLITE_MAC_B4.iter().copied());
                        data.splice(6..6, DSLITE_MAC_AFTR.iter().copied());
                    } else {
                        // Outgoing packet.
                        //
                        // Destination: CE:72:73:00:00:01 (AFTR)
                        // Source: CE:72:73.00:00:02 (B4)

                        data.splice(..0, DSLITE_MAC_AFTR.iter().copied());
                        data.splice(6..6, DSLITE_MAC_B4.iter().copied());
                    }

                    // EtherType: 0x0800 (IPv4)
                    data.splice(12..12, ETHERTYPE_IPV4.to_be_bytes());

                    packet = PcapPacket::new_owned(packet.timestamp, 14 + packet.orig_len, data);
                }

                let mut buf = Vec::new();
                packet
                    .write_to::<_, LittleEndian>(&mut buf, TsResolution::MicroSecond, 65535)
                    .await?;

                let mut packets = server.packets.lock().await;
                packets.push_overwrite(buf.clone());

                let _ = live_tx.send(buf);
            }
            Err(pcap::Error::IoError(io::ErrorKind::WouldBlock) | pcap::Error::TimeoutExpired) => {
                tokio::time::sleep(Duration::from_millis(200)).await
            }
            Err(e) => return Err(e.into()),
        }
    }
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

        packets: Arc::new(Mutex::new(HeapRb::new(PACKET_BUFFER_SIZE))),
    };

    for device in DEVICES {
        if *device == "any" {
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

                println!("[info] capture {}", device);
                match capture((*device).into(), server2.clone(), live_tx2.clone()).await {
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
