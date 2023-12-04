use std::array;
use std::io::{self, Read};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use pcap::Capture;
use ringbuf::{HeapRb, Rb};
use rsdsl_netlinklib::blocking::Connection;
use thiserror::Error;

const PEER_TIMEOUT: Duration = Duration::from_secs(30);

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
}

impl From<mpsc::SendError<Vec<u8>>> for Error {
    fn from(_: mpsc::SendError<Vec<u8>>) -> Self {
        Self::MpscSendU8Vec
    }
}

type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    Ok(())
}
