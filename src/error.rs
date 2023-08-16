use std::io;
use std::sync::mpsc;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("mpsc recv: {0}")]
    MpscRecv(#[from] mpsc::RecvError),
    #[error("mpsc send Vec<u8>")]
    MpscSendU8Vec,

    #[error("pcap: {0}")]
    Pcap(#[from] pcap::Error),
}

impl From<mpsc::SendError<Vec<u8>>> for Error {
    fn from(_: mpsc::SendError<Vec<u8>>) -> Self {
        Self::MpscSendU8Vec
    }
}

pub type Result<T> = std::result::Result<T, Error>;
