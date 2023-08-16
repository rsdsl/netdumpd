use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use pcap::Capture;
use ringbuf::{HeapRb, Rb};
use rsdsl_netlinkd::link;
use rsdsl_udpdumpd::Result;

const PEER_TIMEOUT: Duration = Duration::from_secs(30);

fn main() -> Result<()> {
    let devices = [
        "wlan0", "eth0", "eth0.10", "eth0.20", "eth0.30", "eth0.40", "eth1", "ppp0", "dslite0",
        "he6in4",
    ];

    let clt = Arc::new(Mutex::new(None));
    let last_connect = Arc::new(Mutex::new(Instant::now()));
    let rb = Arc::new(Mutex::new(HeapRb::new(2000)));

    let sock = UdpSocket::bind("[::]:5555")?;

    let (mut r, w) = os_pipe::pipe()?;
    let fd = w.as_raw_fd();

    for dev in devices {
        thread::spawn(move || loop {
            if let Err(e) = link::wait_up(dev.to_owned()) {
                println!("can't wait for {}: {}", dev, e);

                thread::sleep(Duration::from_secs(8));
                continue;
            }

            match capture(dev, fd) {
                Ok(_) => unreachable!(),
                Err(e) => println!("can't capture on {}: {}", dev, e),
            }

            thread::sleep(Duration::from_secs(8));
        });
    }

    let sock2 = sock.try_clone()?;
    let clt2 = clt.clone();
    let rb2 = rb.clone();
    let last_connect2 = last_connect.clone();
    thread::spawn(move || loop {
        match recv_ctl(&sock2, clt2.clone(), rb2.clone(), last_connect2.clone()) {
            Ok(_) => {}
            Err(e) => println!("can't recv control packets: {}", e),
        }
    });

    let clt2 = clt.clone();
    let last_connect2 = last_connect.clone();
    thread::spawn(move || loop {
        if Instant::now().duration_since(
            *last_connect2
                .lock()
                .expect("last connect timestamp mutex is poisoned"),
        ) >= PEER_TIMEOUT
        {
            *clt2.lock().expect("client address mutex is poisoned") = None;
        }

        thread::sleep(PEER_TIMEOUT / 2);
    });

    loop {
        let mut buf = [0; 1600];
        let n = r.read(&mut buf)?;
        let buf = &buf[..n];

        rb.lock()
            .expect("packet ring buffer mutex is poisoned")
            .push_overwrite(buf.to_vec());

        let mut clt = clt.lock().expect("client address mutex is poisoned");
        if let Some(addr) = *clt {
            match sock.send_to(buf, addr) {
                Ok(_) => {}
                Err(e) => {
                    *clt = None;
                    println!("can't send pcap pkt: {}", e);
                }
            }
        }
    }
}

fn recv_ctl(
    sock: &UdpSocket,
    clt: Arc<Mutex<Option<SocketAddr>>>,
    rb: Arc<Mutex<HeapRb<Vec<u8>>>>,
    last_connect: Arc<Mutex<Instant>>,
) -> Result<()> {
    let mut buf = [0; 0];
    let (_, raddr) = sock.recv_from(&mut buf)?;

    if clt
        .lock()
        .expect("client address mutex is poisoned")
        .is_none()
    {
        for pkt in rb
            .lock()
            .expect("packet ring buffer mutex is poisoned")
            .iter()
        {
            sock.send_to(pkt, raddr)?;
        }
    }

    *last_connect
        .lock()
        .expect("last connect timestamp mutex is poisoned") = Instant::now();
    *clt.lock().expect("client address mutex is poisoned") = Some(raddr);

    println!("connect {}", raddr);
    Ok(())
}

fn capture(dev: &str, fd: RawFd) -> Result<()> {
    println!("capturing on {}", dev);

    let mut cap = Capture::from_device(dev)?.immediate_mode(true).open()?;
    let mut savefile = unsafe { cap.savefile_raw_fd(fd)? };

    loop {
        let pkt = cap.next_packet()?;

        savefile.write(&pkt);
        savefile.flush()?;
    }
}
