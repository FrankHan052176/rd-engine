// Modified from rustdesk/rustdesk@092a961b629d318fe290eeafac0cd214a1e9deeb
// src/lan.rs:1-24,76-84,107-352 (AGPL-3.0-only; upstream/LICENCE).
// Local changes are cancellation/admission, owned joins, bounded ingress and
// bridge/cache hooks; payload, filtering and collector merge remain upstream.
use super::{OwnerState, Scan, add_error, lock, panic_error};
use hbb_common::{
    ResultType, allow_err,
    anyhow::bail,
    config::{self, RENDEZVOUS_PORT},
    log,
    protobuf::Message as _,
    rendezvous_proto::*,
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tokio::sync::mpsc::{self, Receiver, Sender, error::TryRecvError};

type Message = RendezvousMessage;
const CANCELLED: u8 = 1;
const DEADLINE: u8 = 2;
const FAILED: u8 = 3;
const INGRESS_CAPACITY: usize = 256;
const CONTROL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) struct ScanControl {
    deadline: Instant,
    stop: AtomicU8,
    failure: Mutex<Option<String>>,
    wake: Condvar,
    waiting: Mutex<()>,
}

impl ScanControl {
    pub(super) fn new() -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(10),
            stop: AtomicU8::new(0),
            failure: Mutex::new(None),
            wake: Condvar::new(),
            waiting: Mutex::new(()),
        }
    }

    pub(super) fn cancel(&self) {
        let _ = self
            .stop
            .compare_exchange(0, CANCELLED, Ordering::AcqRel, Ordering::Acquire);
        self.wake.notify_all();
    }

    pub(super) fn fail(&self, error: String) {
        add_error(&mut lock(&self.failure), error);
        self.stop.store(FAILED, Ordering::Release);
        self.wake.notify_all();
    }

    fn is_stopped(&self) -> bool {
        if self.stop.load(Ordering::Acquire) == 0 && Instant::now() >= self.deadline {
            let _ = self
                .stop
                .compare_exchange(0, DEADLINE, Ordering::AcqRel, Ordering::Acquire);
            self.wake.notify_all();
        }
        self.stop.load(Ordering::Acquire) != 0
    }

    fn wait_for_work(&self) {
        let waiting = lock(&self.waiting);
        if !self.is_stopped() {
            // A missed notification is bounded by 10ms. No blocking_recv can
            // conceal cancellation/deadline while a sender is still alive.
            drop(
                self.wake
                    .wait_timeout(waiting, CONTROL_INTERVAL)
                    .unwrap_or_else(|error| error.into_inner()),
            );
        }
    }

    pub(super) fn terminal(&self) -> &'static str {
        match self.stop.load(Ordering::Acquire) {
            CANCELLED => "cancelled",
            DEADLINE => "deadline",
            FAILED => "failed",
            _ => "inactivity",
        }
    }

    pub(super) fn error(&self) -> Option<String> {
        lock(&self.failure).clone()
    }
}

pub(super) fn discover(owner: Arc<OwnerState>, scan: Arc<Scan>) -> Result<(), String> {
    let (tx, rx) = mpsc::channel(INGRESS_CAPACITY);
    let mut owned = OwnedScan {
        owner,
        scan,
        rx,
        workers: Vec::new(),
        collector: None,
        finished: false,
    };
    match catch_unwind(AssertUnwindSafe(|| owned.run(tx))) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => owned.scan.control.fail(error),
        Err(panic) => owned
            .scan
            .control
            .fail(panic_error("LAN coordinator", panic)),
    }
    owned.finish();
    log::info!("discover ping done");
    owned.scan.control.error().map_or(Ok(()), Err)
}

struct OwnedScan {
    owner: Arc<OwnerState>,
    scan: Arc<Scan>,
    rx: Receiver<config::DiscoveryPeer>,
    workers: Vec<JoinHandle<Result<(), String>>>,
    collector: Option<Collector>,
    finished: bool,
}

impl OwnedScan {
    fn run(&mut self, tx: Sender<config::DiscoveryPeer>) -> Result<(), String> {
        if self.scan.control.is_stopped() {
            return Ok(());
        }
        let sockets = send_query(&self.owner.ping_id, &self.scan.control)
            .map_err(|error| error.to_string())?;
        if self.scan.control.is_stopped() {
            return Ok(());
        }
        // Initialize the official aggregate before admitting socket workers, so
        // a cache-load unwind cannot strand any accepted ingress records.
        self.collector = Some(Collector::new(self.owner.load_peers()));
        self.spawn_wait_responses(sockets, tx)?;
        self.handle_received_peers()
    }

    fn spawn_wait_responses(
        &mut self,
        sockets: Vec<UdpSocket>,
        tx: Sender<config::DiscoveryPeer>,
    ) -> Result<(), String> {
        if self.scan.control.is_stopped() {
            return Ok(());
        }
        // A successful spawn must never be followed by a fallible handle-list
        // allocation before its JoinHandle has an owner.
        self.workers
            .try_reserve(sockets.len())
            .map_err(|error| format!("LAN worker ownership allocation failed: {error}"))?;
        for socket in sockets {
            if self.scan.control.is_stopped() {
                break;
            }
            let tx_clone = tx.clone();
            let control = self.scan.control.clone();
            let worker = std::thread::Builder::new()
                .name("rd-lan-response".to_owned())
                .spawn(move || {
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        wait_response(socket, Some(CONTROL_INTERVAL), tx_clone, &control)
                            .map_err(|error| error.to_string())
                    }))
                    .unwrap_or_else(|panic| Err(panic_error("LAN socket worker", panic)));
                    if let Err(error) = &result {
                        control.fail(error.clone());
                    }
                    control.wake.notify_all();
                    result
                })
                .map_err(|error| format!("LAN socket worker creation failed: {error}"))?;
            // Save each successful spawn before attempting the next one.
            self.workers.push(worker);
        }
        // Dropping the coordinator's original sender permits natural inactivity.
        drop(tx);
        Ok(())
    }

    fn handle_received_peers(&mut self) -> Result<(), String> {
        loop {
            if self.scan.control.is_stopped() {
                self.rx.close();
                self.owner.stopping(self.scan.id);
                break;
            }
            match self.rx.try_recv() {
                Ok(peer) => {
                    // The record has already been admitted. Stop new ingress,
                    // but retain this record as well as the receiver's buffer.
                    if self.scan.control.is_stopped() {
                        self.rx.close();
                        self.owner.stopping(self.scan.id);
                    }
                    if let Some(collector) = &mut self.collector {
                        collector.merge(peer, &self.owner)?;
                    }
                }
                Err(TryRecvError::Empty) => self.scan.control.wait_for_work(),
                Err(TryRecvError::Disconnected) => break,
            }
        }
        Ok(())
    }

    fn drain_accepted(&mut self) {
        // close() rejects blocked/new sends but does not discard the buffer.
        // A sender which already acquired a permit can finish while we drain;
        // the second drain, after all joins, covers that race too.
        while let Ok(peer) = self.rx.try_recv() {
            let _ = self.scan.control.is_stopped();
            if let Some(collector) = &mut self.collector {
                match catch_unwind(AssertUnwindSafe(|| collector.merge(peer, &self.owner))) {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => self.scan.control.fail(error),
                    Err(panic) => self
                        .scan
                        .control
                        .fail(panic_error("LAN collector drain", panic)),
                }
            }
        }
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        if std::thread::panicking() {
            self.scan
                .control
                .fail("LAN coordinator unwound during cleanup".to_owned());
        }
        self.rx.close();
        if self.scan.control.is_stopped() {
            self.owner.stopping(self.scan.id);
        }
        self.drain_accepted();
        // No metadata/cache lock spans a join. Observe every result, not only
        // the first failure. Receiver close first releases full-queue senders.
        while let Some(worker) = self.workers.pop() {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => self.scan.control.fail(error),
                Err(panic) => self
                    .scan
                    .control
                    .fail(panic_error("LAN socket join", panic)),
            }
        }
        self.drain_accepted();
        if let Some(collector) = &self.collector {
            match catch_unwind(AssertUnwindSafe(|| {
                self.owner.store_peers(&collector.peers)
            })) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => self.scan.control.fail(error),
                Err(panic) => self
                    .scan
                    .control
                    .fail(panic_error("LAN final cache write", panic)),
            }
        }
        self.finished = true;
    }
}

impl Drop for OwnedScan {
    fn drop(&mut self) {
        self.finish();
    }
}

#[inline]
fn get_broadcast_port() -> u16 {
    (RENDEZVOUS_PORT + 3) as _
}

fn get_mac(_ip: &IpAddr, _control: &ScanControl) -> String {
    #[cfg(not(target_os = "ios"))]
    if let Ok(mac) = get_mac_by_ip(_ip, _control) {
        mac.to_string()
    } else {
        "".to_owned()
    }
    #[cfg(target_os = "ios")]
    "".to_owned()
}

#[cfg(not(target_os = "ios"))]
fn get_mac_by_ip(ip: &IpAddr, control: &ScanControl) -> ResultType<String> {
    if control.is_stopped() {
        bail!("LAN scan stopped");
    }
    for interface in default_net::get_interfaces() {
        if control.is_stopped() {
            bail!("LAN scan stopped");
        }
        match ip {
            IpAddr::V4(local_ipv4) => {
                if interface.ipv4.iter().any(|x| x.addr == *local_ipv4) {
                    if let Some(mac_addr) = interface.mac_addr {
                        return Ok(mac_addr.address());
                    }
                }
            }
            IpAddr::V6(local_ipv6) => {
                if interface.ipv6.iter().any(|x| x.addr == *local_ipv6) {
                    if let Some(mac_addr) = interface.mac_addr {
                        return Ok(mac_addr.address());
                    }
                }
            }
        }
    }
    bail!("No interface found for ip: {:?}", ip);
}

// Mainly from https://github.com/shellrow/default-net/blob/cf7ca24e7e6e8e566ed32346c9cfddab3f47e2d6/src/interface/shared.rs#L4
fn get_ipaddr_by_peer<A: ToSocketAddrs>(peer: A, control: &ScanControl) -> Option<IpAddr> {
    if control.is_stopped() {
        return None;
    }
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return None,
    };

    if control.is_stopped() {
        return None;
    }
    match socket.connect(peer) {
        Ok(()) => (),
        Err(_) => return None,
    };

    match socket.local_addr() {
        Ok(addr) => return Some(addr.ip()),
        Err(_) => return None,
    };
}

fn create_broadcast_sockets(control: &ScanControl) -> Vec<UdpSocket> {
    let mut ipv4s = Vec::new();
    if control.is_stopped() {
        return Vec::new();
    }
    // Upstream uses only [Ipv4Addr::UNSPECIFIED] on iOS because enumeration
    // causes undefined symbols when building the iOS simulator x86_64 target.
    #[cfg(not(any(target_os = "ios")))]
    for interface in default_net::get_interfaces() {
        if control.is_stopped() {
            return Vec::new();
        }
        for ipv4 in &interface.ipv4 {
            ipv4s.push(ipv4.addr.clone());
        }
    }
    ipv4s.push(Ipv4Addr::UNSPECIFIED); // for robustness
    let mut sockets = Vec::new();
    for v4_addr in ipv4s {
        if control.is_stopped() {
            break;
        }
        // removing v4_addr.is_private() check, https://github.com/rustdesk/rustdesk/issues/4663
        if let Ok(s) = UdpSocket::bind(SocketAddr::from((v4_addr, 0))) {
            if control.is_stopped() {
                break;
            }
            if s.set_broadcast(true).is_ok() {
                sockets.push(s);
            }
        }
    }
    sockets
}

fn send_query(_ping_id: &str, control: &ScanControl) -> ResultType<Vec<UdpSocket>> {
    let sockets = create_broadcast_sockets(control);
    if control.is_stopped() {
        return Ok(sockets);
    }
    if sockets.is_empty() {
        bail!("Found no bindable ipv4 addresses");
    }

    let mut msg_out = Message::new();
    // We may not be able to get the mac address on mobile platforms.
    // So we need to use the id to avoid discovering ourselves.
    // The existing initialized identity is injected instead of entering UI/IPC.
    #[cfg(any(target_os = "android", target_os = "ios", target_env = "ohos"))]
    let id = _ping_id.to_owned();
    // No need to get id for desktop platforms.
    // We can use the mac address to identify the device.
    #[cfg(not(any(target_os = "android", target_os = "ios", target_env = "ohos")))]
    let id = "".to_owned();
    let peer = PeerDiscovery {
        cmd: "ping".to_owned(),
        id,
        ..Default::default()
    };
    msg_out.set_peer_discovery(peer);
    let out = msg_out.write_to_bytes()?;
    let maddr = SocketAddr::from(([255, 255, 255, 255], get_broadcast_port()));
    for socket in &sockets {
        if control.is_stopped() {
            break;
        }
        allow_err!(socket.send_to(&out, maddr));
    }
    log::info!("discover ping sent");
    Ok(sockets)
}

fn wait_response(
    socket: UdpSocket,
    timeout: Option<std::time::Duration>,
    tx: Sender<config::DiscoveryPeer>,
    control: &ScanControl,
) -> ResultType<()> {
    if control.is_stopped() {
        return Ok(());
    }
    let mut last_recv_time = Instant::now();

    let local_addr = socket.local_addr();
    let try_get_ip_by_peer = match local_addr.as_ref() {
        Err(..) => true,
        Ok(addr) => addr.ip().is_unspecified(),
    };
    let mut mac: Option<String> = None;

    socket.set_read_timeout(timeout)?;
    loop {
        if control.is_stopped() {
            break;
        }
        let mut buf = [0; 2048];
        if let Ok((len, addr)) = socket.recv_from(&mut buf) {
            if control.is_stopped() {
                break;
            }
            if let Ok(msg_in) = Message::parse_from_bytes(&buf[0..len]) {
                match msg_in.union {
                    Some(rendezvous_message::Union::PeerDiscovery(p)) => {
                        last_recv_time = Instant::now();
                        if p.cmd == "pong" {
                            if !super::peer_id::is_valid_untrusted_peer_id(&p.id) {
                                log::warn!(
                                    "Ignoring LAN discovery response from {} with invalid peer id",
                                    addr
                                );
                                continue;
                            }

                            if control.is_stopped() {
                                break;
                            }
                            let local_mac = if try_get_ip_by_peer {
                                if let Some(self_addr) = get_ipaddr_by_peer(&addr, control) {
                                    get_mac(&self_addr, control)
                                } else {
                                    "".to_owned()
                                }
                            } else {
                                match mac.as_ref() {
                                    Some(m) => m.clone(),
                                    None => {
                                        let m = if let Ok(local_addr) = local_addr {
                                            get_mac(&local_addr.ip(), control)
                                        } else {
                                            "".to_owned()
                                        };
                                        mac = Some(m.clone());
                                        m
                                    }
                                }
                            };

                            if control.is_stopped() {
                                break;
                            }
                            if local_mac.is_empty() && p.mac.is_empty() || local_mac != p.mac {
                                if tx
                                    .blocking_send(config::DiscoveryPeer {
                                        id: p.id.clone(),
                                        ip_mac: HashMap::from([(
                                            addr.ip().to_string(),
                                            p.mac.clone(),
                                        )]),
                                        username: p.username.clone(),
                                        hostname: p.hostname.clone(),
                                        platform: p.platform.clone(),
                                        online: true,
                                    })
                                    .is_err()
                                {
                                    break;
                                }
                                control.wake.notify_all();
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if last_recv_time.elapsed().as_millis() > 3_000 {
            break;
        }
    }
    Ok(())
}

// Official handle_received_peers aggregate, separated from its wait so close
// and unwind can drain the same admitted records using the same merge rule.
struct Collector {
    peers: Vec<config::DiscoveryPeer>,
    response_set: HashSet<String>,
    last_write_time: Option<Instant>,
}

impl Collector {
    fn new(mut peers: Vec<config::DiscoveryPeer>) -> Self {
        peers.iter_mut().for_each(|peer| {
            peer.online = false;
        });
        Self {
            peers,
            response_set: HashSet::new(),
            last_write_time: None,
        }
    }

    fn merge(
        &mut self,
        mut peer: config::DiscoveryPeer,
        owner: &Arc<OwnerState>,
    ) -> Result<(), String> {
        let peers = &mut self.peers;
        let response_set = &mut self.response_set;
        let last_write_time = &mut self.last_write_time;
        let in_response_set = !response_set.insert(peer.id.clone());
        if let Some(pos) = peers.iter().position(|x| x.is_same_peer(&peer)) {
            let peer1 = peers.remove(pos);
            if in_response_set {
                peer.ip_mac.extend(peer1.ip_mac);
                peer.online = true;
            }
        }
        peers.insert(0, peer);
        if last_write_time
            .map(|t| t.elapsed().as_millis() > 300)
            .unwrap_or(true)
        {
            owner.store_peers(peers)?;
            *last_write_time = Some(Instant::now());
        }
        Ok(())
    }
}
