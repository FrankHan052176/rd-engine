//! Wake-on-LAN magic-packet submission over the engine's own Tokio runtime.
//!
//! One explicit datagram per call: six `0xFF` octets followed by the target MAC
//! repeated sixteen times (102 octets), the packet shape Intel/AMD Wake-on-LAN
//! NICs match. Every input is the caller's — the MAC, the local IPv4 address the
//! socket binds to, and the IPv4 destination, which may be a directed or global
//! broadcast, loopback or unicast. This module enumerates no interface, reads no
//! neighbour/ARP table, invents no MAC, chooses no destination, scans no LAN,
//! retries nothing and sends no second packet.
//!
//! # What the result means
//!
//! [`WakeRequest::submit`] returning `Ok` means one datagram was accepted by the
//! local socket layer, and nothing more. UDP is unacknowledged, so that is not
//! evidence that a computer woke, that a NIC received the packet, or that the
//! destination is reachable; [`SubmittedDatagram`] therefore offers no such
//! field. Whether a machine acts on the packet at all depends on its own
//! Wake-on-LAN configuration — host state this engine never reads and never
//! writes.
//!
//! # Interface selection
//!
//! The interface a packet leaves from is chosen by binding the socket to an
//! explicit local IPv4 address ([`WakeRequest::new`] takes that address;
//! `Ipv4Addr::UNSPECIFIED` leaves the choice to the routing table). Selection by
//! interface name (`SO_BINDTODEVICE`) is not implemented: it needs a native
//! binding this crate does not depend on.

use std::{fmt, io, net::{Ipv4Addr, SocketAddrV4}};
use tokio::net::UdpSocket;

const MAC_OCTETS: usize = 6;
const MAC_REPEATS: usize = 16;

/// Octets in one magic packet: the six-octet synchronisation stream (`0xFF` × 6)
/// followed by the target MAC repeated sixteen times.
pub const MAGIC_PACKET_BYTES: usize = MAC_OCTETS * (1 + MAC_REPEATS);

/// A validated MAC address: one interface, never a group.
///
/// Constructing one is the only way to name a Wake-on-LAN target, so a packet
/// for an all-zero, broadcast or multicast address cannot be built at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// Validates the six octets exactly as the user supplied them, in wire order.
    ///
    /// All zeros names no interface, and an I/G bit (the low bit of the first
    /// octet) set means a group address: multicast, of which the all-ones
    /// broadcast is one. A locally administered unicast address is legitimate and
    /// passes. There is no default and no discovery — a caller that has no MAC
    /// must supply one.
    pub fn new(octets: [u8; 6]) -> Result<Self, WakeError> {
        if octets == [0; MAC_OCTETS] || octets[0] & 0x01 != 0 {
            return Err(WakeError::InvalidMac);
        }
        Ok(Self(octets))
    }

    /// The six octets in wire order, as validated.
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }
}

/// One magic-packet submission: which NIC, from which local address, to which
/// destination. Nothing is defaulted and nothing is corrected — a request that
/// cannot carry a magic packet is refused instead of adjusted.
pub struct WakeRequest {
    mac: MacAddress,
    /// The local IPv4 address the socket is bound to. It selects the interface
    /// the datagram leaves from, and `Ipv4Addr::UNSPECIFIED` leaves both to the
    /// routing table. Whether the address is local (or legal as a source at all)
    /// is the kernel's answer: a wrong one fails the bind instead of being
    /// second-guessed here.
    bind: Ipv4Addr,
    /// IPv4 destination and port. Directed and global broadcast, loopback and
    /// unicast all pass [`WakeRequest::new`]; port zero, `0.0.0.0/8`, multicast
    /// and the reserved class-E range are refused there rather than rewritten.
    destination: SocketAddrV4,
}

impl WakeRequest {
    /// Validates the destination once, so [`WakeRequest::submit`] can only fail
    /// on the socket.
    pub fn new(
        mac: MacAddress,
        bind: Ipv4Addr,
        destination: SocketAddrV4,
    ) -> Result<Self, WakeError> {
        if destination.port() == 0 {
            return Err(WakeError::PortZero);
        }
        let ip = destination.ip();
        let first_octet = ip.octets()[0];
        // 0.0.0.0/8 is this-network/unspecified and is never a destination;
        // 224.0.0.0/4 is a group, not a host a NIC can be woken as; 240.0.0.0/4
        // is reserved for future use and must not be used as a destination
        // (RFC 1112 §4). That last range contains the limited broadcast
        // 255.255.255.255, which is legitimate and stays allowed, as do directed
        // broadcasts such as 192.168.1.255, loopback and unicast.
        if first_octet == 0 || ip.is_multicast() || (first_octet >= 240 && !ip.is_broadcast()) {
            return Err(WakeError::InvalidDestination);
        }
        Ok(Self {
            mac,
            bind,
            destination,
        })
    }

    /// Submits one datagram and returns once the socket layer accepted it.
    ///
    /// A fresh socket per call, bound to the caller's address on an ephemeral
    /// local port (Wake-on-LAN does not care which port the packet leaves from)
    /// and dropped with the call. Exactly one `send_to`: no retry, no second
    /// destination, and no waiting for anything to happen at the far end.
    pub async fn submit(&self) -> Result<SubmittedDatagram, WakeError> {
        let socket = UdpSocket::bind(SocketAddrV4::new(self.bind, 0))
            .await
            .map_err(WakeError::Bind)?;
        // SO_BROADCAST is a permission, not a mode: it changes nothing for a
        // unicast destination. It is required for the limited broadcast and for
        // a directed broadcast such as 192.168.1.255, which cannot be told apart
        // from a host address without the interface netmask — interface
        // configuration this module never reads. Enabling it only for
        // 255.255.255.255 would break the directed broadcast case.
        socket
            .set_broadcast(true)
            .map_err(WakeError::SetBroadcast)?;
        let packet = magic_packet(&self.mac);
        let bytes = socket
            .send_to(&packet, self.destination)
            .await
            .map_err(WakeError::Send)?;
        Ok(SubmittedDatagram {
            bytes,
            destination: self.destination,
        })
    }
}

/// One datagram accepted by the socket layer, and nothing more.
///
/// There is deliberately no "delivered", "reachable" or "awake" field: UDP
/// reports no acknowledgement, so none of those is observable from here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmittedDatagram {
    /// Octets `send_to` reported for the datagram it accepted. A complete magic
    /// packet is [`MAGIC_PACKET_BYTES`]; the reported value is returned unchanged
    /// so a caller checks it rather than trusting it.
    pub bytes: usize,
    /// The destination the datagram was submitted to. UDP reports nothing about
    /// where it went afterwards.
    pub destination: SocketAddrV4,
}

/// The standard packet for one MAC: `0xFF` × 6, then the MAC sixteen times.
fn magic_packet(mac: &MacAddress) -> [u8; MAGIC_PACKET_BYTES] {
    // The synchronisation stream is the fill value, so every octet past it is
    // MAC material: no separate header write and no heap buffer.
    let mut packet = [0xFF; MAGIC_PACKET_BYTES];
    for repeat in packet[MAC_OCTETS..].chunks_exact_mut(MAC_OCTETS) {
        repeat.copy_from_slice(&mac.0);
    }
    packet
}

#[derive(Debug)]
pub enum WakeError {
    /// The MAC names no single interface: all zeros, or a group address (the
    /// I/G bit set, which includes the all-ones broadcast). A caller without a
    /// MAC must supply one; this module never invents or discovers one.
    InvalidMac,
    /// Port zero: there is no service to submit to, and no default port is
    /// assumed on the caller's behalf.
    PortZero,
    /// An IPv4 destination no magic packet can go to: `0.0.0.0/8`
    /// (this-network/unspecified), multicast (`224.0.0.0/4`), or the reserved
    /// `240.0.0.0/4` other than the limited broadcast `255.255.255.255`.
    /// Directed/global broadcast, loopback and unicast all pass.
    InvalidDestination,
    /// The socket could not be created for the requested source address, most
    /// often because that address is not local. Nothing was submitted.
    Bind(io::Error),
    /// `SO_BROADCAST` could not be set on the socket. Nothing was submitted.
    SetBroadcast(io::Error),
    /// The socket layer refused the datagram. Nothing was submitted.
    Send(io::Error),
}

impl fmt::Display for WakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMac => write!(f, "MAC address does not name one interface"),
            Self::PortZero => write!(f, "Wake-on-LAN destination port is zero"),
            Self::InvalidDestination => {
                write!(f, "Wake-on-LAN destination cannot carry a magic packet")
            }
            Self::Bind(err) => write!(f, "Wake-on-LAN source address could not be bound: {err}"),
            Self::SetBroadcast(err) => {
                write!(f, "Wake-on-LAN socket could not be allowed to broadcast: {err}")
            }
            Self::Send(err) => write!(f, "Wake-on-LAN datagram was not submitted: {err}"),
        }
    }
}

impl std::error::Error for WakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind(err) | Self::SetBroadcast(err) | Self::Send(err) => Some(err),
            Self::InvalidMac | Self::PortZero | Self::InvalidDestination => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::SocketAddr, time::Duration};
    use tokio::time::timeout;

    /// A unicast, universally administered test address. Nothing here is read
    /// from the machine's own hardware.
    const TEST_MAC: [u8; 6] = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
    /// Long enough for a loopback datagram that was actually submitted, short
    /// enough that a test proving silence stays quick.
    const RECEIVE_WAIT: Duration = Duration::from_millis(100);

    async fn quiet_receiver() -> (UdpSocket, SocketAddrV4) {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let SocketAddr::V4(local) = socket.local_addr().unwrap() else {
            panic!("the receiver binds IPv4 loopback only");
        };
        (socket, local)
    }

    fn test_mac() -> MacAddress {
        MacAddress::new(TEST_MAC).unwrap()
    }

    /// Fails unless the receiver stays silent: what is refused must never reach a
    /// socket.
    async fn assert_silent(receiver: &UdpSocket) {
        let mut received = [0u8; MAGIC_PACKET_BYTES];
        match timeout(RECEIVE_WAIT, receiver.recv_from(&mut received)).await {
            Err(_elapsed) => {}
            Ok(Ok((length, _))) => panic!("{length} bytes were submitted anyway"),
            Ok(Err(error)) => panic!("receiver failed: {error}"),
        }
    }

    #[tokio::test]
    async fn one_magic_packet_arrives_byte_for_byte_at_the_requested_destination() {
        let (receiver, destination) = quiet_receiver().await;
        let request = WakeRequest::new(test_mac(), Ipv4Addr::LOCALHOST, destination).unwrap();
        let submitted = request.submit().await.unwrap();
        assert_eq!(submitted.destination, destination);

        // The specification's own bytes, built independently of the sender: six
        // 0xFF, then the MAC sixteen times.
        let mut expected = vec![0xFFu8; 6];
        for _ in 0..16 {
            expected.extend_from_slice(&TEST_MAC);
        }
        assert_eq!(expected.len(), 102);

        let mut received = [0u8; 128];
        let (length, origin) = timeout(RECEIVE_WAIT, receiver.recv_from(&mut received))
            .await
            .expect("the submitted datagram arrived")
            .unwrap();
        // The bind took effect: the datagram left from the address that was
        // asked for, on whatever ephemeral port the kernel chose.
        assert_eq!(origin.ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(&received[..length], &expected[..]);
        // What the socket reported submitting is what the receiver got.
        assert_eq!(submitted.bytes, length);
        // Exactly one datagram: a retry, a duplicate or a stray packet would
        // already be queued here.
        assert_silent(&receiver).await;
    }

    #[tokio::test]
    async fn invalid_macs_and_destinations_are_refused_and_submit_nothing() {
        let (receiver, _) = quiet_receiver().await;

        // MACs that name no single interface: all zeros, the all-ones broadcast,
        // and an IPv4 and an IPv6 multicast address.
        for mac in [
            [0x00; 6],
            [0xFF; 6],
            [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01],
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
        ] {
            assert!(
                matches!(MacAddress::new(mac), Err(WakeError::InvalidMac)),
                "{mac:?}"
            );
        }
        // Unicast addresses pass, including a locally administered one: nothing
        // is refused merely for looking unusual.
        for mac in [TEST_MAC, [0x02, 0x00, 0x5A, 0x1B, 0x2C, 0x3D]] {
            assert!(MacAddress::new(mac).is_ok(), "{mac:?}");
        }
        assert_eq!(test_mac().octets(), TEST_MAC);

        // Port zero is its own refusal.
        assert!(matches!(
            WakeRequest::new(
                test_mac(),
                Ipv4Addr::LOCALHOST,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)
            ),
            Err(WakeError::PortZero)
        ));
        // Destinations no magic packet can go to: this-network/unspecified,
        // multicast, and the reserved range above the limited broadcast.
        for ip in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(0, 0, 0, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(239, 255, 255, 250),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 254),
        ] {
            assert!(
                matches!(
                    WakeRequest::new(test_mac(), Ipv4Addr::LOCALHOST, SocketAddrV4::new(ip, 9)),
                    Err(WakeError::InvalidDestination)
                ),
                "{ip}"
            );
        }
        // Global and directed broadcast, unicast and loopback are all the
        // caller's to choose: which interface the packet leaves by is the only
        // thing the source address decides.
        for ip in [
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(192, 168, 1, 255),
            Ipv4Addr::new(192, 168, 1, 50),
            Ipv4Addr::LOCALHOST,
        ] {
            assert!(
                WakeRequest::new(test_mac(), Ipv4Addr::LOCALHOST, SocketAddrV4::new(ip, 9)).is_ok(),
                "{ip}"
            );
        }

        // Everything above was refused before a socket existed, so the receiver
        // never saw a datagram.
        assert_silent(&receiver).await;
    }

    #[tokio::test]
    async fn a_source_address_the_kernel_refuses_is_a_visible_bind_failure() {
        let (receiver, destination) = quiet_receiver().await;
        // 255.255.255.255 is never a local address, so the bind fails instead of
        // the packet being submitted from somewhere else. The destination is
        // loopback, so nothing could leave the machine even if that bind were
        // somehow accepted.
        let request = WakeRequest::new(test_mac(), Ipv4Addr::BROADCAST, destination).unwrap();
        let error = request.submit().await.unwrap_err();
        assert!(matches!(error, WakeError::Bind(_)), "{error:?}");
        // The socket's own reason is preserved rather than replaced by a local
        // constant, so the caller can tell "not local" from "no permission".
        assert!(std::error::Error::source(&error).is_some());
        assert_silent(&receiver).await;
    }
}
