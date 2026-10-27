//! Rendezvous fixtures: the source-order TCP viewer dialer (hbbs→direct encrypted
//! handoff and hbbs→relay fallback) and the host-side registration service
//! (UDP registration, TCP punch, hbbr pairing, presence, cancellation).
use base::message_proto::{
    Hash, LoginRequest, LoginResponse, Message, Misc, PeerInfo, SignedId, message,
};
use hbb_common::{
    AddrMangle,
    bytes::Bytes,
    protobuf::{Message as _, MessageField},
    rendezvous_proto::{
        ConnType, ControlPermissions, FetchLocalAddr, IdPk, OnlineResponse, PunchHole,
        PunchHoleResponse, RegisterPeerResponse, RegisterPkResponse, RelayResponse,
        RendezvousMessage, RequestRelay, register_pk_response, rendezvous_message,
    },
    sodiumoxide::{
        self,
        crypto::{box_, sign},
    },
    tcp::{Encrypt, FramedStream},
    uuid::Uuid,
};
use rd_engine::{
    rendezvous::{
        HostRouteKind, IdentityConflict, PresenceConfig, PresenceState, RegistrationConfig,
        RegistrationState, RendezvousConfig, RouteKind, StopReason, connect_viewer, query_presence,
        run_host_registration,
    },
    session::{ViewerEvent, ViewerSession},
};
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, mpsc, watch},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

const LIMIT: Duration = Duration::from_secs(8);

fn wire(stream: TcpStream) -> FramedStream {
    let local = stream.local_addr().unwrap();
    FramedStream::from(stream, local)
}
async fn control(wire: &mut FramedStream) -> RendezvousMessage {
    RendezvousMessage::parse_from_bytes(
        &tokio::time::timeout(LIMIT, wire.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    )
    .unwrap()
}
async fn peer_message(wire: &mut FramedStream) -> Message {
    Message::parse_from_bytes(
        &tokio::time::timeout(LIMIT, wire.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    )
    .unwrap()
}
fn certificate(public: &[u8], signer: &sign::SecretKey) -> Vec<u8> {
    sign::sign(
        &IdPk {
            id: "target".into(),
            pk: public.to_vec().into(),
            ..Default::default()
        }
        .write_to_bytes()
        .unwrap(),
        signer,
    )
}

#[tokio::test]
async fn direct_punch_reuses_source_port_and_preserves_encrypted_auth_handoff() {
    sodiumoxide::init().unwrap();
    let (server_pk, server_sk) = sign::gen_keypair();
    let (peer_pk, peer_sk) = sign::gen_keypair();
    let hbbs = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_address = hbbs.local_addr().unwrap();
    let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_address = peer.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, origin) = hbbs.accept().await.unwrap();
        let mut wire = wire(stream);
        let Some(rendezvous_message::Union::PunchHoleRequest(request)) =
            control(&mut wire).await.union
        else {
            panic!("Expected PunchHoleRequest")
        };
        assert_eq!(request.id, "target");
        assert_eq!(request.licence_key, "wire-key");
        assert!(!request.force_relay && request.udp_port == 0);
        let mut response = RendezvousMessage::new();
        response.set_key_exchange(Default::default());
        wire.send(&response).await.unwrap();
        response.set_punch_hole_response(PunchHoleResponse {
            socket_addr: AddrMangle::encode(peer_address).into(),
            pk: certificate(&peer_pk.0, &server_sk).into(),
            ..Default::default()
        });
        wire.send(&response).await.unwrap();
        origin.port()
    });
    let peer = tokio::spawn(async move {
        let (stream, origin) = peer.accept().await.unwrap();
        let mut wire = wire(stream);
        let (ephemeral_pk, ephemeral_sk) = box_::gen_keypair();
        let mut response = Message::new();
        response.set_signed_id(SignedId {
            id: certificate(&ephemeral_pk.0, &peer_sk).into(),
            ..Default::default()
        });
        wire.send(&response).await.unwrap();
        let Some(message::Union::PublicKey(key)) = peer_message(&mut wire).await.union else {
            panic!("Expected PublicKey")
        };
        wire.set_key(
            Encrypt::decode(&key.symmetric_value, &key.asymmetric_value, &ephemeral_sk).unwrap(),
        );
        response.set_hash(Hash {
            salt: "salt".into(),
            challenge: "challenge".into(),
            ..Default::default()
        });
        wire.send(&response).await.unwrap();
        let Some(message::Union::LoginRequest(request)) = peer_message(&mut wire).await.union
        else {
            panic!("Expected encrypted LoginRequest")
        };
        assert_eq!(request.username, "target");
        let mut success = LoginResponse::new();
        success.set_peer_info(PeerInfo::new());
        response.set_login_response(success);
        wire.send(&response).await.unwrap();
        response.set_test_delay(Default::default());
        wire.send(&response).await.unwrap();
        assert!(peer_message(&mut wire).await.misc().has_close_reason());
        origin.port()
    });
    let (established, route) = connect_viewer(RendezvousConfig {
        id: "target".into(),
        rendezvous_server: format!("localhost:{}", server_address.port()),
        licence_key: "wire-key".into(),
        server_key: server_pk,
        relay_server: None,
        connect_timeout: LIMIT,
    })
    .await
    .unwrap();
    assert_eq!(route.route, RouteKind::TcpHolePunch);
    assert!(route.encrypted && route.peer_verified);
    let mut session = ViewerSession::from_established(established, LIMIT, LIMIT);
    assert!(matches!(
        session.recv().await.unwrap(),
        ViewerEvent::Challenge
    ));
    session
        .login(
            LoginRequest {
                username: "target".into(),
                my_id: "controller".into(),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        session.recv().await.unwrap(),
        ViewerEvent::Authorized(_)
    ));
    let mut parts = session.into_authenticated_parts().unwrap();
    assert!(matches!(
        parts.reader.recv().await.unwrap().unwrap().union,
        Some(message::Union::TestDelay(_))
    ));
    let mut misc = Misc::new();
    misc.set_close_reason(String::new());
    let mut close = Message::new();
    close.set_misc(misc);
    parts.writer.send(&close).await.unwrap();
    assert_eq!(server.await.unwrap(), peer.await.unwrap());
}

#[tokio::test]
async fn relay_fallback_pairs_original_uuid_but_rejects_substituted_peer_key() {
    sodiumoxide::init().unwrap();
    let (server_pk, server_sk) = sign::gen_keypair();
    let (peer_pk, _) = sign::gen_keypair();
    let (_, attacker_sk) = sign::gen_keypair();
    let hbbs = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_address = hbbs.local_addr().unwrap();
    let hbbr = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_address = hbbr.local_addr().unwrap();
    // Reserve a non-listening port; do not race ephemeral-port reuse after drop.
    let unavailable = tokio::net::TcpSocket::new_v4().unwrap();
    unavailable.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let unavailable_address = unavailable.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = hbbs.accept().await.unwrap();
        let mut first = wire(stream);
        let Some(rendezvous_message::Union::PunchHoleRequest(request)) =
            control(&mut first).await.union
        else {
            panic!("Expected PunchHoleRequest")
        };
        assert_eq!(request.licence_key, "wire-key");
        let mut response = RendezvousMessage::new();
        response.set_punch_hole_response(PunchHoleResponse {
            socket_addr: AddrMangle::encode(unavailable_address).into(),
            pk: certificate(&peer_pk.0, &server_sk).into(),
            relay_server: format!("localhost:{}", relay_address.port()),
            ..Default::default()
        });
        first.send(&response).await.unwrap();
        drop(first);
        let (stream, _) = hbbs.accept().await.unwrap();
        let mut next = wire(stream);
        let Some(rendezvous_message::Union::RequestRelay(request)) = control(&mut next).await.union
        else {
            panic!("Expected hbbs RequestRelay")
        };
        assert!(request.secure);
        assert_eq!(request.id, "target");
        assert_eq!(
            request.relay_server,
            format!("localhost:{}", relay_address.port())
        );
        assert!(Uuid::parse_str(&request.uuid).is_ok());
        assert!(request.licence_key.is_empty());
        // Original ACK is allowed to omit uuid/pk; pairing uses our sent UUID.
        response.set_relay_response(RelayResponse::new());
        next.send(&response).await.unwrap();
        request.uuid
    });
    let relay = tokio::spawn(async move {
        let (stream, _) = hbbr.accept().await.unwrap();
        let mut wire = wire(stream);
        let Some(rendezvous_message::Union::RequestRelay(request)) = control(&mut wire).await.union
        else {
            panic!("Expected hbbr RequestRelay")
        };
        assert_eq!(request.id, "target");
        assert_eq!(request.licence_key, "wire-key");
        assert!(!request.secure); // The hbbs secure flag is not hbbr's join field.
        let (ephemeral, _) = box_::gen_keypair();
        let mut signed = Message::new();
        signed.set_signed_id(SignedId {
            id: certificate(&ephemeral.0, &attacker_sk).into(),
            ..Default::default()
        });
        wire.send(&signed).await.unwrap();
        let mut byte = [0];
        let result = tokio::time::timeout(LIMIT, wire.0.get_mut().read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(result, Ok(0))
                || result.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset),
            "Must not emit a fallback or key to an unverified relay peer"
        );
        request.uuid
    });
    assert!(
        connect_viewer(RendezvousConfig {
            id: "target".into(),
            rendezvous_server: format!("localhost:{}", server_address.port()),
            licence_key: "wire-key".into(),
            server_key: server_pk,
            relay_server: None,
            connect_timeout: LIMIT,
        })
        .await
        .is_err()
    );
    assert_eq!(server.await.unwrap(), relay.await.unwrap());
}

// ---------------------------------------------------------------------------
// Host-side rendezvous service fixtures
//
// These fixtures speak the wire protocol derived strictly from the pinned OSS
// rendezvous_server.rs and relay_server.rs at commit a7736be5e40f85bfc141120dce587e836e5d4b80
// with the engine's shared protobuf source pinned by vendor/rustdesk/UPSTREAM.json.
//
// Specific server rules modeled:
// * IDs must be >= 6 bytes (S:377-378); shorter IDs are rejected at preflight.
// * RegisterPeerResponse { request_pk: false } establishes only an address
//   observation; identity Observed requires real RegisterPk submission and OK (S:593-633, F03).
// * Unsolicited RegisterPkResponse is dropped without modifying state (F04).
// * Controller-forwarded RequestRelay.relay_server is unapproved without explicit
//   local configuration; evil relay hints are refused without connection or key exfiltration (F02).
// * Local route listener is prepared and ready BEFORE announcement (F08).
// * TCP punch preserves server-observed TCP source port mapping (S:637-668, F08).
// * HBBR pairing bridges both peers on matching UUID without invented ACK (R:461-498, F09/F10).
// * Dropping route consumer terminates worker immediately without waiting for route (F06).
// * Presence strictly requires a single OnlineResponse; KeyExchange is not skipped (S01).
//
// Local fake server acceptance does not constitute cross-platform pinned-server interoperability.
// ---------------------------------------------------------------------------

async fn hbbs() -> (UdpSocket, TcpListener, u16) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let udp = UdpSocket::bind(("127.0.0.1", port)).await.unwrap();
    (udp, tcp, port)
}

fn registration_config(
    port: u16,
    relay_port: Option<u16>,
    public_key: sign::PublicKey,
    id: &str,
) -> RegistrationConfig {
    RegistrationConfig {
        id: id.into(),
        registration_uuid: b"stable-uuid-0001".to_vec(),
        public_key,
        rendezvous_server: format!("127.0.0.1:{port}"),
        relay_server: relay_port.map(|port| format!("127.0.0.1:{port}")),
        licence_key: "wire-key-auth".into(),
        deadline: LIMIT * 2,
    }
}

fn wire_bytes(message: &RendezvousMessage) -> Vec<u8> {
    message.write_to_bytes().unwrap()
}

async fn datagram(socket: &UdpSocket) -> (RendezvousMessage, SocketAddr) {
    let mut buffer = [0u8; 4096];
    let (length, origin) = timeout(LIMIT, socket.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    (
        RendezvousMessage::parse_from_bytes(&buffer[..length]).unwrap(),
        origin,
    )
}

fn state_channel() -> (
    watch::Sender<RegistrationState>,
    watch::Receiver<RegistrationState>,
) {
    watch::channel(RegistrationState::Registering)
}

async fn await_state(rx: &mut watch::Receiver<RegistrationState>, want: RegistrationState) {
    let deadline = tokio::time::Instant::now() + LIMIT;
    loop {
        let current = *rx.borrow_and_update();
        if current == want {
            return;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "state {want:?} was never published; last state {current:?}"
        );
        let _ = timeout(remaining, rx.changed()).await;
    }
}

#[tokio::test]
async fn short_id_is_rejected_at_preflight() {
    let (host_pk, _) = sign::gen_keypair();
    let (states, _) = state_channel();
    let (routes, _) = mpsc::channel(4);
    let cancel = CancellationToken::new();

    // Pinned server S:377-378 rejects id.len() < 6 with UUID_MISMATCH.
    // Our preflight contract enforces this minimum length synchronously.
    let config = registration_config(21116, None, host_pk, "short");
    let res = run_host_registration(config, cancel, states, routes).await;
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().kind(), io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn malformed_registration_endpoints_preserve_preflight_state_and_error_contract() {
    let (host_pk, _) = sign::gen_keypair();
    for invalid_relay in [false, true] {
        let (states, state_rx) = watch::channel(RegistrationState::Stale);
        let (routes, _route_rx) = mpsc::channel(4);
        let mut config = registration_config(21116, None, host_pk, "host01");
        if invalid_relay {
            config.relay_server = Some(String::new());
        } else {
            config.rendezvous_server.clear();
        }
        let error = run_host_registration(config, CancellationToken::new(), states.clone(), routes)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(*state_rx.borrow(), RegistrationState::Stale);
        assert!(!state_rx.has_changed().unwrap());
    }
}

#[tokio::test]
async fn host_registration_requires_pk_submission_and_ok_before_identity_observed() {
    let (udp, _tcp, port) = hbbs().await;
    let (host_pk, _) = sign::gen_keypair();
    let (states, mut state_rx) = state_channel();
    let (routes, _route_rx) = mpsc::channel(4);
    let cancel = CancellationToken::new();
    let worker = tokio::spawn(run_host_registration(
        registration_config(port, None, host_pk, "host01"),
        cancel.clone(),
        states,
        routes,
    ));

    // 1. Host sends initial RegisterPeer heartbeat.
    let (registered, host_addr) = datagram(&udp).await;
    let Some(rendezvous_message::Union::RegisterPeer(peer)) = registered.union else {
        panic!("Expected RegisterPeer");
    };
    assert_eq!(peer.id, "host01");

    // 2. Server answers with request_pk = false (e.g. server already held some key for this id).
    // Host must NOT enter identity Observed; it must publish AddressObserved and submit RegisterPk (F03).
    let mut peer_res = RendezvousMessage::new();
    peer_res.set_register_peer_response(RegisterPeerResponse {
        request_pk: false,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&peer_res), host_addr)
        .await
        .unwrap();

    await_state(&mut state_rx, RegistrationState::AddressObserved).await;

    // 3. Host must submit RegisterPk to verify that server has its actual key.
    let (submitted, _) = datagram(&udp).await;
    let Some(rendezvous_message::Union::RegisterPk(key)) = submitted.union else {
        panic!("Expected RegisterPk submission");
    };
    assert_eq!(key.id, "host01");
    assert_eq!(key.uuid, Bytes::from_static(b"stable-uuid-0001"));
    assert_eq!(key.pk, Bytes::copy_from_slice(&host_pk.0));

    // 4. Server replies OK with keep_alive.
    let mut accepted = RendezvousMessage::new();
    accepted.set_register_pk_response(RegisterPkResponse {
        result: register_pk_response::Result::OK.into(),
        keep_alive: 25,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&accepted), host_addr)
        .await
        .unwrap();

    // Now, and only now, does identity Observed get published.
    await_state(
        &mut state_rx,
        RegistrationState::Observed { keep_alive_raw: 25 },
    )
    .await;

    // A duplicate answer has no pending submission and must not replace the
    // already observed result or turn a delayed conflict into a new decision.
    accepted.mut_register_pk_response().keep_alive = 100;
    udp.send_to(&wire_bytes(&accepted), host_addr)
        .await
        .unwrap();
    accepted.mut_register_pk_response().result = register_pk_response::Result::UUID_MISMATCH.into();
    udp.send_to(&wire_bytes(&accepted), host_addr)
        .await
        .unwrap();
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        *state_rx.borrow_and_update(),
        RegistrationState::Observed { keep_alive_raw: 25 }
    );
    assert!(!worker.is_finished());

    cancel.cancel();
    assert!(worker.await.unwrap().is_ok());
    assert_eq!(
        *state_rx.borrow_and_update(),
        RegistrationState::Stopped(StopReason::Cancelled)
    );
}

#[tokio::test]
async fn host_registration_ignores_unsolicited_pk_responses() {
    let (udp, _tcp, port) = hbbs().await;
    let (host_pk, _) = sign::gen_keypair();
    let (states, mut state_rx) = state_channel();
    let (routes, _route_rx) = mpsc::channel(4);
    let cancel = CancellationToken::new();
    let worker = tokio::spawn(run_host_registration(
        registration_config(port, None, host_pk, "host01"),
        cancel.clone(),
        states,
        routes,
    ));

    let (_, host_addr) = datagram(&udp).await;

    // Unsolicited RegisterPkResponse before any RegisterPk was requested or submitted.
    // Must be dropped completely without updating state (F04).
    let mut unsolicited = RendezvousMessage::new();
    unsolicited.set_register_pk_response(RegisterPkResponse {
        result: register_pk_response::Result::OK.into(),
        keep_alive: 100,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&unsolicited), host_addr)
        .await
        .unwrap();

    // Give time to ensure no state change happens.
    sleep(Duration::from_millis(200)).await;
    assert_eq!(
        *state_rx.borrow_and_update(),
        RegistrationState::Registering
    );

    // Unsolicited UUID_MISMATCH must also NOT terminate the worker when not expecting pk response.
    let mut unsolicited_mismatch = RendezvousMessage::new();
    unsolicited_mismatch.set_register_pk_response(RegisterPkResponse {
        result: register_pk_response::Result::UUID_MISMATCH.into(),
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&unsolicited_mismatch), host_addr)
        .await
        .unwrap();

    sleep(Duration::from_millis(200)).await;
    assert_eq!(
        *state_rx.borrow_and_update(),
        RegistrationState::Registering
    );

    cancel.cancel();
    assert!(worker.await.unwrap().is_ok());
}

#[tokio::test]
async fn conflicting_registration_uuid_stops_worker_with_conflict() {
    let (udp, _tcp, port) = hbbs().await;
    let (host_pk, _) = sign::gen_keypair();
    let (states, mut state_rx) = state_channel();
    let (routes, _route_rx) = mpsc::channel(4);
    let cancel = CancellationToken::new();
    let worker = tokio::spawn(run_host_registration(
        registration_config(port, None, host_pk, "host01"),
        cancel.clone(),
        states,
        routes,
    ));

    let (_, host_addr) = datagram(&udp).await;

    // Server requests pk.
    let mut req_pk = RendezvousMessage::new();
    req_pk.set_register_peer_response(RegisterPeerResponse {
        request_pk: true,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&req_pk), host_addr).await.unwrap();

    // Host submits pk.
    let _ = datagram(&udp).await;

    // Server answers with UUID_MISMATCH (S:399-408).
    let mut mismatch = RendezvousMessage::new();
    mismatch.set_register_pk_response(RegisterPkResponse {
        result: register_pk_response::Result::UUID_MISMATCH.into(),
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&mismatch), host_addr)
        .await
        .unwrap();

    await_state(
        &mut state_rx,
        RegistrationState::Conflict(IdentityConflict::UuidMismatch),
    )
    .await;

    let err = worker.await.unwrap().unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
}

#[tokio::test]
async fn untrusted_forwarded_relay_is_refused_without_connecting_or_key_exfiltration() {
    let (udp, tcp, port) = hbbs().await;
    let (host_pk, _) = sign::gen_keypair();

    // Host has NO configured relay (relay_server: None).
    let (states, mut state_rx) = state_channel();
    let (routes, _route_rx) = mpsc::channel(4);
    let cancel = CancellationToken::new();
    let worker = tokio::spawn(run_host_registration(
        registration_config(port, None, host_pk, "host01"),
        cancel.clone(),
        states,
        routes,
    ));

    // Complete registration
    let (_, host_addr) = datagram(&udp).await;
    let mut req_pk = RendezvousMessage::new();
    req_pk.set_register_peer_response(RegisterPeerResponse {
        request_pk: true,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&req_pk), host_addr).await.unwrap();
    let _ = datagram(&udp).await;
    let mut ok_res = RendezvousMessage::new();
    ok_res.set_register_pk_response(RegisterPkResponse {
        result: register_pk_response::Result::OK.into(),
        keep_alive: 30,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&ok_res), host_addr).await.unwrap();
    await_state(
        &mut state_rx,
        RegistrationState::Observed { keep_alive_raw: 30 },
    )
    .await;

    // Set up an unapproved evil relay target that must NOT receive any connection.
    let evil_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evil_addr = evil_listener.local_addr().unwrap();

    let controller_addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();

    // Controller forwards RequestRelay through hbbs naming evil_addr (F02).
    let mut req = RendezvousMessage::new();
    req.set_request_relay(RequestRelay {
        id: "host01".into(),
        uuid: "pairing-uuid-1".into(),
        socket_addr: AddrMangle::encode(controller_addr).into(),
        relay_server: evil_addr.to_string(),
        conn_type: ConnType::DEFAULT_CONN.into(),
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&req), host_addr).await.unwrap();

    // Host must connect to hbbs over TCP to announce a refusal.
    let (stream, _) = timeout(LIMIT, tcp.accept()).await.unwrap().unwrap();
    let mut hbbs_wire = wire(stream);
    let Some(rendezvous_message::Union::RelayResponse(refused)) =
        control(&mut hbbs_wire).await.union
    else {
        panic!("Expected RelayResponse refusal");
    };
    assert!(
        !refused.refuse_reason.is_empty(),
        "Refusal reason must be present"
    );
    assert_eq!(refused.uuid, "pairing-uuid-1");

    // Behavioral check: host MUST NOT connect to evil_listener, and licence_key is NOT exfiltrated.
    assert!(
        timeout(Duration::from_millis(300), evil_listener.accept())
            .await
            .is_err(),
        "Host must never connect to unapproved forwarded relay"
    );

    cancel.cancel();
    assert!(worker.await.unwrap().is_ok());
}

#[tokio::test]
async fn mismatched_relay_override_is_refused_no_false_pairing() {
    let (udp, tcp, port) = hbbs().await;
    let (host_pk, _) = sign::gen_keypair();

    let hbbr_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_b_port = hbbr_b.local_addr().unwrap().port();

    // Host configured with approved relay B.
    let (states, mut state_rx) = state_channel();
    let (routes, _route_rx) = mpsc::channel(4);
    let cancel = CancellationToken::new();
    let worker = tokio::spawn(run_host_registration(
        registration_config(port, Some(relay_b_port), host_pk, "host01"),
        cancel.clone(),
        states,
        routes,
    ));

    // Register
    let (_, host_addr) = datagram(&udp).await;
    let mut req_pk = RendezvousMessage::new();
    req_pk.set_register_peer_response(RegisterPeerResponse {
        request_pk: true,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&req_pk), host_addr).await.unwrap();
    let _ = datagram(&udp).await;
    let mut ok_res = RendezvousMessage::new();
    ok_res.set_register_pk_response(RegisterPkResponse {
        result: register_pk_response::Result::OK.into(),
        keep_alive: 30,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&ok_res), host_addr).await.unwrap();
    await_state(
        &mut state_rx,
        RegistrationState::Observed { keep_alive_raw: 30 },
    )
    .await;

    let controller_addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();

    // Controller proposes relay A ("127.0.0.1:11111"), which does not match configured B.
    let mut req = RendezvousMessage::new();
    req.set_request_relay(RequestRelay {
        id: "host01".into(),
        uuid: "pairing-uuid-ab".into(),
        socket_addr: AddrMangle::encode(controller_addr).into(),
        relay_server: "127.0.0.1:11111".into(),
        conn_type: ConnType::DEFAULT_CONN.into(),
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&req), host_addr).await.unwrap();

    // Host must announce refusal to hbbs and NOT join relay B silently (F07).
    let (stream, _) = timeout(LIMIT, tcp.accept()).await.unwrap().unwrap();
    let mut hbbs_wire = wire(stream);
    let Some(rendezvous_message::Union::RelayResponse(refused)) =
        control(&mut hbbs_wire).await.union
    else {
        panic!("Expected RelayResponse");
    };
    assert!(
        !refused.refuse_reason.is_empty(),
        "Mismatched relay must be refused"
    );
    assert_eq!(refused.uuid, "pairing-uuid-ab");

    assert!(
        timeout(Duration::from_millis(300), hbbr_b.accept())
            .await
            .is_err(),
        "Host must not join relay B when controller requested mismatched relay A"
    );

    cancel.cancel();
    assert!(worker.await.unwrap().is_ok());
}

#[tokio::test]
async fn local_route_listener_is_ready_immediately_without_retry() {
    let (udp, tcp, port) = hbbs().await;
    let (host_pk, _) = sign::gen_keypair();
    let (states, mut state_rx) = state_channel();
    let (routes, mut route_rx) = mpsc::channel(4);
    let cancel = CancellationToken::new();
    let worker = tokio::spawn(run_host_registration(
        registration_config(port, None, host_pk, "host01"),
        cancel.clone(),
        states,
        routes,
    ));

    // Complete registration
    let (_, host_addr) = datagram(&udp).await;
    let mut req_pk = RendezvousMessage::new();
    req_pk.set_register_peer_response(RegisterPeerResponse {
        request_pk: true,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&req_pk), host_addr).await.unwrap();
    let _ = datagram(&udp).await;
    let mut ok_res = RendezvousMessage::new();
    ok_res.set_register_pk_response(RegisterPkResponse {
        result: register_pk_response::Result::OK.into(),
        keep_alive: 30,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&ok_res), host_addr).await.unwrap();
    await_state(
        &mut state_rx,
        RegistrationState::Observed { keep_alive_raw: 30 },
    )
    .await;

    let controller_addr: SocketAddr = "127.0.0.1:44444".parse().unwrap();
    let mut fetch = RendezvousMessage::new();
    fetch.set_fetch_local_addr(FetchLocalAddr {
        socket_addr: AddrMangle::encode(controller_addr).into(),
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&fetch), host_addr).await.unwrap();

    // Host connects to hbbs over TCP to send LocalAddr.
    let (stream, _) = timeout(LIMIT, tcp.accept()).await.unwrap().unwrap();
    let mut hbbs_wire = wire(stream);
    let Some(rendezvous_message::Union::LocalAddr(local)) = control(&mut hbbs_wire).await.union
    else {
        panic!("Expected LocalAddr");
    };
    let reported = AddrMangle::decode(&local.local_addr);
    assert_ne!(reported.port(), 0);

    // Prepare-before-announce invariant (F08):
    // The controller connects ONCE immediately with NO retry loop. It MUST succeed.
    let dialed = TcpStream::connect(reported)
        .await
        .expect("Listener must be ready immediately before LocalAddr was announced");

    let route = timeout(LIMIT, route_rx.recv()).await.unwrap().unwrap();
    assert_eq!(route.kind, HostRouteKind::Local);
    assert_eq!(route.peer, dialed.local_addr().unwrap());

    cancel.cancel();
    assert!(worker.await.unwrap().is_ok());
}

#[tokio::test]
async fn tcp_punch_preserves_observed_source_mapping_and_hands_off_stream() {
    let (udp, tcp, port) = hbbs().await;
    let (host_pk, _) = sign::gen_keypair();
    let (states, mut state_rx) = state_channel();
    let (routes, mut route_rx) = mpsc::channel(4);
    let cancel = CancellationToken::new();
    let worker = tokio::spawn(run_host_registration(
        registration_config(port, None, host_pk, "host01"),
        cancel.clone(),
        states,
        routes,
    ));

    // Complete registration
    let (_, host_addr) = datagram(&udp).await;
    let mut req_pk = RendezvousMessage::new();
    req_pk.set_register_peer_response(RegisterPeerResponse {
        request_pk: true,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&req_pk), host_addr).await.unwrap();
    let _ = datagram(&udp).await;
    let mut ok_res = RendezvousMessage::new();
    ok_res.set_register_pk_response(RegisterPkResponse {
        result: register_pk_response::Result::OK.into(),
        keep_alive: 30,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&ok_res), host_addr).await.unwrap();
    await_state(
        &mut state_rx,
        RegistrationState::Observed { keep_alive_raw: 30 },
    )
    .await;

    let controller_addr: SocketAddr = "127.0.0.1:33333".parse().unwrap();
    let mut punch = RendezvousMessage::new();
    punch.set_punch_hole(PunchHole {
        socket_addr: AddrMangle::encode(controller_addr).into(),
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&punch), host_addr).await.unwrap();

    // Host connects to hbbs over TCP to send PunchHoleSent.
    let (stream, host_tcp_origin) = timeout(LIMIT, tcp.accept()).await.unwrap().unwrap();
    let mut hbbs_wire = wire(stream);
    let Some(rendezvous_message::Union::PunchHoleSent(sent)) = control(&mut hbbs_wire).await.union
    else {
        panic!("Expected PunchHoleSent");
    };

    // Server-derived transformations:
    // 1. Version is non-empty (S:1234-1257); we assert non-empty, not a fixed string.
    assert!(
        !sent.version.is_empty(),
        "Version must be non-empty to gate signature"
    );
    assert_eq!(sent.id, "host01");

    // 2. Observed source mapping (S:637-668):
    // Server observes the TCP source address of host's connection.
    // Host listener is bound on that exact port. Controller connects directly to that port.
    let mut controller_wire = wire(
        TcpStream::connect(host_tcp_origin)
            .await
            .expect("Host punch listener must be waiting on observed source port"),
    );

    let mut route = timeout(LIMIT, route_rx.recv()).await.unwrap().unwrap();
    assert_eq!(route.kind, HostRouteKind::TcpHolePunch);

    // 3. Unread stream handoff: controller writes first record, host reads it.
    let mut test_probe = Message::new();
    test_probe.set_hash(Hash {
        salt: "punch-salt".into(),
        challenge: "punch-challenge".into(),
        ..Default::default()
    });
    controller_wire.send(&test_probe).await.unwrap();

    let received = Message::parse_from_bytes(
        &timeout(LIMIT, route.stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(received, test_probe);

    cancel.cancel();
    assert!(worker.await.unwrap().is_ok());
}

#[tokio::test]
async fn hbbr_pairing_survives_duplicate_requests_and_preserves_first_records() {
    let (udp, tcp, port) = hbbs().await;
    let (host_pk, _) = sign::gen_keypair();

    // Fake HBBR pairing oracle modeling R:461-498:
    // Holds connections by UUID; when second peer arrives with matching UUID and licence_key,
    // bridges raw byte streams bidirectionally without sending any artificial ACK.
    let hbbr_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_port = hbbr_listener.local_addr().unwrap().port();

    let pending_peers: Arc<Mutex<HashMap<String, FramedStream>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let pending_clone = pending_peers.clone();

    tokio::spawn(async move {
        while let Ok((stream, _)) = hbbr_listener.accept().await {
            let mut wire = wire(stream);
            let Some(rendezvous_message::Union::RequestRelay(req)) = control(&mut wire).await.union
            else {
                continue;
            };
            if req.licence_key != "wire-key-auth" || req.uuid.is_empty() {
                continue;
            }
            let mut lock = pending_clone.lock().await;
            if let Some(peer_wire) = lock.remove(&req.uuid) {
                // Both peers joined on same UUID! Bridge them bidirectionally.
                tokio::spawn(async move {
                    let mut first = wire.0.into_parts();
                    let mut second = peer_wire.0.into_parts();
                    // A join read may also buffer the first peer record. Preserve
                    // those bytes before switching the paired streams to raw relay.
                    assert!(first.write_buf.is_empty());
                    assert!(second.write_buf.is_empty());
                    tokio::try_join!(
                        first.io.write_all(&second.read_buf),
                        second.io.write_all(&first.read_buf),
                    )
                    .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut first.io, &mut second.io).await;
                });
            } else {
                lock.insert(req.uuid, wire);
            }
        }
    });

    let (states, mut state_rx) = state_channel();
    let (routes, mut route_rx) = mpsc::channel(4);
    let cancel = CancellationToken::new();
    let worker = tokio::spawn(run_host_registration(
        registration_config(port, Some(relay_port), host_pk, "host01"),
        cancel.clone(),
        states,
        routes,
    ));

    // Register
    let (_, host_addr) = datagram(&udp).await;
    let mut req_pk = RendezvousMessage::new();
    req_pk.set_register_peer_response(RegisterPeerResponse {
        request_pk: true,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&req_pk), host_addr).await.unwrap();
    let _ = datagram(&udp).await;
    let mut ok_res = RendezvousMessage::new();
    ok_res.set_register_pk_response(RegisterPkResponse {
        result: register_pk_response::Result::OK.into(),
        keep_alive: 30,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&ok_res), host_addr).await.unwrap();
    await_state(
        &mut state_rx,
        RegistrationState::Observed { keep_alive_raw: 30 },
    )
    .await;

    let controller_addr: SocketAddr = "127.0.0.1:44332".parse().unwrap();
    let pairing_uuid = "pairing-uuid-mutual-99";

    // Controller sends RequestRelay via UDP to host.
    let mut req = RendezvousMessage::new();
    req.set_request_relay(RequestRelay {
        id: "host01".into(),
        uuid: pairing_uuid.into(),
        socket_addr: AddrMangle::encode(controller_addr).into(),
        relay_server: format!("127.0.0.1:{relay_port}"),
        conn_type: ConnType::DEFAULT_CONN.into(),
        control_permissions: MessageField::some(ControlPermissions {
            permissions: 0b101,
            ..Default::default()
        }),
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&req), host_addr).await.unwrap();

    // Host connects to hbbs to announce positive RelayResponse.
    let (stream, _) = timeout(LIMIT, tcp.accept()).await.unwrap().unwrap();
    let mut hbbs_wire = wire(stream);
    let Some(rendezvous_message::Union::RelayResponse(resp)) = control(&mut hbbs_wire).await.union
    else {
        panic!("Expected RelayResponse");
    };
    assert!(resp.refuse_reason.is_empty());
    assert_eq!(resp.uuid, pairing_uuid);

    // Host produced IncomingHostRoute.
    let (mut host_stream, permissions, requirements) = {
        let host_route = timeout(LIMIT, route_rx.recv()).await.unwrap().unwrap();
        assert_eq!(host_route.kind, HostRouteKind::Relay);
        assert_eq!(host_route.permissions, Some(0b101));
        (
            host_route.stream,
            host_route.permissions,
            host_route.requirements,
        )
    };

    // Reservation must outlive the acquisition task and the route envelope.
    // An identical replay must not pair the host with another copy of itself.
    udp.send_to(&wire_bytes(&req), host_addr).await.unwrap();
    assert!(
        timeout(Duration::from_millis(300), route_rx.recv())
            .await
            .is_err()
    );

    // hbbr pairs by UUID, not controller/permission metadata. A changed envelope
    // must not create another join or widen the first admitted route's ceiling.
    if let Some(rendezvous_message::Union::RequestRelay(replay)) = req.union.as_mut() {
        replay.socket_addr = AddrMangle::encode("127.0.0.1:44333".parse().unwrap()).into();
        replay.control_permissions = MessageField::some(ControlPermissions {
            permissions: u64::MAX,
            ..Default::default()
        });
        replay.secure = true;
        replay.controlled_context =
            MessageField::some(hbb_common::rendezvous_proto::ControlledContext {
                conn_audit_ref: "contradictory-context".into(),
                ..Default::default()
            });
    }
    udp.send_to(&wire_bytes(&req), host_addr).await.unwrap();
    assert!(
        timeout(Duration::from_millis(300), route_rx.recv())
            .await
            .is_err()
    );
    assert_eq!(permissions, Some(0b101));
    assert!(!requirements.secure);
    assert!(requirements.conn_audit_ref.is_none());

    // Now controller connects to hbbr on the same pairing UUID.
    let controller_stream = TcpStream::connect(format!("127.0.0.1:{relay_port}"))
        .await
        .unwrap();
    let mut controller_wire = wire(controller_stream);
    let mut join_req = RendezvousMessage::new();
    join_req.set_request_relay(RequestRelay {
        uuid: pairing_uuid.into(),
        licence_key: "wire-key-auth".into(),
        ..Default::default()
    });
    controller_wire.send(&join_req).await.unwrap();

    // Forwarding first records:
    // 1. Controller sends first record -> Host receives it.
    let mut msg_from_controller = Message::new();
    msg_from_controller.set_hash(Hash {
        salt: "c-salt".into(),
        challenge: "c-challenge".into(),
        ..Default::default()
    });
    controller_wire.send(&msg_from_controller).await.unwrap();

    let host_recv = Message::parse_from_bytes(
        &timeout(LIMIT, host_stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(host_recv, msg_from_controller);

    // 2. Host sends record -> Controller receives it.
    let mut msg_from_host = Message::new();
    msg_from_host.set_test_delay(Default::default());
    host_stream.send(&msg_from_host).await.unwrap();

    let controller_recv = Message::parse_from_bytes(
        &timeout(LIMIT, controller_wire.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(controller_recv, msg_from_host);

    cancel.cancel();
    assert!(worker.await.unwrap().is_ok());
}

#[tokio::test]
async fn closed_route_consumer_stops_worker_promptly() {
    let (_udp, _tcp, port) = hbbs().await;
    let (host_pk, _) = sign::gen_keypair();
    let (states, mut state_rx) = state_channel();
    let (routes, route_rx) = mpsc::channel(4);
    let cancel = CancellationToken::new();

    // Drop the route consumer immediately (F06).
    drop(route_rx);

    let worker = tokio::spawn(run_host_registration(
        registration_config(port, None, host_pk, "host01"),
        cancel.clone(),
        states,
        routes,
    ));

    // Worker must terminate immediately with BrokenPipe and Stopped(ConsumerClosed).
    let res = worker.await.unwrap();
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(
        *state_rx.borrow_and_update(),
        RegistrationState::Stopped(StopReason::ConsumerClosed)
    );
}

#[tokio::test]
async fn cancellation_stops_registration_and_retires_tasks() {
    let (udp, _tcp, port) = hbbs().await;
    let (host_pk, _) = sign::gen_keypair();
    let (states, mut state_rx) = state_channel();
    let (routes, _route_rx) = mpsc::channel(4);
    let cancel = CancellationToken::new();

    let worker = tokio::spawn(run_host_registration(
        registration_config(port, None, host_pk, "host01"),
        cancel.clone(),
        states,
        routes,
    ));

    let (_, host_addr) = datagram(&udp).await;
    let mut req_pk = RendezvousMessage::new();
    req_pk.set_register_peer_response(RegisterPeerResponse {
        request_pk: true,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&req_pk), host_addr).await.unwrap();
    let _ = datagram(&udp).await;
    let mut ok_res = RendezvousMessage::new();
    ok_res.set_register_pk_response(RegisterPkResponse {
        result: register_pk_response::Result::OK.into(),
        keep_alive: 30,
        ..Default::default()
    });
    udp.send_to(&wire_bytes(&ok_res), host_addr).await.unwrap();
    await_state(
        &mut state_rx,
        RegistrationState::Observed { keep_alive_raw: 30 },
    )
    .await;

    // Fire cancel token.
    cancel.cancel();
    assert!(worker.await.unwrap().is_ok());
    assert_eq!(
        *state_rx.borrow_and_update(),
        RegistrationState::Stopped(StopReason::Cancelled)
    );
}

#[tokio::test]
async fn presence_reads_msb_first_bits_and_refuses_short_answer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peers = [
        "peer01", "peer02", "peer03", "peer04", "peer05", "peer06", "peer07", "peer08", "peer09",
    ];
    let server = tokio::spawn(async move {
        // First query: 0, 4, 8 online -> 0b1000_1000, 0b1000_0000.
        let (stream, _) = listener.accept().await.unwrap();
        let mut first_wire = wire(stream);
        let Some(rendezvous_message::Union::OnlineRequest(req)) =
            control(&mut first_wire).await.union
        else {
            panic!("Expected OnlineRequest");
        };
        assert_eq!(req.id, "host01");
        assert_eq!(req.peers, peers);
        let mut answer = RendezvousMessage::new();
        answer.set_online_response(OnlineResponse {
            states: Bytes::from_static(&[0b1000_1000, 0b1000_0000]),
            ..Default::default()
        });
        first_wire.send(&answer).await.unwrap();

        // Second query: truncated response (1 byte instead of 2).
        let (stream, _) = listener.accept().await.unwrap();
        let mut second_wire = wire(stream);
        let _ = control(&mut second_wire).await;
        let mut short = RendezvousMessage::new();
        short.set_online_response(OnlineResponse {
            states: Bytes::from_static(&[0b1000_1000]),
            ..Default::default()
        });
        second_wire.send(&short).await.unwrap();
    });

    let query = || PresenceConfig {
        endpoint: format!("127.0.0.1:{port}"),
        local_id: "host01".into(),
        peers: peers.iter().map(|p| p.to_string()).collect(),
        timeout: LIMIT,
    };

    assert_eq!(
        query_presence(query()).await.unwrap(),
        vec![
            PresenceState::Online,
            PresenceState::Offline,
            PresenceState::Offline,
            PresenceState::Offline,
            PresenceState::Online,
            PresenceState::Offline,
            PresenceState::Offline,
            PresenceState::Offline,
            PresenceState::Online,
        ]
    );

    assert_eq!(
        query_presence(query()).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );

    server.await.unwrap();
}

#[tokio::test]
async fn presence_strictly_requires_single_online_response_without_key_exchange_skip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut wire = wire(stream);
        let _ = control(&mut wire).await;

        // Server attempts to inject a KeyExchange before OnlineResponse.
        // S01: presence must NOT skip KeyExchange; it must reject unexpected message immediately.
        let mut kx = RendezvousMessage::new();
        kx.set_key_exchange(Default::default());
        wire.send(&kx).await.unwrap();
    });

    let res = query_presence(PresenceConfig {
        endpoint: format!("127.0.0.1:{port}"),
        local_id: "host01".into(),
        peers: vec!["peer01".into()],
        timeout: LIMIT,
    })
    .await;

    assert!(res.is_err());
    assert_eq!(res.unwrap_err().kind(), io::ErrorKind::InvalidData);
    server.await.unwrap();
}
