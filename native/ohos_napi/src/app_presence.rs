//! App-scoped, bounded RustDesk presence query (the hbbs `OnlineRequest`).
//!
//! `rd_engine::rendezvous::query_presence` is the engine's own implementation of
//! this exchange, but it is async and drives the engine executor, which this HAR
//! crate cannot reach; a second Tokio runtime is not permitted here. This module
//! therefore reuses the pinned wire types (`hbb_common::rendezvous_proto`) and the
//! pinned frame codec (`hbb_common::bytes_codec::BytesCodec`) over a bounded
//! blocking socket instead of re-implementing the protocol.
//!
//! It is not discovery: a peer is reported online only when the service's
//! `OnlineResponse` says so for that exact id. A LAN scan, a stored address or a
//! previously visible peer never becomes an online claim, and every failure is a
//! failure rather than an empty online list.
use super::{
    app_context::{admit_presence, cancel_presence, PresenceAdmission},
    server_profile::{ServerProfile, MAX_SAFE_REVISION},
};
use hbb_common::{
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    protobuf::Message as _,
    rendezvous_proto::{rendezvous_message, OnlineRequest, RendezvousMessage},
    tokio_util::codec::{Decoder as _, Encoder as _},
};
use napi_derive_ohos::napi;
use napi_ohos::{
    bindgen_prelude::{AsyncTask, Task},
    Env,
};
use serde_json::{json, Value};
use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

/// Original NAT/presence listener port answering `OnlineRequest`.
const PRESENCE_PORT: u16 = 21115;
/// Pinned server profile's minimum id length.
const MIN_ID_BYTES: usize = 6;
const MAX_ID_BYTES: usize = 512;
const MAX_PEERS: usize = 4096;
const MAX_REQUEST_BYTES: usize = 256 * 1024;
/// Whole-query ceiling, including DNS, connect, write and the single record.
const QUERY_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest record this query accepts from the endpoint.
const MAX_RECORD_BYTES: usize = 64 * 1024;
/// Read slice, so a cancellation can be observed while a socket read waits.
const READ_SLICE: Duration = Duration::from_millis(250);
const MAX_ADDRESSES: usize = 2;

fn error_text(previous: Option<String>, next: String) -> String {
    match previous {
        Some(previous) if previous != next => format!("{previous}; {next}"),
        Some(previous) => previous,
        None => next,
    }
}

fn refusal(generation: &str, error: &str) -> Value {
    json!({
        "ok": false,
        "action": "peer_query_online",
        "queryGeneration": generation,
        "online": [],
        "offline": [],
        "message": "",
        "error": error,
    })
}

fn token(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|number| *number != 0 && number.to_string() == value)
        .ok_or_else(|| "invalid presence query generation".to_string())
}

/// The pinned server profile grammar: the first byte is alphanumeric and the
/// rest are alphanumeric, `_`, `-` or `.`. Peer ids carry no minimum length in
/// the engine's own presence preflight; the local id does.
fn valid_peer_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_BYTES
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'.')
}

fn valid_local_id(id: &str) -> bool {
    id.len() >= MIN_ID_BYTES && valid_peer_id(id)
}

fn parse_ids(ids_json: &str) -> Result<Vec<String>, String> {
    if ids_json.len() > MAX_REQUEST_BYTES {
        return Err("peer id list is larger than this layer accepts".to_string());
    }
    let value: Value = serde_json::from_str(ids_json)
        .map_err(|_| "peer id list must be a JSON array".to_string())?;
    let entries = value
        .as_array()
        .ok_or_else(|| "peer id list must be a JSON array".to_string())?;
    if entries.is_empty() || entries.len() > MAX_PEERS {
        return Err(format!("peer id list must hold 1..={MAX_PEERS} ids"));
    }
    let mut peers = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(id) = entry.as_str() else {
            return Err("peer id list must hold strings".to_string());
        };
        if !valid_peer_id(id) {
            return Err("peer id list holds an id this wire does not accept".to_string());
        }
        peers.push(id.to_string());
    }
    Ok(peers)
}

/// The presence service listens on its own port of the same hbbs host. The saved
/// profile normalizes the control endpoint with its own port, so the host is
/// taken from it and re-normalized with the presence port; this is still the
/// endpoint the approved profile names, not a caller-chosen probe target.
fn presence_endpoint(id_server: &str) -> Result<String, String> {
    let (host, _) = id_server
        .rsplit_once(':')
        .ok_or_else(|| "the approved server endpoint has no port".to_string())?;
    if host.is_empty() {
        return Err("the approved server endpoint has an empty host".to_string());
    }
    rd_engine::rendezvous::endpoint(&format!("{host}:{PRESENCE_PORT}"), PRESENCE_PORT)
        .map_err(|error| error.to_string())
}

fn approve(profile_json: &str) -> Result<String, String> {
    if profile_json.len() > MAX_REQUEST_BYTES {
        return Err("server profile JSON is larger than this layer accepts".to_string());
    }
    let value: Value = serde_json::from_str(profile_json)
        .map_err(|_| "server profile must be a JSON object".to_string())?;
    if value.get("schemaVersion").and_then(Value::as_u64) != Some(2)
        || value.get("approval").and_then(Value::as_str) != Some("explicit-save")
        || !value
            .get("revision")
            .and_then(Value::as_u64)
            .is_some_and(|revision| (1..=MAX_SAFE_REVISION).contains(&revision))
    {
        return Err(
            "a presence query requires an explicitly saved, approved server profile".to_string(),
        );
    }
    let profile = ServerProfile::parse(&value)?;
    presence_endpoint(profile.id_server())
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("presence query timed out".to_string());
    }
    Ok(remaining)
}

fn connect(name: &str, deadline: Instant) -> Result<TcpStream, String> {
    let addresses = name
        .to_socket_addrs()
        .map_err(|error| format!("presence address resolution failed: {error}"))?;
    let mut last = None;
    for address in addresses.take(MAX_ADDRESSES) {
        let budget = remaining(deadline)?;
        match TcpStream::connect_timeout(&address, budget) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(error) => last = Some(error),
        }
    }
    match last {
        Some(error) => Err(format!("presence connect failed: {error}")),
        None => Err("presence address resolution returned no address".to_string()),
    }
}

fn encode_request(local_id: &str, peers: &[String]) -> Result<Vec<u8>, String> {
    let mut request = RendezvousMessage::new();
    request.set_online_request(OnlineRequest {
        id: local_id.to_owned(),
        peers: peers.to_vec(),
        ..Default::default()
    });
    request
        .write_to_bytes()
        .map_err(|_| "cannot encode the presence request".to_string())
}

fn write_frame(stream: &mut TcpStream, payload: &[u8], deadline: Instant) -> Result<(), String> {
    if payload.len() > MAX_RECORD_BYTES {
        return Err("presence request is larger than this layer accepts".to_string());
    }
    let mut codec = BytesCodec::new();
    let mut buffer = BytesMut::new();
    codec
        .encode(Bytes::copy_from_slice(payload), &mut buffer)
        .map_err(|_| "cannot frame the presence request".to_string())?;
    stream
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|error| format!("presence socket write timeout failed: {error}"))?;
    stream
        .write_all(&buffer)
        .map_err(|error| format!("presence request write failed: {error}"))
}

fn read_frame(
    stream: &mut TcpStream,
    deadline: Instant,
    admission: &PresenceAdmission,
) -> Result<Vec<u8>, String> {
    let mut codec = BytesCodec::new();
    codec.set_max_packet_length(MAX_RECORD_BYTES);
    let mut buffer = BytesMut::new();
    let mut chunk = [0u8; 4096];
    loop {
        if admission.cancelled() {
            return Err("presence query was cancelled".to_string());
        }
        if let Some(frame) = codec
            .decode(&mut buffer)
            .map_err(|_| "invalid presence record".to_string())?
        {
            return Ok(frame.to_vec());
        }
        let slice = remaining(deadline)?.min(READ_SLICE);
        stream
            .set_read_timeout(Some(slice))
            .map_err(|error| format!("presence socket read timeout failed: {error}"))?;
        match stream.read(&mut chunk) {
            Ok(0) => return Err("presence service closed the connection".to_string()),
            Ok(read) => {
                if buffer.len() + read > MAX_RECORD_BYTES + 4 {
                    return Err("presence record is larger than this layer accepts".to_string());
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(format!("presence read failed: {error}")),
        }
    }
}

/// Strict single-record `OnlineResponse`, exactly as the engine's own presence
/// query validates it. Any other message, a short answer or a wrong count is a
/// failure, never an offline or online guess.
fn decode_response(record: &[u8], count: usize) -> Result<Vec<bool>, String> {
    let message = RendezvousMessage::parse_from_bytes(record)
        .map_err(|_| "invalid presence message".to_string())?;
    let Some(rendezvous_message::Union::OnlineResponse(response)) = message.union else {
        return Err("presence service answered a different message".to_string());
    };
    let required = count.div_ceil(8);
    if response.states.len() != required {
        return Err("presence answer does not match the query".to_string());
    }
    Ok((0..count)
        .map(|index| response.states[index / 8] & (1u8 << (7 - index % 8)) != 0)
        .collect())
}

fn query(
    admission: &PresenceAdmission,
    endpoint: &str,
    peers: &[String],
) -> Result<Vec<bool>, String> {
    if !valid_local_id(&admission.local_id) {
        return Err("the local id is not a valid RustDesk id".to_string());
    }
    if admission.cancelled() {
        return Err("presence query was cancelled".to_string());
    }
    let deadline = Instant::now() + QUERY_TIMEOUT;
    let mut stream = connect(endpoint, deadline)?;
    let request = encode_request(&admission.local_id, peers)?;
    write_frame(&mut stream, &request, deadline)?;
    let record = read_frame(&mut stream, deadline, admission)?;
    decode_response(&record, peers.len())
}

/// One admitted presence query. The endpoint and peer list are fixed at
/// admission; the worker only performs the bounded exchange.
pub struct PresenceWork {
    admission: Option<PresenceAdmission>,
    endpoint: Option<String>,
    peers: Vec<String>,
    error: Option<String>,
}

pub struct PresenceOutput {
    document: String,
    generation: String,
}

impl PresenceWork {
    fn refused(error: String) -> Self {
        Self {
            admission: None,
            endpoint: None,
            peers: Vec::new(),
            error: Some(error),
        }
    }

    fn run(&mut self) -> Value {
        let Some(admission) = self.admission.as_ref() else {
            return refusal(
                "",
                self.error
                    .as_deref()
                    .unwrap_or("presence query was not admitted"),
            );
        };
        let generation = admission.generation.to_string();
        let mut failure = self.error.clone();
        if let Err(error) = admission.check() {
            failure = Some(error_text(failure, error));
        }
        let outcome = if failure.is_some() {
            Err(failure.clone().unwrap_or_default())
        } else if admission.cancelled() {
            Err("presence query was cancelled".to_string())
        } else {
            match self.endpoint.as_deref() {
                Some(endpoint) => query(admission, endpoint, &self.peers),
                None => Err("presence query has no admitted endpoint".to_string()),
            }
        };
        // The slot is released by the worker itself, including on failure, so an
        // abandoned promise cannot hold the admission.
        admission.finish();
        match outcome {
            Ok(states) => {
                let mut online = Vec::new();
                let mut offline = Vec::new();
                for (index, state) in states.into_iter().enumerate() {
                    if state {
                        online.push(self.peers[index].clone());
                    } else {
                        offline.push(self.peers[index].clone());
                    }
                }
                json!({
                    "ok": true,
                    "action": "peer_query_online",
                    "queryGeneration": generation,
                    "online": online,
                    "offline": offline,
                    "message": format!(
                        "the presence service answered OnlineResponse for {} peer(s)",
                        self.peers.len()
                    ),
                })
            }
            Err(error) => refusal(&generation, &error_text(failure, error)),
        }
    }
}

impl Task for PresenceWork {
    type Output = PresenceOutput;
    type JsValue = String;

    fn compute(&mut self) -> napi_ohos::Result<Self::Output> {
        let generation = self
            .admission
            .as_ref()
            .map(|admission| admission.generation.to_string())
            .unwrap_or_default();
        let document = self.run().to_string();
        Ok(PresenceOutput {
            document,
            generation,
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi_ohos::Result<Self::JsValue> {
        let Some(admission) = self.admission.as_ref() else {
            return Ok(output.document);
        };
        // The worker already released its slot; this only re-checks the app
        // generation, so an answer produced across a fence is never reported.
        if let Err(error) = admission.fenced() {
            return Ok(refusal(&output.generation, &error).to_string());
        }
        Ok(output.document)
    }
}

fn admit(ids_json: &str, profile_json: &str) -> PresenceWork {
    let admitted = (|| -> Result<(Vec<String>, String), String> {
        let peers = parse_ids(ids_json)?;
        let endpoint = approve(profile_json)?;
        Ok((peers, endpoint))
    })();
    match admitted {
        Ok((peers, endpoint)) => match admit_presence() {
            Ok(admission) => PresenceWork {
                admission: Some(admission),
                endpoint: Some(endpoint),
                peers,
                error: None,
            },
            Err(error) => PresenceWork::refused(error),
        },
        Err(error) => PresenceWork::refused(error),
    }
}

/// Asks hbbs whether the listed peer ids are online.
///
/// The second argument is the explicitly saved, approved server profile (the
/// same envelope `sessionAdd` accepts); without it no endpoint is probed. `ok`
/// is true only when the service answered `OnlineResponse`; `online` holds
/// exactly the ids that answer marked present, and everything else is `offline`
/// or an error. A LAN scan, a stored address or a session's own progress never
/// appears here.
#[napi(ts_return_type = "Promise<string>")]
pub fn peer_query_online(ids_json: String, profile_json: String) -> AsyncTask<PresenceWork> {
    AsyncTask::new(admit(&ids_json, &profile_json))
}

/// Cancels the exact admitted query, observed between bounded read slices.
#[napi]
pub fn peer_presence_cancel(query_generation: String) -> String {
    let answer = token(&query_generation).and_then(cancel_presence);
    match answer {
        Ok(cancelled) => json!({ "ok": true, "cancelled": cancelled }).to_string(),
        Err(error) => json!({ "ok": false, "cancelled": false, "error": error }).to_string(),
    }
}
