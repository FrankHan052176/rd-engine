//! Standalone viewer client for interop runs against real hosts.
//!
//! usage: rd-engine-viewer <ip:port> [password] [seconds]
//!
//! Connects with the engine's viewer role, authenticates, requests video and
//! reports what actually arrived. It renders nothing and records no pixels; its
//! purpose is a repeatable client-side check against unmodified peers.
use hbb_common::message_proto::{
    self as proto, LoginRequest, Message, Misc, OptionMessage, SupportedDecoding, message, misc,
    option_message::BoolOption, supported_decoding::PreferCodec, video_frame,
};
use rd_engine::{
    handshake::ViewerIdentity,
    session::{ViewerEvent, ViewerSession},
};
use std::{error::Error, net::SocketAddr, time::Duration};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let address: SocketAddr = args
        .next()
        .ok_or("usage: rd-engine-viewer <ip:port> [password] [seconds]")?
        .parse()?;
    let password = args.next();
    let seconds: u64 = args
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(20);

    let connected_at = tokio::time::Instant::now();
    let mut session = ViewerSession::connect_direct(
        address,
        ViewerIdentity::LegacyUnverified,
        Duration::from_secs(120),
    )
    .await?;
    println!("transport connected to {address}");

    let request = LoginRequest {
        username: address.ip().to_string(),
        my_id: "rd-engine-viewer".into(),
        my_name: "rd-engine viewer".into(),
        my_platform: std::env::consts::OS.into(),
        version: "1.4.9".into(),
        session_id: 1,
        option: Some(OptionMessage {
            supported_decoding: Some(SupportedDecoding {
                ability_h264: 1,
                ability_h265: 1,
                prefer: PreferCodec::H265.into(),
                prefer_chroma: proto::Chroma::I420.into(),
                ..Default::default()
            })
            .into(),
            custom_fps: 60,
            disable_keyboard: BoolOption::Yes.into(),
            disable_clipboard: BoolOption::Yes.into(),
            disable_audio: BoolOption::Yes.into(),
            enable_file_transfer: BoolOption::No.into(),
            disable_camera: BoolOption::Yes.into(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };

    loop {
        match session.recv().await? {
            ViewerEvent::Challenge => {
                println!(
                    "password challenge received; replying {}",
                    if password.is_some() {
                        "with credential"
                    } else {
                        "without credential"
                    }
                );
                session
                    .login(request.clone(), password.as_deref().map(str::as_bytes))
                    .await?
            }
            ViewerEvent::LoginError(error) if error == "No Password Access" => {
                println!("awaiting explicit approval on the peer")
            }
            ViewerEvent::LoginError(error) => return Err(error.into()),
            ViewerEvent::Authorized(info) => {
                println!("auth_ms={}", connected_at.elapsed().as_millis());
                let display = info.displays.first();
                println!(
                    "authorized: peer={} platform={} display={}x{}",
                    info.username,
                    info.platform,
                    display.map(|d| d.width).unwrap_or_default(),
                    display.map(|d| d.height).unwrap_or_default()
                );
                break;
            }
            ViewerEvent::Closed => return Err("peer closed before authorization".into()),
            _ => {}
        }
    }

    let mut parts = session.into_authenticated_parts()?;
    let mut refresh = Message::new();
    let mut misc_message = Misc::new();
    misc_message.set_refresh_video(true);
    refresh.set_misc(misc_message);
    parts.writer.send(&refresh).await?;
    let refresh_at = tokio::time::Instant::now();
    let mut first_frame_ms: Option<u128> = None;
    let mut previous_frame_at: Option<tokio::time::Instant> = None;
    let (mut gap_min, mut gap_max, mut gap_sum, mut gap_count) = (f64::MAX, 0.0f64, 0.0f64, 0usize);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    let (mut frame_count, mut key_count, mut encoded_bytes) = (0usize, 0usize, 0usize);
    let mut first: Option<String> = None;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let incoming = match tokio::time::timeout(remaining, parts.reader.recv()).await {
            Ok(Ok(Some(message))) => message,
            Ok(Ok(None)) => {
                println!("peer closed the session");
                break;
            }
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => break,
        };
        match incoming.union {
            Some(message::Union::VideoFrame(frame)) => {
                let units = match frame.union {
                    Some(video_frame::Union::H264s(frames)) => Some(("H264", frames)),
                    Some(video_frame::Union::H265s(frames)) => Some(("H265", frames)),
                    _ => None,
                };
                if let Some((codec, frames)) = units {
                    if first_frame_ms.is_none() {
                        first_frame_ms = Some(refresh_at.elapsed().as_millis());
                    }
                    if let Some(previous) = previous_frame_at {
                        let gap = previous.elapsed().as_secs_f64() * 1000.0;
                        gap_min = gap_min.min(gap);
                        gap_max = gap_max.max(gap);
                        gap_sum += gap;
                        gap_count += 1;
                    }
                    previous_frame_at = Some(tokio::time::Instant::now());
                    for unit in &frames.frames {
                        frame_count += 1;
                        encoded_bytes += unit.data.len();
                        if unit.key {
                            key_count += 1;
                        }
                        if first.is_none() {
                            first = Some(format!(
                                "codec={codec} key={} bytes={} pts={}",
                                unit.key,
                                unit.data.len(),
                                unit.pts
                            ));
                        }
                    }
                }
            }
            Some(message::Union::TestDelay(probe)) if !probe.from_client => {
                let mut response = Message::new();
                response.set_test_delay(probe);
                parts.writer.send(&response).await?;
            }
            Some(message::Union::Misc(m)) if matches!(m.union, Some(misc::Union::CloseReason(_))) => {
                println!("peer closed the session");
                break;
            }
            _ => {}
        }
    }

    match first {
        Some(first) => println!(
            "media: {first} | frames={frame_count} key={key_count} encoded_bytes={encoded_bytes}"
        ),
        None => println!("media: none received within {seconds}s"),
    }
    if let Some(first_frame_ms) = first_frame_ms {
        let average = gap_sum / gap_count.max(1) as f64;
        println!(
            "timing: first_frame_ms={first_frame_ms} gap_ms min={:.2} avg={:.2} max={:.2} samples={gap_count}",
            if gap_min == f64::MAX { 0.0 } else { gap_min },
            average,
            gap_max
        );
    }
    let mut close = Message::new();
    let mut reason = Misc::new();
    reason.set_close_reason(String::new());
    close.set_misc(reason);
    let _ = parts.writer.send(&close).await;
    Ok(())
}
