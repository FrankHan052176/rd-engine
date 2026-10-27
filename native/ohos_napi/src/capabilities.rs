//! ArkTS-facing decoder capability evidence, produced off the JS/UI thread.
//!
//! A thin conversion over `rd_engine::media_capability`: the engine's two real
//! hardware decoder metadata queries, copied into one JSON document for the
//! client. The engine documents that the platform may perform IPC while it
//! answers them, so the queries run inside a napi async-work task (`compute`
//! leaves the JS/UI thread) and the promise resolves with that document.
//!
//! This layer creates no codec, capture or session object, keeps no cache —
//! every call re-queries the platform — and measures nothing. It serializes
//! what the platform advertises, including the error of every field the
//! platform refused to answer, so a nested failure cannot read as a default.

use napi_derive_ohos::napi;
use napi_ohos::bindgen_prelude::{AsyncTask, Task};
use rd_engine::media_capability::{
    AdvertisedCodec, AdvertisedSizeRate, CapabilityError, CodecDirection,
};

/// The one label every value in the document carries: this is what the platform
/// advertises, not what it was measured doing. The advertised frame rates below
/// are the platform's own claims and must never be shown as throughput.
const EVIDENCE: &str = "advertised_metadata";

/// The engine calls that produce the document. Both calls query decoder
/// metadata only; no encoder capability is computed for this consumer.
const SOURCE: &str = "rd_engine::media_capability::{query_h264_hardware_decoder, query_hevc_hardware_decoder}";

/// Direction of a codec a query asked for.
fn direction_name(direction: CodecDirection) -> &'static str {
    match direction {
        CodecDirection::Encode => "encode",
        CodecDirection::Decode => "decode",
    }
}

/// The engine's own failure, named by its local variant so the client keys on a
/// stable string. `native` keeps the platform API and its numeric code; the
/// other variants carry the facts they own, and nothing is invented to fill a
/// shape.
fn error_json(error: &CapabilityError) -> serde_json::Value {
    match error {
        CapabilityError::UnsupportedPlatform => serde_json::json!({
            "kind": "unsupported_platform",
        }),
        CapabilityError::NoHardwareCapability { direction } => serde_json::json!({
            "kind": "no_hardware_capability",
            "direction": direction_name(*direction),
        }),
        CapabilityError::Native { api, code } => serde_json::json!({
            "kind": "native",
            "api": *api,
            "code": *code,
        }),
        CapabilityError::InvalidNativeResult { api } => serde_json::json!({
            "kind": "invalid_native_result",
            "api": *api,
        }),
        CapabilityError::UnexpectedSoftwareCodec => serde_json::json!({
            "kind": "unexpected_software_codec",
        }),
        CapabilityError::QueryLockPoisoned => serde_json::json!({
            "kind": "query_lock_poisoned",
        }),
    }
}

/// One metadata field of a codec the platform did answer for: `ok` is what
/// separates a value the platform returned from the error that replaced it.
fn field(result: Result<serde_json::Value, CapabilityError>) -> serde_json::Value {
    match result {
        Ok(value) => serde_json::json!({ "ok": true, "value": value }),
        Err(error) => serde_json::json!({ "ok": false, "error": error_json(&error) }),
    }
}

/// Main10 levels are three-way: the advertised levels, "this codec does not
/// advertise Main10", and "the query failed". A bare null would make the middle
/// case and the failure share one value, so each case is named.
fn main10_levels_json(result: Result<Option<Vec<i32>>, CapabilityError>) -> serde_json::Value {
    match result {
        Ok(Some(levels)) => serde_json::json!({
            "ok": true,
            "advertised": true,
            "levels": levels,
        }),
        Ok(None) => serde_json::json!({
            "ok": true,
            "advertised": false,
            "levels": null,
        }),
        Err(error) => serde_json::json!({
            "ok": false,
            "error": error_json(&error),
        }),
    }
}

/// One of the engine's four advertised size/rate targets, in that order.
///
/// `size_supported` and `size_and_rate_supported` are the platform's native
/// booleans: those two APIs have no error channel, so they stay plain booleans
/// and no error is invented for them.
fn size_rate_json(size: AdvertisedSizeRate) -> serde_json::Value {
    let frame_rate_range = field(size.frame_rate_range.map(|range| {
        serde_json::json!({
            "min": range.min,
            "max": range.max,
        })
    }));
    serde_json::json!({
        "width": size.target.width,
        "height": size.target.height,
        "fps": size.target.fps,
        "size_supported": size.size_supported,
        "size_and_rate_supported": size.size_and_rate_supported,
        "frame_rate_range": frame_rate_range,
    })
}

/// One decoder query: the advertised codec with its per-field results, or the
/// failure that replaced the whole codec. The name, MIME, hardware flag,
/// profiles, Main10 facts, buffer/pixel formats, alignments and the four
/// size/rate rows all survive as the platform returned them.
fn codec_json(result: Result<AdvertisedCodec, CapabilityError>) -> serde_json::Value {
    let codec = match result {
        Ok(codec) => codec,
        Err(error) => {
            return serde_json::json!({
                "ok": false,
                "evidence": EVIDENCE,
                "error": error_json(&error),
            })
        }
    };
    let profiles = field(codec.profiles.map(|values| serde_json::json!(values)));
    let main10_advertised = field(
        codec
            .main10_advertised
            .map(|advertised| serde_json::json!(advertised)),
    );
    let native_buffer_formats = field(
        codec
            .native_buffer_formats
            .map(|values| serde_json::json!(values)),
    );
    let pixel_formats = field(codec.pixel_formats.map(|values| serde_json::json!(values)));
    let width_alignment = field(
        codec
            .width_alignment
            .map(|alignment| serde_json::json!(alignment)),
    );
    let height_alignment = field(
        codec
            .height_alignment
            .map(|alignment| serde_json::json!(alignment)),
    );
    let sizes = codec.sizes.map(size_rate_json);
    serde_json::json!({
        "ok": true,
        "evidence": EVIDENCE,
        "direction": direction_name(codec.direction),
        "codec_name": codec.codec_name,
        "mime": codec.mime,
        "hardware": codec.hardware,
        "profiles": profiles,
        "main10_advertised": main10_advertised,
        "main10_levels": main10_levels_json(codec.main10_levels),
        "native_buffer_formats": native_buffer_formats,
        "pixel_formats": pixel_formats,
        "width_alignment": width_alignment,
        "height_alignment": height_alignment,
        "sizes": sizes,
    })
}

/// Runs both decoder queries and serializes what they returned.
///
/// `ok` is true when at least one decoder query produced a codec: a decoder the
/// platform cannot answer for must not erase the other one's evidence, and two
/// failures must not read as a successful "everything unsupported". Each
/// decoder keeps its own result either way.
///
/// `not_measured` names the facts this document does not carry. The platform
/// metadata contract has no throughput or HDR measurement, and this layer
/// measured none, so neither is reported as a numeric zero: "not_measured" is
/// the whole truth about them.
///
/// The exported entry point wraps this conversion in a background task.
fn capability_report() -> String {
    let h264 = rd_engine::media_capability::query_h264_hardware_decoder();
    let hevc = rd_engine::media_capability::query_hevc_hardware_decoder();
    let ok = h264.is_ok() || hevc.is_ok();
    // Null when at least one decoder answered; a string naming the failure when
    // neither did, so `ok: false` never arrives without a reason.
    let failure = if ok {
        serde_json::Value::Null
    } else {
        serde_json::json!("no decoder capability query succeeded")
    };
    serde_json::json!({
        "ok": ok,
        "evidence": EVIDENCE,
        "source": SOURCE,
        "error": failure,
        "h264_decoder": codec_json(h264),
        "hevc_decoder": codec_json(hevc),
        "not_measured": {
            "codec_throughput": "not_measured",
            "hdr_display": "not_measured",
        },
    })
    .to_string()
}

/// The background half of the export. It is not a JS type: nothing here is
/// registered as a class, and the only thing that names it is the returned
/// `AsyncTask`.
pub struct DecoderCapabilityQuery;

impl Task for DecoderCapabilityQuery {
    type Output = String;
    type JsValue = String;

    /// Runs on a napi worker thread, never on the JS/UI thread: capability
    /// lookup may perform platform IPC.
    fn compute(&mut self) -> napi_ohos::Result<Self::Output> {
        Ok(capability_report())
    }

    fn resolve(
        &mut self,
        _env: napi_ohos::Env,
        output: Self::Output,
    ) -> napi_ohos::Result<Self::JsValue> {
        Ok(output)
    }
}

/// Advertised H264 and HEVC hardware decoder metadata as a JSON string.
///
/// The document is
/// `{ ok, evidence, source, error, h264_decoder, hevc_decoder, not_measured }`.
/// `ok` is true when at least one decoder query produced a codec; each decoder
/// is either the codec object — whose every metadata field is `{ok, value}` or
/// `{ok, error}` — or `{ok: false, error}`; `error` is null when at least one
/// decoder answered; and `not_measured` names throughput and HDR as
/// measurements this query does not make.
///
/// Async on purpose: the engine's queries may perform platform IPC, so the work
/// runs on a napi worker thread and the caller receives a promise. Nothing here
/// starts capture, opens a session, or creates a codec, and the entry point
/// registers no class: its declared return type is what the task resolves to.
#[napi(ts_return_type = "Promise<string>")]
pub fn query_decoder_capabilities() -> AsyncTask<DecoderCapabilityQuery> {
    AsyncTask::new(DecoderCapabilityQuery)
}

