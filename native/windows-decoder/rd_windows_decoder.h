#ifndef RD_WINDOWS_DECODER_H_
#define RD_WINDOWS_DECODER_H_
/* Private ABI. Runner ABI remains native/frb/include/rd_engine_windows_texture.h.
 * Windows x64, C++17. No symbol in this header is a Dart/Flutter export.
 * Link: d3d11, dxgi, dxguid, mfplat, mfuuid, ole32. Enable C++ exceptions.
 * One persistent MTA thread owns each decoder, including open and close. All
 * presenter methods are thread-safe under the caller's shared lifetime gate;
 * final disposal requires its exclusive gate. SDK calls never hold a Rust
 * metadata mutex. Import methods and final disposal use try-lock and never wait for GPU.
 * Images are immutable, legacy shared handles are borrowed, and releasing an
 * import loan is NOT a consumer GPU fence. Native failure retains uncertain
 * resources; only successful close permits releasing callback userdata.
 */
#include <stddef.h>
#include <stdint.h>
#ifdef _WIN32
#define RD_WD_CALL __cdecl
#else
#define RD_WD_CALL
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef struct rd_wd_presenter rd_wd_presenter;
typedef struct rd_wd_decoder rd_wd_decoder;
typedef int32_t rd_wd_status;
enum {
  RD_WD_OK=0, RD_WD_WOULD_BLOCK=1, RD_WD_BUSY=2, RD_WD_CLOSING=3,
  RD_WD_UNSUPPORTED_PLATFORM=4, RD_WD_UNSUPPORTED_BACKEND=5,
  RD_WD_NO_HARDWARE_DECODER=6, RD_WD_UNSUPPORTED_FORMAT=7,
  RD_WD_DEVICE_LOST=8, RD_WD_INVALID_TOKEN=9, RD_WD_INVALID_ARGUMENT=10,
  RD_WD_NATIVE_FAILURE=11, RD_WD_RECLAMATION_UNCONFIRMED=12,
  RD_WD_OWNER_LIMIT=13
};
enum { RD_WD_STAGE_NONE=0, RD_WD_STAGE_VALIDATE=1, RD_WD_STAGE_DEVICE=2,
  RD_WD_STAGE_RESOURCE=3, RD_WD_STAGE_IMPORT=4, RD_WD_STAGE_CLOSE=5,
  RD_WD_STAGE_CAPABILITY=6 };
/* Only the two Media Foundation hardware categories below are named. VP8/VP9
 * have no id here: the Rust seam refuses them by name before any presenter
 * call, and no fallback MFT category or decoder attribute is ever mapped. */
enum { RD_WD_CODEC_H264=1, RD_WD_CODEC_H265=2 };
enum { RD_WD_EVIDENCE_NONE=0, RD_WD_EVIDENCE_METADATA_SUPPORTED=1,
  RD_WD_EVIDENCE_OPENED=2, RD_WD_EVIDENCE_FIRST_NATIVE_OUTPUT=3 };
enum { RD_WD_CLEANUP_UNKNOWN=0, RD_WD_CLEANUP_CONFIRMED=1,
  RD_WD_CLEANUP_UNCONFIRMED=2 };
enum { RD_WD_AU_CLEAN_POINT=1, RD_WD_AU_END_OF_STREAM=2,
  RD_WD_AU_CODEC_CONFIG=4 };
enum { RD_WD_OUTPUT_NONE=0, RD_WD_OUTPUT_PICTURE=1,
  RD_WD_OUTPUT_STREAM_CHANGE=2 };
enum { RD_WD_WAKE_FRAME_AVAILABLE=1, RD_WD_WAKE_UNREGISTER_REQUESTED=2,
  RD_WD_WAKE_STATE_CHANGED=4 };
enum { RD_WD_EVENT_NEED_INPUT=1, RD_WD_EVENT_HAVE_OUTPUT=2,
  RD_WD_EVENT_DRAIN_COMPLETE=3, RD_WD_EVENT_FAILED=5,
  RD_WD_EVENT_OTHER=6 };
typedef struct rd_wd_error {
  uint32_t struct_size, stage;
  int32_t hresult;
  uint32_t reserved;
} rd_wd_error;
/* Callbacks only signal bounded metadata; no reentry, blocking or exceptions. */
typedef void (RD_WD_CALL *rd_wd_wake)(void*, uint64_t, uint32_t);
/* Synchronous private progress only: no public callback, producer wake, reentry
 * or deferred use of context. A null error denotes a real registered blocker
 * retirement; non-null preserves the first unconfirmed reclamation error.
 * The caller's admission/live producer protects context through this return. */
typedef void (RD_WD_CALL *rd_wd_progress)(void*, const rd_wd_error*);
typedef void (RD_WD_CALL *rd_wd_decoder_wake)(void*, uint32_t, int32_t);
typedef void (RD_WD_CALL *rd_wd_input_release)(void*);
/* Client renderer submission: renderer_output is the client's own renderer
 * pointer, never an engine token, and d3d11_texture2d is a borrowed engine
 * texture valid only for the duration of that call. The callee must not throw,
 * must not retain the pointer and reports no per-call status of its own. */
typedef void (RD_WD_CALL *rd_wd_set_texture)(void* renderer_output, void* d3d11_texture2d);
typedef struct rd_wd_presenter_options {
  uint32_t struct_size, adapter_luid_low;
  int32_t adapter_luid_high;
  uint32_t reserved;
  uint64_t token;
  rd_wd_wake wake;
  void* wake_context;
  rd_wd_progress progress;
} rd_wd_presenter_options;
typedef struct rd_wd_codec_capability {
  uint32_t struct_size, codec, available, evidence;
  uint32_t hardware_async, d3d11_aware, native_nv12, tested_width;
  uint32_t tested_height, tested_profile, decoder_profiles, decoder_configs;
  int32_t status, hresult;
  uint8_t clsid[16];
  uint16_t name[128];
} rd_wd_codec_capability;
typedef struct rd_wd_capabilities {
  uint32_t struct_size, adapter_luid_low;
  int32_t adapter_luid_high;
  uint32_t vendor_id, device_id, feature_level;
  uint32_t shared_texture, video_processor, event_completion;
  uint32_t sync_h264_candidates, sync_h265_candidates, reserved;
  rd_wd_codec_capability h264, h265;
} rd_wd_capabilities;
typedef struct rd_wd_frame {
  uint32_t struct_size, pixel_format;
  uint64_t codec_generation, frame_sequence;
  int64_t pts_100ns;
  uint32_t width, height, visible_width, visible_height;
  void* shared_handle;
  uint64_t loan_id;
} rd_wd_frame;
typedef struct rd_wd_presenter_stats {
  uint32_t struct_size, closing, registration_retired, producers_live;
  uint32_t current_present, pending_present, converting, outstanding_loans;
  uint32_t unconfirmed, dispatch_open, wake_in_flight, unregister_requested;
  uint64_t published_images, acquired_images, superseded_images;
  uint64_t gpu_fence_completions, wake_started, wake_finished;
  uint64_t generations_started, generations_retired;
  int32_t last_hresult;
  uint32_t reserved;
} rd_wd_presenter_stats;
/* Actual negotiated metadata. Unknown values remain unknown, never defaults.
 * Fractional apertures and unsupported chroma/colorimetry fail explicitly. */
typedef struct rd_wd_decoded_frame {
  uint32_t struct_size, texture_width, texture_height, subresource;
  uint32_t coded_width, coded_height, aperture_present, aperture_left;
  uint32_t aperture_top, visible_width, visible_height, primaries;
  uint32_t transfer, matrix, nominal_range, chroma_siting;
  uint64_t codec_generation, output_sequence;
  int64_t pts_100ns;
  void* d3d11_texture2d;
  void* d3d11_device;
} rd_wd_decoded_frame;
typedef struct rd_wd_bgra_raster {
  uint32_t struct_size, width, height, stride;
  int32_t damage_left, damage_top, damage_right, damage_bottom;
  int64_t pts_100ns;
  uint64_t codec_generation;
  const uint8_t* data;
  size_t data_len;
} rd_wd_bgra_raster;
typedef struct rd_wd_decoder_options {
  uint32_t struct_size, codec, max_width, max_height;
  uint64_t generation;
  rd_wd_presenter* presenter;
  rd_wd_decoder_wake wake;
  void* wake_context;
} rd_wd_decoder_options;
typedef struct rd_wd_open_report {
  uint32_t struct_size, cleanup;
  rd_wd_codec_capability identity;
} rd_wd_open_report;
typedef struct rd_wd_decoder_stats {
  uint32_t struct_size, opened, need_input_events, have_output_events;
  uint32_t drain_complete, stream_changes, unknown_events, event_overflow;
  uint32_t callback_in_flight, callbacks_retired, input_buffers_live, native_output_seen;
  int32_t last_hresult;
  uint32_t reserved;
  uint64_t pushed_units, pushed_bytes, decoded_pictures, non_picture_outputs;
  uint32_t texture_array_size, reserved2;
  uint64_t texture_allocation_bytes;
  /* Metadata only: the two borrowed pointers are always null in a snapshot. */
  rd_wd_decoded_frame last_output;
} rd_wd_decoder_stats;
rd_wd_status RD_WD_CALL rd_wd_presenter_create(const rd_wd_presenter_options*, rd_wd_presenter**, rd_wd_error*);
rd_wd_status RD_WD_CALL rd_wd_presenter_capabilities(rd_wd_presenter*, rd_wd_capabilities*, rd_wd_error*);
rd_wd_status RD_WD_CALL rd_wd_presenter_begin_generation(rd_wd_presenter*, uint64_t, rd_wd_error*);
rd_wd_status RD_WD_CALL rd_wd_presenter_end_generation(rd_wd_presenter*, uint64_t, rd_wd_error*);
rd_wd_status RD_WD_CALL rd_wd_presenter_acquire(rd_wd_presenter*, rd_wd_frame*, rd_wd_error*);
rd_wd_status RD_WD_CALL rd_wd_presenter_release(rd_wd_presenter*, uint64_t, rd_wd_error*);
rd_wd_status RD_WD_CALL rd_wd_presenter_publish(rd_wd_presenter*, const rd_wd_decoded_frame*, rd_wd_error*);
/* Borrow lasts only through this call. Upload writes a fresh GPU resource; no
 * second persistent CPU framebuffer or retained borrowed pointer exists. */
rd_wd_status RD_WD_CALL rd_wd_presenter_publish_bgra(rd_wd_presenter*, const rd_wd_bgra_raster*, rd_wd_error*);
/* Submits the newest published image to the client's own GPU renderer in one
 * call: take one loan of the current publication, call
 * set_texture(renderer_output, that loan's texture), release that loan. The
 * loan never escapes and the texture pointer is valid only inside the call.
 * WOULD_BLOCK means no image has been published yet; BUSY is owner/state
 * contention; a null renderer_output/set_texture or a closing presenter is
 * rejected. OK means the loan was submitted and released, never that the client
 * copied or presented a frame: that entry point has no error channel. */
rd_wd_status RD_WD_CALL rd_wd_presenter_publish_gpu(rd_wd_presenter*, void* renderer_output, rd_wd_set_texture, rd_wd_error*);
rd_wd_status RD_WD_CALL rd_wd_presenter_snapshot(const rd_wd_presenter*, rd_wd_presenter_stats*, rd_wd_error*);
rd_wd_status RD_WD_CALL rd_wd_presenter_request_close(rd_wd_presenter*, rd_wd_error*);
rd_wd_status RD_WD_CALL rd_wd_presenter_registration_retired(rd_wd_presenter*, rd_wd_error*);
/* OK deletes the native presenter. BUSY/UNCONFIRMED retain it. */
rd_wd_status RD_WD_CALL rd_wd_presenter_dispose(rd_wd_presenter*, rd_wd_error*);
void* RD_WD_CALL rd_wd_presenter_device(rd_wd_presenter*);
rd_wd_status RD_WD_CALL rd_wd_decoder_open(const rd_wd_decoder_options*, rd_wd_decoder**, rd_wd_open_report*, rd_wd_error*);
/* OK transfers the input lease until release(context), including when the MFT
 * retains the buffer. Every other status leaves the lease with the caller.
 * A retained lease counts against Rust's two-AU/32MiB budget. */
rd_wd_status RD_WD_CALL rd_wd_decoder_input(rd_wd_decoder*, void*, size_t, int64_t, uint32_t, rd_wd_input_release, void*, rd_wd_error*);
rd_wd_status RD_WD_CALL rd_wd_decoder_output(rd_wd_decoder*, rd_wd_decoded_frame*, uint32_t*, rd_wd_error*);
/* Do not release the sample after an unconfirmed producer fence. Native close
 * retains that sample in quarantine along with the presentation device. */
void RD_WD_CALL rd_wd_decoder_release_output(rd_wd_decoder*, const rd_wd_decoded_frame*);
rd_wd_status RD_WD_CALL rd_wd_decoder_drain(rd_wd_decoder*, rd_wd_error*);
rd_wd_status RD_WD_CALL rd_wd_decoder_flush(rd_wd_decoder*, rd_wd_error*);
rd_wd_status RD_WD_CALL rd_wd_decoder_snapshot(const rd_wd_decoder*, rd_wd_decoder_stats*, rd_wd_error*);
/* On OK the decoder is deleted and all userdata retired. On UNCONFIRMED the
 * graph and its creating MTA thread must remain quarantined, never reused. */
rd_wd_status RD_WD_CALL rd_wd_decoder_close(rd_wd_decoder*, rd_wd_error*);
#ifdef __cplusplus
}
static_assert(sizeof(void*) == 8, "Windows native ABI requires 64-bit");
static_assert(sizeof(rd_wd_error) == 16, "error layout");
static_assert(sizeof(rd_wd_frame) == 64, "frame layout");
static_assert(sizeof(rd_wd_presenter_options) == 48, "options layout");
static_assert(sizeof(rd_wd_codec_capability) == 328, "capability layout");
static_assert(sizeof(rd_wd_capabilities) == 704, "capabilities layout");
static_assert(sizeof(rd_wd_presenter_stats) == 120, "presenter stats layout");
static_assert(sizeof(rd_wd_decoded_frame) == 104, "decoded frame layout");
static_assert(sizeof(rd_wd_bgra_raster) == 64, "raster layout");
static_assert(sizeof(rd_wd_decoder_options) == 48, "decoder options layout");
static_assert(sizeof(rd_wd_open_report) == 336, "open report layout");
static_assert(sizeof(rd_wd_decoder_stats) == 208, "decoder stats layout");
#endif
#endif
