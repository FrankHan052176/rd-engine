#ifndef RD_ENGINE_WINDOWS_TEXTURE_H
#define RD_ENGINE_WINDOWS_TEXTURE_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define RD_WIN_CALL __cdecl
#else
#define RD_WIN_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Tokens and loan IDs never repeat during the process lifetime. Only tokens,
 * encoded as decimal strings, may cross into Dart. GPU handles remain native. */
typedef uint64_t RdWinTextureToken;
typedef int32_t RdWinTextureStatus;
enum {
  RD_WIN_OK = 0,
  RD_WIN_WOULD_BLOCK = 1,
  RD_WIN_BUSY = 2,
  RD_WIN_CLOSING = 3,
  RD_WIN_UNSUPPORTED_PLATFORM = 4,
  RD_WIN_UNSUPPORTED_BACKEND = 5,
  RD_WIN_NO_HARDWARE_DECODER = 6,
  RD_WIN_UNSUPPORTED_FORMAT = 7,
  RD_WIN_DEVICE_LOST = 8,
  RD_WIN_INVALID_TOKEN = 9,
  RD_WIN_INVALID_ARGUMENT = 10,
  RD_WIN_NATIVE_FAILURE = 11,
  RD_WIN_RECLAMATION_UNCONFIRMED = 12,
  RD_WIN_OWNER_LIMIT = 13
};

enum {
  RD_WIN_WAKE_FRAME_AVAILABLE = 1,
  RD_WIN_WAKE_UNREGISTER_REQUESTED = 2,
  RD_WIN_WAKE_STATE_CHANGED = 4,
  RD_WIN_PIXEL_BGRA8 = 1
};

enum {
  RD_WIN_STAGE_NONE = 0,
  RD_WIN_STAGE_VALIDATE = 1,
  RD_WIN_STAGE_DEVICE = 2,
  RD_WIN_STAGE_RESOURCE = 3,
  RD_WIN_STAGE_IMPORT = 4,
  RD_WIN_STAGE_CLOSE = 5,
  RD_WIN_STAGE_CAPABILITY = 6
};

/* The callback may run on native workers. It must only enqueue bounded metadata,
 * must not throw or block, and must retain its context through successful
 * dispose. It is not called before create returns its token. A notification is
 * not a successful import or physical presentation measurement. */
typedef void (RD_WIN_CALL *RdWinTextureWake)(void* context,
                                          RdWinTextureToken token,
                                          uint32_t reasons);

typedef struct RdWinTextureCreate {
  uint32_t struct_size;
  uint32_t adapter_luid_low;
  int32_t adapter_luid_high;
  uint32_t reserved;
  RdWinTextureWake wake;
  void* context;
} RdWinTextureCreate;

typedef struct RdWinTextureError {
  uint32_t struct_size;
  uint32_t stage;
  int32_t native_hresult;
  uint32_t reserved;
} RdWinTextureError;

typedef struct RdWinTextureFrame {
  uint32_t struct_size;
  uint32_t pixel_format;
  uint64_t codec_generation;
  uint64_t frame_sequence;
  int64_t pts_100ns;
  uint32_t width;
  uint32_t height;
  uint32_t visible_width;
  uint32_t visible_height;
  void* shared_handle;
  uint64_t loan_id;
} RdWinTextureFrame;

/* Caller initializes struct_size on every input/output struct and zeroes
 * reserved fields. Error is required and initialized on every return. Output
 * token/frame are only usable on RD_WIN_OK; WOULD_BLOCK owns no loan.
 * create may initialize the native device and must run off the platform thread.
 * It creates presentation, not a session and not a claim of codec support. */
RdWinTextureStatus RD_WIN_CALL rd_engine_windows_texture_create(
    const RdWinTextureCreate* options, RdWinTextureToken* token,
    RdWinTextureError* error);

/* Nonblocking import acquisition. BUSY is transient owner/state contention;
 * WOULD_BLOCK means no image is available. Neither status owns an import loan.
 * A worker can wait for BUSY progress then request another Flutter acquisition.
 * Frame is immutable forever. release ends an import loan; it does NOT signal
 * GPU consumer completion or permit recycling. A DXGI legacy shared handle is
 * borrowed: never call CloseHandle on it. */
RdWinTextureStatus RD_WIN_CALL rd_engine_windows_texture_acquire(
    RdWinTextureToken token, RdWinTextureFrame* frame, RdWinTextureError* error);
RdWinTextureStatus RD_WIN_CALL rd_engine_windows_texture_release(
    RdWinTextureToken token, uint64_t loan_id, RdWinTextureError* error);

/* request_close is nonblocking and idempotent for the live token. The engine
 * requests Flutter unregistration only after its producers have retired.
 * registration_retired is legal only after Flutter's asynchronous unregister
 * completion AND all descriptor callbacks/import loans have returned. */
RdWinTextureStatus RD_WIN_CALL rd_engine_windows_texture_request_close(
    RdWinTextureToken token, RdWinTextureError* error);
RdWinTextureStatus RD_WIN_CALL rd_engine_windows_texture_registration_retired(
    RdWinTextureToken token, RdWinTextureError* error);

/* Nonblocking final reclamation. BUSY retains the owner; UNCONFIRMED quarantines
 * it and is not successful disposal. Only OK releases the token and callback
 * context. No callback starts or remains in flight after OK. */
RdWinTextureStatus RD_WIN_CALL rd_engine_windows_texture_dispose(
    RdWinTextureToken token, RdWinTextureError* error);

enum {
  RD_WIN_PROGRESS_WAIT = 0,
  RD_WIN_PROGRESS_CANCEL = 1
};

/* Worker-only progress wait; never call WAIT with a nonzero revision from the
 * Flutter platform/render thread or a native wake callback. With *revision=0,
 * WAIT only records a nonzero snapshot. Take that snapshot BEFORE attempting
 * an operation; after BUSY, WAIT with the same revision until a real retirement
 * edge occurs, then retry. A wait or failed retry does not itself create an edge.
 * Revision is caller-owned storage retained for the duration of this call.
 * Use one serialized lifecycle/retry worker per owner. Passive waiters may be
 * concurrent; competing automatic retry loops must not contend with each other.
 *
 * CANCEL permanently wakes/cancels this owner's progress waiters. It is only
 * for an abandoned registrar/plugin, not normal user disposal. Its OK result
 * acknowledges cancellation, NOT resource reclamation. Subsequent WAIT calls
 * return CLOSING unless a recorded terminal failure must be preserved with its
 * actual status/stage/HRESULT. Repeated CANCEL does not advance the revision.
 *
 * A waiter holds independent Rust lifetime ownership, never the native access
 * gate or callback userdata. Disposal does not wait for waiters to exit: after
 * native callbacks retire it publishes terminal state and wakes them. A waiter
 * may then return CLOSING after successful disposal without touching userdata.
 * Unknown flags, null or unaligned revision/error pointers are invalid.
 * This export is required; clients must reject older DLLs rather than poll. */
RdWinTextureStatus RD_WIN_CALL rd_engine_windows_texture_wait_progress(
    RdWinTextureToken token, uint64_t* revision, uint32_t flags,
    RdWinTextureError* error);

#ifdef __cplusplus
}
static_assert(sizeof(void*) == 8, "Windows texture ABI requires a 64-bit build");
static_assert(sizeof(RdWinTextureCreate) == 32, "create ABI size");
static_assert(offsetof(RdWinTextureCreate, wake) == 16, "wake ABI offset");
static_assert(sizeof(RdWinTextureError) == 16, "error ABI size");
static_assert(sizeof(RdWinTextureFrame) == 64, "frame ABI size");
static_assert(offsetof(RdWinTextureFrame, shared_handle) == 48,
              "shared handle ABI offset");
static_assert(offsetof(RdWinTextureFrame, loan_id) == 56, "loan ABI offset");
#endif
#endif
