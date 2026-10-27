// This must be included before the other Windows headers.
#include <windows.h>

#include "include/rd_engine_texture/rd_engine_texture_plugin_c_api.h"
#include "rd_engine_texture_plugin.h"
#include "rd_engine_windows_texture.h"

#include <flutter/encodable_value.h>
#include <flutter/standard_method_codec.h>
#include <flutter/texture_registrar.h>

#include <dxgi.h>

#include <algorithm>
#include <array>

#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <exception>
#include <functional>
#include <iostream>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>

namespace rd_engine_texture {

constexpr char kMethodChannel[] = "rd_engine/windows_texture";
constexpr UINT kPluginMessage = WM_APP + 0x4D6;
constexpr size_t kMaxDescriptorSlots = 4;
constexpr size_t kMaxPresentations = 4;
constexpr size_t kMaxRetainedOwners = 64;

static_assert(sizeof(RdWinTextureCreate) == 32, "engine create ABI changed");
static_assert(offsetof(RdWinTextureCreate, wake) == 16,
              "engine create callback ABI changed");
static_assert(sizeof(RdWinTextureError) == 16, "engine error ABI changed");
static_assert(sizeof(RdWinTextureFrame) == 64, "engine frame ABI changed");
static_assert(offsetof(RdWinTextureFrame, shared_handle) == 48,
              "engine frame handle ABI changed");
static_assert(offsetof(RdWinTextureFrame, loan_id) == 56,
              "engine frame loan ABI changed");
static_assert(RD_WIN_PIXEL_BGRA8 == 1, "engine pixel ABI changed");
static_assert(RD_WIN_WAKE_FRAME_AVAILABLE == 1, "engine wake ABI changed");
static_assert(RD_WIN_WAKE_UNREGISTER_REQUESTED == 2, "engine wake ABI changed");
static_assert(RD_WIN_WAKE_STATE_CHANGED == 4, "engine wake ABI changed");

// Layout checks alone do not prove consumer lifetime compatibility. The serial
// consumer below was inspected in the local Flutter 3.47.4 sources; the pinned
// 3.38.10 consumer still needs independent source/runtime validation.
static_assert(sizeof(FlutterDesktopGpuSurfaceDescriptor) == 72,
              "unsupported Flutter GPU descriptor ABI");
static_assert(offsetof(FlutterDesktopGpuSurfaceDescriptor, handle) == 8,
              "unsupported Flutter GPU descriptor ABI");
static_assert(offsetof(FlutterDesktopGpuSurfaceDescriptor, format) == 48,
              "unsupported Flutter GPU descriptor ABI");
static_assert(offsetof(FlutterDesktopGpuSurfaceDescriptor, release_callback) ==
                  56,
              "unsupported Flutter GPU descriptor ABI");
static_assert(offsetof(FlutterDesktopGpuSurfaceDescriptor, release_context) ==
                  64,
              "unsupported Flutter GPU descriptor ABI");
static_assert(sizeof(FlutterDesktopGpuSurfaceTextureConfig) == 32,
              "unsupported Flutter texture config ABI");

using CreateFn = RdWinTextureStatus(RD_WIN_CALL *)(const RdWinTextureCreate *,
                                                   RdWinTextureToken *,
                                                   RdWinTextureError *);
using AcquireFn = RdWinTextureStatus(RD_WIN_CALL *)(RdWinTextureToken,
                                                    RdWinTextureFrame *,
                                                    RdWinTextureError *);
using ReleaseFn = RdWinTextureStatus(RD_WIN_CALL *)(RdWinTextureToken, uint64_t,
                                                    RdWinTextureError *);
using RequestCloseFn = RdWinTextureStatus(RD_WIN_CALL *)(RdWinTextureToken,
                                                         RdWinTextureError *);
using RegistrationRetiredFn =
    RdWinTextureStatus(RD_WIN_CALL *)(RdWinTextureToken, RdWinTextureError *);
using DisposeFn = RdWinTextureStatus(RD_WIN_CALL *)(RdWinTextureToken,
                                                    RdWinTextureError *);
using WaitProgressFn = decltype(&rd_engine_windows_texture_wait_progress);

template <typename Fn> Fn LoadExport(HMODULE module, const char *name) {
  return reinterpret_cast<Fn>(GetProcAddress(module, name));
}

struct EngineApi {
  CreateFn create = nullptr;
  AcquireFn acquire = nullptr;
  ReleaseFn release = nullptr;
  RequestCloseFn request_close = nullptr;
  RegistrationRetiredFn registration_retired = nullptr;
  DisposeFn dispose = nullptr;
  WaitProgressFn wait_progress = nullptr;

  bool complete() const {
    return create != nullptr && acquire != nullptr && release != nullptr &&
           request_close != nullptr && registration_retired != nullptr &&
           dispose != nullptr && wait_progress != nullptr;
  }
};

std::wstring ExecutableDirectoryDllPath(bool *ok) {
  *ok = false;
  std::vector<wchar_t> buffer(32768);
  const DWORD length = GetModuleFileNameW(nullptr, buffer.data(),
                                          static_cast<DWORD>(buffer.size()));
  if (length == 0 || length >= buffer.size()) {
    return {};
  }
  std::wstring executable(buffer.data(), length);
  const size_t slash = executable.find_last_of(L"\\/");
  if (slash == std::wstring::npos) {
    return {};
  }
  // The official client loads this exact image for both its FRB symbols and the
  // token registry. Loading a differently named engine would split that
  // process-local state, so there is deliberately no alternate-image fallback.
  const std::wstring candidate = executable.substr(0, slash + 1) +
                                 L"librustdesk.dll";
  std::vector<wchar_t> full_buffer(32768);
  const DWORD full_length = GetFullPathNameW(
      candidate.c_str(), static_cast<DWORD>(full_buffer.size()),
      full_buffer.data(), nullptr);
  if (full_length == 0 || full_length >= full_buffer.size()) {
    return {};
  }
  *ok = true;
  return std::wstring(full_buffer.data(), full_length);
}

struct ModuleLease {
  HMODULE module = nullptr;
  EngineApi api;

  ~ModuleLease() {
    if (module != nullptr) {
      FreeLibrary(module);
    }
  }
};

std::shared_ptr<ModuleLease> LoadEngineModule(std::string *error,
                                             std::string *error_code) {
  bool path_ok = false;
  const std::wstring path = ExecutableDirectoryDllPath(&path_ok);
  if (!path_ok) {
    *error = "executable_directory_unavailable";
    return nullptr;
  }

  HMODULE module = LoadLibraryExW(path.c_str(), nullptr,
                                  LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                                      LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (module == nullptr) {
    *error = "engine_dll_missing";
    return nullptr;
  }

  // Verify that the loader returned the exact requested executable-directory
  // image. Do not accept a same-named module from another search location.
  std::vector<wchar_t> loaded_buffer(32768);
  const DWORD loaded_length = GetModuleFileNameW(
      module, loaded_buffer.data(), static_cast<DWORD>(loaded_buffer.size()));
  if (loaded_length == 0 || loaded_length >= loaded_buffer.size() ||
      _wcsicmp(path.c_str(),
               std::wstring(loaded_buffer.data(), loaded_length).c_str()) !=
          0) {
    FreeLibrary(module);
    *error = "engine_dll_path_mismatch";
    return nullptr;
  }

  auto lease = std::make_shared<ModuleLease>();
  lease->module = module;
  lease->api.create =
      LoadExport<CreateFn>(module, "rd_engine_windows_texture_create");
  lease->api.acquire =
      LoadExport<AcquireFn>(module, "rd_engine_windows_texture_acquire");
  lease->api.release =
      LoadExport<ReleaseFn>(module, "rd_engine_windows_texture_release");
  lease->api.request_close = LoadExport<RequestCloseFn>(
      module, "rd_engine_windows_texture_request_close");
  lease->api.registration_retired = LoadExport<RegistrationRetiredFn>(
      module, "rd_engine_windows_texture_registration_retired");
  lease->api.dispose =
      LoadExport<DisposeFn>(module, "rd_engine_windows_texture_dispose");
  lease->api.wait_progress = LoadExport<WaitProgressFn>(
      module, "rd_engine_windows_texture_wait_progress");
  if (lease->api.wait_progress == nullptr) {
    *error_code = "unsupported_backend";
    *error = "Engine DLL does not support required texture wait_progress ABI";
    return nullptr;
  }
  if (!lease->api.complete()) {
    lease.reset();
    *error = "engine_dll_missing_texture_exports";
    return nullptr;
  }
  return lease;
}

void InitError(RdWinTextureError *error) {
  std::memset(error, 0, sizeof(*error));
  error->struct_size = sizeof(*error);
}

const char *StatusName(RdWinTextureStatus status) {
  switch (status) {
  case RD_WIN_OK:
    return "ok";
  case RD_WIN_WOULD_BLOCK:
    return "would_block";
  case RD_WIN_BUSY:
    return "busy";
  case RD_WIN_CLOSING:
    return "closing";
  case RD_WIN_UNSUPPORTED_PLATFORM:
    return "unsupported_platform";
  case RD_WIN_UNSUPPORTED_BACKEND:
    return "unsupported_backend";
  case RD_WIN_NO_HARDWARE_DECODER:
    return "no_hardware_decoder";
  case RD_WIN_UNSUPPORTED_FORMAT:
    return "unsupported_format";
  case RD_WIN_DEVICE_LOST:
    return "device_lost";
  case RD_WIN_INVALID_TOKEN:
    return "invalid_token";
  case RD_WIN_INVALID_ARGUMENT:
    return "invalid_argument";
  case RD_WIN_NATIVE_FAILURE:
    return "native_failure";
  case RD_WIN_RECLAMATION_UNCONFIRMED:
    return "reclamation_unconfirmed";
  case RD_WIN_OWNER_LIMIT:
    return "owner_limit";
  default:
    return "unknown";
  }
}

std::string NativeFailureMessage(const char *operation,
                                 RdWinTextureStatus status,
                                 const RdWinTextureError &error) {
  std::ostringstream stream;
  stream << operation << " failed (" << StatusName(status) << ", stage "
         << error.stage << ", HRESULT " << error.native_hresult << ")";
  return stream.str();
}

bool ParseDecimalToken(const std::string &text, uint64_t *token) {
  if (text.empty() || text == "0") {
    return false;
  }
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return false;
    }
  }
  const auto parsed =
      std::from_chars(text.data(), text.data() + text.size(), *token, 10);
  return parsed.ec == std::errc() && parsed.ptr == text.data() + text.size() &&
         *token != 0;
}

std::string DecimalToken(uint64_t token) { return std::to_string(token); }

// Admission, not teardown, reserves callback retention. Intentionally never
// destroyed: static destruction is not proof that native callbacks have stopped.
struct RetainedOwners {
  std::mutex mutex;
  std::array<std::shared_ptr<Presentation>, kMaxRetainedOwners> owners{};
  uint64_t next_cookie = 1;
  HANDLE dispatch_event = nullptr;
  HANDLE dispatch_wait = nullptr;
  bool ready = false;

  RetainedOwners();
  static void CALLBACK DispatchFallback(void *opaque, BOOLEAN timed_out);
};

RetainedOwners &OwnerRetention() {
  static auto *owners = new RetainedOwners();
  return *owners;
}

bool ReserveOwner(const std::shared_ptr<Presentation> &presentation);
void ReleaseOwner(const std::shared_ptr<Presentation> &presentation);

struct PlatformState {
  std::atomic<bool> alive{true};
  std::atomic<void *> hwnd{nullptr};
  DWORD thread_id = GetCurrentThreadId();
};

struct PresentationContext {
  std::shared_ptr<ModuleLease> module;
  std::shared_ptr<PlatformState> platform;
  RetainedOwners *retention = nullptr;
  uint64_t dispatch_cookie = 0;
  std::atomic<bool> dispatch_enabled{true};
  std::atomic<uint64_t> token{0};
  std::atomic<uint32_t> wake_reasons{0};
  // A successful render attempt acknowledges only the demand observed before
  // acquire; it must not erase a frame wake that raced that native call.
  std::atomic<uint64_t> frame_requests{0};
  std::atomic<uint64_t> frame_completed{0};
  std::atomic<bool> message_posted{false};
  std::atomic<bool> fallback_pending{false};
  std::atomic<DWORD> dispatch_error{ERROR_SUCCESS};
  std::atomic<bool> create_done{false};
  std::atomic<bool> native_created{false};
  std::atomic<bool> closing{false};
  // 0 = empty, 1 = being written, 2 = published. Payload is immutable after 2.
  std::atomic<uint8_t> error_state{0};
  RdWinTextureStatus first_error_status = RD_WIN_OK;
  RdWinTextureError first_error{};
  const char *first_error_operation = nullptr;
  RdWinTextureStatus create_status = RD_WIN_NATIVE_FAILURE;
  RdWinTextureError create_error{};

  bool NeedsFrame() const noexcept {
    return frame_requests.load(std::memory_order_acquire) >
           frame_completed.load(std::memory_order_acquire);
  }

  void RequireFrame() noexcept {
    uint64_t requested = frame_requests.load(std::memory_order_acquire);
    if (requested == frame_completed.load(std::memory_order_acquire)) {
      // Only the serial render consumer completes demands. A failed CAS here
      // means a native frame wake has already supplied the needed demand.
      frame_requests.compare_exchange_strong(requested, requested + 1,
                                             std::memory_order_acq_rel);
    }
  }

  void RecordError(const char *operation, RdWinTextureStatus status,
                   const RdWinTextureError &error) noexcept {
    uint8_t expected = 0;
    if (error_state.compare_exchange_strong(expected, 1,
                                            std::memory_order_acq_rel)) {
      first_error_operation = operation;
      first_error_status = status;
      first_error = error;
      closing.store(true, std::memory_order_release);
      error_state.store(2, std::memory_order_release);
      PostPlatformMessage();
    }
  }

  void PostPlatformMessage() noexcept {
    if (!platform->alive.load(std::memory_order_acquire) ||
        !dispatch_enabled.load(std::memory_order_acquire)) {
      return;
    }
    const HWND window =
        static_cast<HWND>(platform->hwnd.load(std::memory_order_acquire));
    if (window == nullptr || message_posted.exchange(true,
                                                    std::memory_order_acq_rel)) {
      return;
    }
    // Messages carry a never-reused cookie, not a pointer that could dangle or
    // alias a newly admitted owner after successful disposal.
    if (!PostMessageW(window, kPluginMessage, 0,
                      static_cast<LPARAM>(dispatch_cookie))) {
      fallback_pending.store(true, std::memory_order_release);
      // One process-wide auto-reset event and one serial wait callback. No
      // allocation, blocking call, thread creation, or retry queue on this path.
      if (!SetEvent(retention->dispatch_event)) {
        const DWORD error = GetLastError();
        dispatch_error.store(error == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : error,
                             std::memory_order_release);
        message_posted.store(false, std::memory_order_release);
      }
    }
  }
};

enum class LoanState : uint8_t { Free, Loaned, Returning, Pending, Failed };

enum WorkerCommand : uint32_t {
  kReturnLoans = 1,
  kRequestClose = 2,
  kRegistrationRetired = 4,
  kDispose = 8,
  kPrepareFrame = 16,
  kRetryAcquire = 32,
};

struct DescriptorSlot {
  Presentation *owner = nullptr;
  std::atomic<LoanState> state{LoanState::Free};
  uint64_t loan_id = 0;
  FlutterDesktopGpuSurfaceDescriptor descriptor{};
};

struct Presentation {
  explicit Presentation(std::shared_ptr<PresentationContext> context)
      : context(std::move(context)),
        texture(flutter::GpuSurfaceTexture(
            kFlutterDesktopGpuSurfaceTypeDxgiSharedHandle,
            [this](size_t width, size_t height) {
              return ObtainDescriptor(width, height);
            })) {
    for (auto &slot : slots) {
      slot.owner = this;
    }
  }

  ~Presentation() {
    if (worker_event != nullptr) {
      CloseHandle(worker_event);
    }
  }

  std::shared_ptr<PresentationContext> context;
  flutter::TextureVariant texture;
  std::array<DescriptorSlot, kMaxDescriptorSlots> slots{};
  std::atomic<DWORD> consumer_thread{0};
  std::atomic_flag obtaining = ATOMIC_FLAG_INIT;
  std::atomic<uint32_t> callback_users{0};
  std::atomic<uint32_t> outstanding_loans{0};
  HANDLE worker_event = nullptr;
  std::atomic<uint32_t> worker_commands{0};
  std::atomic<bool> worker_abandoned{false};
  std::atomic<bool> worker_exited{false};
  bool progress_terminal = false; // lifecycle worker only
  std::atomic<bool> close_complete{false};
  std::atomic<bool> registration_retired{false};
  std::atomic<uint64_t> acquire_revision{0};
  std::atomic<uint64_t> retry_acquire_revision{0};
  std::atomic<bool> waiting_for_slot{false};
  std::atomic<bool> frame_ready{false};

  // Platform-thread fields, except explicitly atomic completion signals and
  // worker payloads published by their corresponding release/acquire signal.
  bool create_handled = false;
  bool registered = false;
  int64_t texture_id = -1;
  bool close_requested = false;
  bool close_handed_off = false;
  bool close_started = false;
  bool unregister_started = false;
  bool native_unregister_ready = false;
  std::atomic<bool> flutter_unregister_complete{false};
  bool retirement_started = false;
  bool dispose_started = false;
  std::atomic<bool> dispose_signal{false};
  RdWinTextureStatus dispose_status = RD_WIN_BUSY;
  RdWinTextureError dispose_error{};
  bool disposed = false;
  bool quarantined = false;
  bool error_handled = false;
  std::string failure_code;
  std::string failure_message;
  std::shared_ptr<RdEngineTexturePlugin::MethodResult> create_result;
  std::shared_ptr<RdEngineTexturePlugin::MethodResult> dispose_result;

  const FlutterDesktopGpuSurfaceDescriptor *ObtainDescriptor(size_t width,
                                                             size_t height);
  void ReleaseDescriptor(DescriptorSlot *slot) noexcept;
  void ReturnLoan(DescriptorSlot *slot) noexcept;
  void ReturnPendingLoans() noexcept;
  void ScheduleWork(uint32_t commands) noexcept;
  void CancelProgressWaits() noexcept;
  void PrepareFrame(bool retry_acquire) noexcept;

  static void ReleaseDescriptorCallback(void *opaque) noexcept {
    auto *slot = static_cast<DescriptorSlot *>(opaque);
    if (slot != nullptr && slot->owner != nullptr) {
      slot->owner->ReleaseDescriptor(slot);
    }
  }

  static void RD_WIN_CALL WakeCallback(void *opaque, RdWinTextureToken token,
                                       uint32_t reasons) noexcept {
    auto *context = static_cast<PresentationContext *>(opaque);
    if (context == nullptr) {
      return;
    }
    const uint64_t expected = context->token.load(std::memory_order_acquire);
    if (expected != 0 && expected != token) {
      RdWinTextureError error{};
      error.struct_size = sizeof(error);
      error.stage = RD_WIN_STAGE_VALIDATE;
      error.native_hresult = ERROR_INVALID_DATA;
      context->RecordError("wake", RD_WIN_INVALID_TOKEN, error);
      return;
    }
    if ((reasons & RD_WIN_WAKE_FRAME_AVAILABLE) != 0) {
      context->frame_requests.fetch_add(1, std::memory_order_acq_rel);
    }
    context->wake_reasons.fetch_or(reasons, std::memory_order_acq_rel);
    context->PostPlatformMessage();
  }

private:
  struct CallbackScope {
    explicit CallbackScope(Presentation *owner) : owner(owner) {
      owner->callback_users.fetch_add(1, std::memory_order_acq_rel);
    }
    ~CallbackScope() {
      if (owner->callback_users.fetch_sub(1, std::memory_order_acq_rel) == 1 &&
          owner->context->closing.load(std::memory_order_acquire)) {
        owner->context->PostPlatformMessage();
      }
    }
    Presentation *owner;
  };
};

RetainedOwners::RetainedOwners() {
  // Retaining userdata without retaining the DLL containing the callbacks would
  // still be a UAF. Pin this plugin image; engine images are leased per owner.
  HMODULE self = nullptr;
  if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                             GET_MODULE_HANDLE_EX_FLAG_PIN,
                         reinterpret_cast<LPCWSTR>(&DispatchFallback), &self)) {
    return;
  }
  dispatch_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  if (dispatch_event == nullptr) {
    return;
  }
  // INFINITE disables timers; EXECUTEINWAITTHREAD serializes this short bounded
  // callback and prevents one queued work item per failed frame notification.
  if (!RegisterWaitForSingleObject(&dispatch_wait, dispatch_event,
                                   &DispatchFallback, this, INFINITE,
                                   WT_EXECUTEINWAITTHREAD)) {
    CloseHandle(dispatch_event);
    dispatch_event = nullptr;
    return;
  }
  ready = true;
}

void CALLBACK RetainedOwners::DispatchFallback(void *opaque, BOOLEAN) {
  auto *retained = static_cast<RetainedOwners *>(opaque);
  std::array<std::shared_ptr<Presentation>, kMaxRetainedOwners> snapshot;
  {
    std::lock_guard<std::mutex> lock(retained->mutex);
    snapshot = retained->owners;
  }
  for (const auto &owner : snapshot) {
    if (!owner || !owner->context->fallback_pending.exchange(
                      false, std::memory_order_acq_rel)) {
      continue;
    }
    const auto &context = owner->context;
    const auto &platform = context->platform;
    if (!platform->alive.load(std::memory_order_acquire) ||
        !context->dispatch_enabled.load(std::memory_order_acquire)) {
      continue;
    }
    const HWND window =
        static_cast<HWND>(platform->hwnd.load(std::memory_order_acquire));
    // SendNotifyMessage is asynchronous ONLY across threads. This wait callback
    // never executes on the platform thread, even if the failed post did.
    // It uses sent-message delivery, not the exhausted posted-message queue.
    const DWORD window_thread = GetWindowThreadProcessId(window, nullptr);
    if (window_thread == 0 || window_thread != platform->thread_id ||
        window_thread == GetCurrentThreadId() ||
        !SendNotifyMessageW(window, kPluginMessage, 0,
                            static_cast<LPARAM>(context->dispatch_cookie))) {
      DWORD error = GetLastError();
      if (error == ERROR_SUCCESS) {
        error = ERROR_INVALID_WINDOW_HANDLE;
      }
      context->dispatch_error.store(error, std::memory_order_release);
      context->message_posted.store(false, std::memory_order_release);
      // Both Win32 delivery paths failed. The next platform entry reports the
      // failure to pending callers; the admitted owner remains retained.
    }
  }
}

bool ReserveOwner(const std::shared_ptr<Presentation> &presentation) {
  auto &retained = OwnerRetention();
  if (!retained.ready) {
    return false;
  }
  std::lock_guard<std::mutex> lock(retained.mutex);
  if (retained.next_cookie == 0) {
    return false;
  }
  for (auto &owner : retained.owners) {
    if (!owner) {
      presentation->context->retention = &retained;
      presentation->context->dispatch_cookie = retained.next_cookie++;
      owner = presentation;
      return true;
    }
  }
  return false;
}

void ReleaseOwner(const std::shared_ptr<Presentation> &presentation) {
  presentation->context->dispatch_enabled.store(false,
                                                std::memory_order_release);
  auto &retained = *presentation->context->retention;
  std::lock_guard<std::mutex> lock(retained.mutex);
  for (auto &owner : retained.owners) {
    if (owner == presentation) {
      owner.reset();
      return;
    }
  }
}

const FlutterDesktopGpuSurfaceDescriptor *
Presentation::ObtainDescriptor(size_t /*width*/, size_t /*height*/) {
  CallbackScope callback_scope(this);
  if (context->closing.load(std::memory_order_acquire) ||
      !context->native_created.load(std::memory_order_acquire)) {
    return nullptr;
  }

  // Flutter 3.47.4 ExternalTextureD3d::PopulateTexture reads dimensions AFTER
  // release_callback. Only the next serial call on the same raster thread is a
  // reuse boundary. Reject thread migration/concurrent/reentrant acquisition;
  // an atomic slot-free bit alone cannot protect those post-release reads.
  const DWORD thread = GetCurrentThreadId();
  DWORD expected_thread = 0;
  consumer_thread.compare_exchange_strong(expected_thread, thread,
                                           std::memory_order_acq_rel);
  if ((expected_thread != 0 && expected_thread != thread) ||
      obtaining.test_and_set(std::memory_order_acq_rel)) {
    RdWinTextureError error{};
    InitError(&error);
    error.stage = RD_WIN_STAGE_IMPORT;
    error.native_hresult = ERROR_INVALID_THREAD_ID;
    context->RecordError("concurrent_texture_consumer",
                         RD_WIN_UNSUPPORTED_BACKEND, error);
    return nullptr;
  }
  struct ObtainScope {
    std::atomic_flag &flag;
    ~ObtainScope() { flag.clear(std::memory_order_release); }
  } obtain_scope{obtaining};

  const uint64_t revision = acquire_revision.load(std::memory_order_acquire);
  if (revision == 0) {
    // Flutter may request a texture before the first native frame mark. Seed a
    // worker-side snapshot first; never bootstrap after a BUSY render attempt.
    context->RequireFrame();
    ScheduleWork(kPrepareFrame);
    return nullptr;
  }

  DescriptorSlot *selected = nullptr;
  for (auto &slot : slots) {
    LoanState expected = LoanState::Free;
    if (slot.state.compare_exchange_strong(expected, LoanState::Loaned,
                                           std::memory_order_acq_rel)) {
      selected = &slot;
      break;
    }
  }
  if (selected == nullptr) {
    context->RequireFrame();
    waiting_for_slot.store(true, std::memory_order_release);
    // A return may have freed a slot between the scan and arming this bit.
    // Either that return sees the bit, or this recheck schedules the mark.
    for (const auto &slot : slots) {
      if (slot.state.load(std::memory_order_acquire) == LoanState::Free) {
        if (waiting_for_slot.exchange(false, std::memory_order_acq_rel)) {
          ScheduleWork(kPrepareFrame);
        }
        break;
      }
    }
    return nullptr;
  }
  waiting_for_slot.store(false, std::memory_order_release);
  const uint64_t requested =
      context->frame_requests.load(std::memory_order_acquire);

  RdWinTextureFrame frame{};
  frame.struct_size = sizeof(frame);
  RdWinTextureError error{};
  InitError(&error);
  const RdWinTextureStatus status = context->module->api.acquire(
      context->token.load(std::memory_order_acquire), &frame, &error);
  if (status != RD_WIN_OK) {
    selected->state.store(LoanState::Free, std::memory_order_release);
    if (status == RD_WIN_BUSY) {
      context->RequireFrame();
      retry_acquire_revision.store(revision, std::memory_order_release);
      ScheduleWork(kRetryAcquire);
    } else if (status == RD_WIN_WOULD_BLOCK) {
      // No image is not lock contention. Consume this demand without starting
      // a progress wait that could strand close/loan work on the sole worker.
      context->frame_completed.store(requested, std::memory_order_release);
    } else if (status != RD_WIN_CLOSING) {
      context->RecordError("acquire", status, error);
    }
    return nullptr;
  }
  context->frame_completed.store(requested, std::memory_order_release);

  selected->loan_id = frame.loan_id;
  if (frame.loan_id != 0) {
    outstanding_loans.fetch_add(1, std::memory_order_acq_rel);
  }
  if (frame.struct_size != sizeof(frame) ||
      frame.pixel_format != RD_WIN_PIXEL_BGRA8 ||
      frame.shared_handle == nullptr || frame.loan_id == 0 ||
      frame.width == 0 || frame.height == 0 || frame.visible_width == 0 ||
      frame.visible_height == 0 || frame.visible_width > frame.width ||
      frame.visible_height > frame.height) {
    if (frame.loan_id != 0) {
      selected->state.store(LoanState::Pending, std::memory_order_release);
      ScheduleWork(kReturnLoans);
    } else {
      // An OK acquisition with no returnable identity cannot be accounted for.
      selected->state.store(LoanState::Failed, std::memory_order_release);
    }
    RdWinTextureError invalid_error{};
    InitError(&invalid_error);
    invalid_error.stage = RD_WIN_STAGE_IMPORT;
    invalid_error.native_hresult = ERROR_INVALID_DATA;
    context->RecordError("invalid_descriptor", RD_WIN_UNSUPPORTED_FORMAT,
                         invalid_error);
    return nullptr;
  }

  selected->descriptor = {};
  selected->descriptor.struct_size = sizeof(selected->descriptor);
  selected->descriptor.handle = frame.shared_handle;
  selected->descriptor.width = frame.width;
  selected->descriptor.height = frame.height;
  selected->descriptor.visible_width = frame.visible_width;
  selected->descriptor.visible_height = frame.visible_height;
  selected->descriptor.format = kFlutterDesktopPixelFormatBGRA8888;
  selected->descriptor.release_callback =
      &Presentation::ReleaseDescriptorCallback;
  selected->descriptor.release_context = selected;
  return &selected->descriptor;
}

// This helper is used only by the single lifecycle worker. Bootstrap BEFORE
// the first operation; BUSY waits on that saved revision, never on a snapshot
// taken after the failing call. A successful wait supplies the next snapshot.
template <typename Operation>
RdWinTextureStatus RunWithProgress(Presentation *owner, Operation operation,
                                    RdWinTextureError *error) noexcept {
  const auto &api = owner->context->module->api;
  const uint64_t token = owner->context->token.load(std::memory_order_acquire);
  uint64_t revision = 0;
  InitError(error);
  try {
    RdWinTextureStatus status = api.wait_progress(token, &revision, 0, error);
    if (status != RD_WIN_OK || revision == 0) {
      owner->progress_terminal = true;
      if (status == RD_WIN_OK) {
        error->stage = RD_WIN_STAGE_CLOSE;
        error->native_hresult = ERROR_INVALID_DATA;
        return RD_WIN_RECLAMATION_UNCONFIRMED;
      }
      return status;
    }
    for (;;) {
      if (owner->worker_abandoned.load(std::memory_order_acquire)) {
        owner->progress_terminal = true;
        InitError(error);
        error->stage = RD_WIN_STAGE_CLOSE;
        return RD_WIN_CLOSING;
      }
      InitError(error);
      status = operation(error);
      if (status != RD_WIN_BUSY) {
        return status;
      }
      const uint64_t previous = revision;
      InitError(error);
      status = api.wait_progress(token, &revision, 0, error);
      if (status != RD_WIN_OK) {
        owner->progress_terminal = true;
        return status;
      }
      if (revision == 0 || revision == previous) {
        owner->progress_terminal = true;
        error->stage = RD_WIN_STAGE_CLOSE;
        error->native_hresult = ERROR_INVALID_DATA;
        return RD_WIN_RECLAMATION_UNCONFIRMED;
      }
    }
  } catch (...) {
    owner->progress_terminal = true;
    InitError(error);
    error->stage = RD_WIN_STAGE_CLOSE;
    error->native_hresult = ERROR_UNHANDLED_EXCEPTION;
    return RD_WIN_RECLAMATION_UNCONFIRMED;
  }
}

void Presentation::ScheduleWork(uint32_t commands) noexcept {
  if (worker_abandoned.load(std::memory_order_acquire) ||
      worker_exited.load(std::memory_order_acquire)) {
    return;
  }
  worker_commands.fetch_or(commands, std::memory_order_acq_rel);
  if (!SetEvent(worker_event)) {
    RdWinTextureError error{};
    InitError(&error);
    error.stage = RD_WIN_STAGE_CLOSE;
    error.native_hresult = GetLastError();
    context->RecordError("lifecycle_worker_dispatch", RD_WIN_NATIVE_FAILURE,
                         error);
  }
}

void Presentation::CancelProgressWaits() noexcept {
  // Sticky abandonment, never normal dispose. Waking the local event also
  // retires an idle worker; flags=1 wakes a worker blocked in native progress.
  worker_abandoned.store(true, std::memory_order_release);
  context->closing.store(true, std::memory_order_release);
  SetEvent(worker_event);
  const uint64_t token = context->token.load(std::memory_order_acquire);
  if (token == 0) {
    return; // Pending create repeats cancellation once it publishes its token.
  }
  uint64_t revision = 0;
  RdWinTextureError error{};
  InitError(&error);
  const auto status = context->module->api.wait_progress(token, &revision, 1,
                                                        &error);
  if (status != RD_WIN_OK) {
    context->RecordError("cancel_progress_waits", status, error);
  }
  // An OK cancellation acknowledgement is NOT a disposal acknowledgement.
}

void Presentation::ReturnLoan(DescriptorSlot *slot) noexcept {
  RdWinTextureError error{};
  const RdWinTextureStatus status = RunWithProgress(
      this,
      [this, slot](RdWinTextureError *error) {
        return context->module->api.release(
            context->token.load(std::memory_order_acquire), slot->loan_id, error);
      },
      &error);
  if (status == RD_WIN_OK) {
    slot->loan_id = 0;
    outstanding_loans.fetch_sub(1, std::memory_order_acq_rel);
    slot->state.store(LoanState::Free, std::memory_order_release);
    if (waiting_for_slot.exchange(false, std::memory_order_acq_rel)) {
      ScheduleWork(kPrepareFrame);
    }
    if (context->closing.load(std::memory_order_acquire)) {
      context->PostPlatformMessage();
    }
  } else {
    slot->state.store(LoanState::Failed, std::memory_order_release);
    context->RecordError("release_import_loan", status, error);
  }
  // Descriptor metadata is never touched by this worker, including after OK.
}

void Presentation::ReleaseDescriptor(DescriptorSlot *slot) noexcept {
  CallbackScope callback_scope(this);
  if (consumer_thread.load(std::memory_order_acquire) != GetCurrentThreadId()) {
    RdWinTextureError error{};
    InitError(&error);
    error.stage = RD_WIN_STAGE_IMPORT;
    error.native_hresult = ERROR_INVALID_THREAD_ID;
    context->RecordError("concurrent_texture_release",
                         RD_WIN_UNSUPPORTED_BACKEND, error);
  }
  LoanState expected = LoanState::Loaned;
  if (slot->state.compare_exchange_strong(expected, LoanState::Pending,
                                          std::memory_order_acq_rel)) {
    ScheduleWork(kReturnLoans);
  }
}

void Presentation::ReturnPendingLoans() noexcept {
  for (auto &slot : slots) {
    if (progress_terminal || worker_abandoned.load(std::memory_order_acquire)) {
      return;
    }
    LoanState expected = LoanState::Pending;
    if (slot.state.compare_exchange_strong(expected, LoanState::Returning,
                                           std::memory_order_acq_rel)) {
      ReturnLoan(&slot);
    }
  }
}

void Presentation::PrepareFrame(bool retry_acquire) noexcept {
  if (!context->NeedsFrame() ||
      context->closing.load(std::memory_order_acquire) ||
      waiting_for_slot.load(std::memory_order_acquire)) {
    return;
  }
  uint64_t revision = retry_acquire
                          ? retry_acquire_revision.load(std::memory_order_acquire)
                          : 0;
  const uint64_t previous = revision;
  RdWinTextureError error{};
  InitError(&error);
  RdWinTextureStatus status;
  if (retry_acquire && revision == 0) {
    status = RD_WIN_RECLAMATION_UNCONFIRMED;
    error.stage = RD_WIN_STAGE_IMPORT;
    error.native_hresult = ERROR_INVALID_DATA;
  } else {
    try {
      status = context->module->api.wait_progress(
          context->token.load(std::memory_order_acquire), &revision, 0, &error);
    } catch (...) {
      status = RD_WIN_RECLAMATION_UNCONFIRMED;
      error.stage = RD_WIN_STAGE_IMPORT;
      error.native_hresult = ERROR_UNHANDLED_EXCEPTION;
    }
  }
  if (status == RD_WIN_OK &&
      (revision == 0 || (retry_acquire && revision == previous))) {
    status = RD_WIN_RECLAMATION_UNCONFIRMED;
    error.stage = RD_WIN_STAGE_IMPORT;
    error.native_hresult = ERROR_INVALID_DATA;
  }
  if (status != RD_WIN_OK) {
    progress_terminal = true;
    context->RecordError("acquire_progress", status, error);
    return;
  }
  acquire_revision.store(revision, std::memory_order_release);
  // Another render can have satisfied the demand while this worker waited.
  // Only an outstanding demand can produce a replacement frame mark.
  if (context->NeedsFrame() &&
      !context->closing.load(std::memory_order_acquire) &&
      !waiting_for_slot.load(std::memory_order_acquire)) {
    frame_ready.store(true, std::memory_order_release);
    context->PostPlatformMessage();
  }
}

namespace {

void RunLifecycleWorker(const std::shared_ptr<Presentation> &presentation) {
  const auto &context = presentation->context;
  const uint64_t token = context->token.load(std::memory_order_acquire);
  for (;;) {
    if (presentation->worker_abandoned.load(std::memory_order_acquire) ||
        !context->platform->alive.load(std::memory_order_acquire)) {
      presentation->CancelProgressWaits();
      return;
    }
    if (presentation->progress_terminal) {
      return;
    }
    const uint32_t commands = presentation->worker_commands.exchange(
        0, std::memory_order_acq_rel);
    if (commands == 0) {
      if (WaitForSingleObject(presentation->worker_event, INFINITE) !=
          WAIT_OBJECT_0) {
        RdWinTextureError error{};
        InitError(&error);
        error.stage = RD_WIN_STAGE_CLOSE;
        error.native_hresult = GetLastError();
        context->RecordError("lifecycle_worker_wait", RD_WIN_NATIVE_FAILURE,
                             error);
        return;
      }
      continue;
    }
    if ((commands & kReturnLoans) != 0) {
      presentation->ReturnPendingLoans();
    }
    if (presentation->progress_terminal ||
        presentation->worker_abandoned.load(std::memory_order_acquire)) {
      continue;
    }
    if ((commands & kRequestClose) != 0) {
      RdWinTextureError error{};
      const auto status = RunWithProgress(
          presentation.get(),
          [&context, token](RdWinTextureError *error) {
            return context->module->api.request_close(token, error);
          },
          &error);
      if (status == RD_WIN_OK) {
        presentation->close_complete.store(true, std::memory_order_release);
        context->PostPlatformMessage();
      } else {
        context->RecordError("request_close", status, error);
      }
    }
    if (presentation->progress_terminal ||
        presentation->worker_abandoned.load(std::memory_order_acquire)) {
      continue;
    }
    if ((commands & kRegistrationRetired) != 0) {
      RdWinTextureError error{};
      const auto status = RunWithProgress(
          presentation.get(),
          [&context, token](RdWinTextureError *error) {
            return context->module->api.registration_retired(token, error);
          },
          &error);
      if (status == RD_WIN_OK) {
        presentation->registration_retired.store(true,
                                                std::memory_order_release);
        context->PostPlatformMessage();
      } else {
        context->RecordError("registration_retired", status, error);
      }
    }
    if (presentation->progress_terminal ||
        presentation->worker_abandoned.load(std::memory_order_acquire)) {
      continue;
    }
    if ((commands & kDispose) != 0) {
      RdWinTextureError error{};
      const auto status = RunWithProgress(
          presentation.get(),
          [&context, token](RdWinTextureError *error) {
            return context->module->api.dispose(token, error);
          },
          &error);
      presentation->dispose_status = status;
      presentation->dispose_error = error;
      presentation->dispose_signal.store(true, std::memory_order_release);
      context->PostPlatformMessage();
      if (status == RD_WIN_OK &&
          !context->platform->alive.load(std::memory_order_acquire)) {
        ReleaseOwner(presentation);
      }
      // No waiter survives successful dispose; no further native call or
      // callback-userdata access through the engine follows this operation.
      return;
    }
    if ((commands & kRetryAcquire) != 0) {
      presentation->PrepareFrame(true);
    } else if ((commands & kPrepareFrame) != 0) {
      presentation->PrepareFrame(false);
    }
  }
}

void StartNativeCreate(const std::shared_ptr<Presentation> &presentation,
                       uint32_t luid_low, int32_t luid_high) {
  try {
    // Exactly one thread per admitted presentation, through create, import
    // returns and teardown. Frame callbacks enqueue bounded bits, not threads.
    std::thread([presentation, luid_low, luid_high]() {
      struct WorkerExit {
        Presentation *owner;
        ~WorkerExit() {
          owner->worker_exited.store(true, std::memory_order_release);
        }
      } worker_exit{presentation.get()};
      RdWinTextureCreate options{};
      options.struct_size = sizeof(options);
      options.adapter_luid_low = luid_low;
      options.adapter_luid_high = luid_high;
      options.wake = &Presentation::WakeCallback;
      options.context = presentation->context.get();
      RdWinTextureToken token = 0;
      RdWinTextureError error{};
      InitError(&error);
      RdWinTextureStatus status;
      try {
        status = presentation->context->module->api.create(&options, &token,
                                                           &error);
      } catch (...) {
        status = RD_WIN_RECLAMATION_UNCONFIRMED;
        error.stage = RD_WIN_STAGE_DEVICE;
        error.native_hresult = ERROR_UNHANDLED_EXCEPTION;
      }
      if (status == RD_WIN_OK && token == 0) {
        status = RD_WIN_RECLAMATION_UNCONFIRMED;
        error.stage = RD_WIN_STAGE_VALIDATE;
        error.native_hresult = ERROR_INVALID_DATA;
      }
      if (status == RD_WIN_OK) {
        presentation->context->token.store(token, std::memory_order_release);
        presentation->context->native_created.store(true,
                                                    std::memory_order_release);
      }
      presentation->context->create_status = status;
      presentation->context->create_error = error;
      presentation->context->create_done.store(true, std::memory_order_release);
      presentation->context->PostPlatformMessage();
      if (status == RD_WIN_OK) {
        RunLifecycleWorker(presentation);
      } else if (status != RD_WIN_RECLAMATION_UNCONFIRMED &&
                 !presentation->context->platform->alive.load(
                     std::memory_order_acquire)) {
        ReleaseOwner(presentation);
      }
    }).detach();
  } catch (...) {
    // No native call was admitted if the worker could not be started.
    presentation->worker_exited.store(true, std::memory_order_release);
    presentation->context->create_status = RD_WIN_NATIVE_FAILURE;
    InitError(&presentation->context->create_error);
    presentation->context->create_error.stage = RD_WIN_STAGE_DEVICE;
    presentation->context->create_error.native_hresult = ERROR_NOT_ENOUGH_MEMORY;
    presentation->context->create_done.store(true, std::memory_order_release);
    presentation->context->PostPlatformMessage();
  }
}


} // namespace

void RdEngineTexturePlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows *registrar) {
  if (registrar == nullptr) {
    return;
  }
  auto plugin = std::make_unique<RdEngineTexturePlugin>(registrar);
  auto *plugin_pointer = plugin.get();
  plugin->channel_ =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(), kMethodChannel,
          &flutter::StandardMethodCodec::GetInstance());
  plugin->channel_->SetMethodCallHandler(
      [plugin_pointer](const auto &call, auto result) {
        plugin_pointer->HandleMethodCall(call, std::move(result));
      });
  plugin->window_proc_delegate_id_ =
      registrar->RegisterTopLevelWindowProcDelegate(
          [plugin_pointer](HWND hwnd, UINT message, WPARAM wparam,
                           LPARAM lparam) {
            return plugin_pointer->OnTopLevelWindowProc(hwnd, message, wparam,
                                                        lparam);
          });
  registrar->AddPlugin(std::move(plugin));
}

RdEngineTexturePlugin::RdEngineTexturePlugin(
    flutter::PluginRegistrarWindows *registrar)
    : registrar_(registrar),
      texture_registrar_(registrar != nullptr ? registrar->texture_registrar()
                                              : nullptr),
      platform_state_(std::make_shared<PlatformState>()) {
  module_ = LoadEngineModule(&module_error_, &module_error_code_);
}

RdEngineTexturePlugin::~RdEngineTexturePlugin() {
  shutting_down_ = true;
  platform_state_->alive.store(false, std::memory_order_release);
  if (channel_) {
    channel_->SetMethodCallHandler(nullptr);
  }
  if (registrar_ != nullptr && window_proc_delegate_id_ != 0) {
    registrar_->UnregisterTopLevelWindowProcDelegate(window_proc_delegate_id_);
    window_proc_delegate_id_ = 0;
  }

  auto abandon = [](const std::shared_ptr<Presentation> &presentation) {
    const auto &context = presentation->context;
    context->dispatch_enabled.store(false, std::memory_order_release);
    context->closing.store(true, std::memory_order_release);
    if (presentation->create_result) {
      presentation->create_result->Error(
          "plugin_shutdown", "Registrar retired; native cleanup is unconfirmed");
      presentation->create_result.reset();
    }
    if (presentation->dispose_result) {
      presentation->dispose_result->Error(
          "plugin_shutdown", "Registrar retired; native cleanup is unconfirmed");
      presentation->dispose_result.reset();
    }
    if ((presentation->dispose_signal.load(std::memory_order_acquire) &&
         presentation->dispose_status == RD_WIN_OK) ||
        (context->create_done.load(std::memory_order_acquire) &&
         context->create_status != RD_WIN_OK &&
         context->create_status != RD_WIN_RECLAMATION_UNCONFIRMED)) {
      ReleaseOwner(presentation);
      return;
    }
    presentation->CancelProgressWaits();
    // Already owned by the reserved process-lifetime slot, including a create
    // that has not returned yet. No overflow decision is made during teardown.
    presentation->quarantined = true;
  };
  for (const auto &pair : presentations_) {
    abandon(pair.second);
  }
  for (const auto &pending : pending_) {
    abandon(pending);
  }
  presentations_.clear();
  pending_.clear();
}

void RdEngineTexturePlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue> &method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  RecoverDispatchFailures();
  if (method_call.method_name() == "create") {
    StartCreate(std::shared_ptr<MethodResult>(std::move(result)));
    return;
  }

  if (method_call.method_name() == "dispose") {
    const auto *arguments = method_call.arguments();
    if (arguments == nullptr ||
        !std::holds_alternative<flutter::EncodableMap>(*arguments)) {
      result->Error("invalid_argument",
                    "dispose requires a presentationToken string");
      return;
    }
    const auto &map = std::get<flutter::EncodableMap>(*arguments);
    const auto key = map.find(flutter::EncodableValue("presentationToken"));
    if (key == map.end() || !std::holds_alternative<std::string>(key->second)) {
      result->Error("invalid_argument",
                    "dispose requires a presentationToken string");
      return;
    }
    uint64_t token = 0;
    if (!ParseDecimalToken(std::get<std::string>(key->second), &token)) {
      result->Error("invalid_argument", "presentationToken is not decimal");
      return;
    }
    auto presentation = FindPresentation(token);
    if (!presentation) {
      result->Error("invalid_token", "presentation token is not live");
      return;
    }
    if (presentation->quarantined) {
      result->Error(presentation->failure_code,
                    presentation->failure_message);
      return;
    }
    if (presentation->dispose_result) {
      result->Error("busy", "this presentation is already closing");
      return;
    }
    presentation->dispose_result =
        std::shared_ptr<MethodResult>(std::move(result));
    ProcessPresentationMessage(presentation);
    if (!presentation->disposed && !presentation->quarantined) {
      RequestClose(presentation);
    }
    return;
  }

  result->NotImplemented();
}

void RdEngineTexturePlugin::StartCreate(MethodResultPtr result) {
  if (shutting_down_ || window_close_requested_) {
    result->Error("plugin_shutdown", "Windows texture plugin is closing");
    return;
  }
  if (module_ == nullptr || texture_registrar_ == nullptr) {
    result->Error(module_ == nullptr ? module_error_code_ : "native_unavailable",
                  module_ == nullptr ? module_error_
                                     : "Flutter texture registrar unavailable");
    return;
  }
  if (presentations_.size() + pending_.size() >= kMaxPresentations) {
    result->Error("owner_limit", "too many live Windows presentations");
    return;
  }

  uint32_t luid_low = 0;
  int32_t luid_high = 0;
  if (!GetFlutterAdapterLuid(&luid_low, &luid_high)) {
    result->Error("unsupported_backend", "Flutter D3D adapter is unavailable");
    return;
  }

  auto context = std::make_shared<PresentationContext>();
  context->module = module_;
  context->platform = platform_state_;
  auto presentation = std::make_shared<Presentation>(std::move(context));
  presentation->worker_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  if (presentation->worker_event == nullptr) {
    result->Error("native_failure", "Cannot allocate texture lifecycle event");
    return;
  }
  if (!ReserveOwner(presentation)) {
    result->Error(OwnerRetention().ready ? "owner_limit" : "platform_dispatch_failed",
                  "Cannot reserve process-wide callback retention and delivery");
    return;
  }
  presentation->create_result = std::move(result);
  pending_.push_back(presentation);
  StartNativeCreate(presentation, luid_low, luid_high);
}

bool RdEngineTexturePlugin::GetFlutterAdapterLuid(uint32_t *low,
                                                  int32_t *high) {
  if (registrar_ == nullptr || registrar_->GetView() == nullptr) {
    return false;
  }
  auto *view = registrar_->GetView();
  const HWND child = view->GetNativeWindow();
  const HWND hwnd = child == nullptr ? nullptr : GetAncestor(child, GA_ROOT);
  if (hwnd == nullptr || GetWindowThreadProcessId(hwnd, nullptr) != GetCurrentThreadId()) {
    return false;
  }
  platform_state_->hwnd.store(hwnd, std::memory_order_release);

  IDXGIAdapter *adapter = view->GetGraphicsAdapter();
  if (adapter == nullptr) {
    return false;
  }
  DXGI_ADAPTER_DESC desc{};
  const HRESULT hr = adapter->GetDesc(&desc);
  adapter->Release();
  if (FAILED(hr)) {
    return false;
  }
  *low = desc.AdapterLuid.LowPart;
  *high = desc.AdapterLuid.HighPart;
  return true;
}

std::shared_ptr<Presentation>
RdEngineTexturePlugin::FindPresentation(uint64_t token) const {
  const auto found = presentations_.find(token);
  return found == presentations_.end() ? nullptr : found->second;
}

void RdEngineTexturePlugin::RecoverDispatchFailures() {
  auto recover = [this](const std::shared_ptr<Presentation> &presentation) {
    const DWORD error = presentation->context->dispatch_error.exchange(
        ERROR_SUCCESS, std::memory_order_acq_rel);
    if (error != ERROR_SUCCESS) {
      const std::string message =
          "Windows callback delivery failed (Win32 " + std::to_string(error) +
          "); owner retained, cleanup unconfirmed";
      FailPresentation(presentation, "platform_dispatch_failed", message.c_str());
    }
  };
  for (const auto &pending : pending_) {
    recover(pending);
  }
  for (const auto &pair : presentations_) {
    recover(pair.second);
  }
}

std::optional<LRESULT>
RdEngineTexturePlugin::OnTopLevelWindowProc(HWND hwnd, UINT message,
                                            WPARAM /*wparam*/, LPARAM lparam) {
  const HWND runner_window = static_cast<HWND>(
      platform_state_->hwnd.load(std::memory_order_acquire));
  if (runner_window == nullptr || hwnd != runner_window) {
    return std::nullopt;
  }

  RecoverDispatchFailures();
  if (message == kPluginMessage) {
    const uint64_t cookie = static_cast<uint64_t>(lparam);
    std::shared_ptr<Presentation> presentation;
    for (const auto &pending : pending_) {
      if (pending->context->dispatch_cookie == cookie) {
        presentation = pending;
        break;
      }
    }
    if (!presentation) {
      for (const auto &pair : presentations_) {
        if (pair.second->context->dispatch_cookie == cookie) {
          presentation = pair.second;
          break;
        }
      }
    }
    if (presentation) {
      ProcessPresentationMessage(presentation);
    }
    return static_cast<LRESULT>(0);
  }

  if (message == WM_CLOSE) {
    if (allow_window_close_) {
      allow_window_close_ = false;
      return std::nullopt;
    }
    if (!pending_.empty() || !presentations_.empty()) {
      window_close_requested_ = true;
      RequestWindowClose();
      return static_cast<LRESULT>(0);
    }
  }
  return std::nullopt;
}

void RdEngineTexturePlugin::ProcessPresentationMessage(
    const std::shared_ptr<Presentation> &presentation) {
  const auto &context = presentation->context;
  context->message_posted.store(false, std::memory_order_release);
  if (context->create_done.load(std::memory_order_acquire) &&
      !presentation->create_handled) {
    HandleCreateCompleted(presentation);
  }
  if (!presentation->create_handled ||
      !context->native_created.load(std::memory_order_acquire)) {
    MaybeContinueWindowClose();
    return;
  }

  const uint32_t reasons = context->wake_reasons.exchange(
      0, std::memory_order_acq_rel);
  if (reasons != 0) {
    ProcessWakeReasons(presentation, reasons);
  }
  if (presentation->frame_ready.exchange(false, std::memory_order_acq_rel) &&
      context->NeedsFrame() && presentation->registered &&
      !presentation->close_requested &&
      !context->closing.load(std::memory_order_acquire) &&
      !presentation->waiting_for_slot.load(std::memory_order_acquire)) {
    if (!texture_registrar_->MarkTextureFrameAvailable(
            presentation->texture_id)) {
      RdWinTextureError error{};
      InitError(&error);
      error.stage = RD_WIN_STAGE_IMPORT;
      error.native_hresult = ERROR_NOT_FOUND;
      context->RecordError("mark_frame_available", RD_WIN_NATIVE_FAILURE, error);
    }
  }
  if (presentation->close_complete.load(std::memory_order_acquire)) {
    presentation->close_handed_off = true;
  }
  if (!presentation->error_handled &&
      context->error_state.load(std::memory_order_acquire) == 2) {
    presentation->error_handled = true;
    FailPresentation(
        presentation, StatusName(context->first_error_status),
        NativeFailureMessage(context->first_error_operation,
                             context->first_error_status,
                             context->first_error).c_str());
  }
  if (presentation->dispose_signal.load(std::memory_order_acquire)) {
    CompleteDisposed(presentation);
  }
  if (!presentation->disposed && presentation->close_requested) {
    RequestClose(presentation);
  }
  if (!presentation->disposed && !presentation->quarantined) {
    TryRegistrationRetired(presentation);
    TryDispose(presentation);
  }
  MaybeContinueWindowClose();
}

void RdEngineTexturePlugin::HandleCreateCompleted(
    const std::shared_ptr<Presentation> &presentation) {
  presentation->create_handled = true;
  const auto &context = presentation->context;
  const RdWinTextureStatus status = context->create_status;
  if (status != RD_WIN_OK) {
    if (status == RD_WIN_RECLAMATION_UNCONFIRMED) {
      // No usable token; keep the pending slot visibly unconfirmed and block
      // normal window-close acknowledgement. Retention is already guaranteed.
      FailPresentation(presentation, StatusName(status),
                       NativeFailureMessage("create", status,
                                            context->create_error).c_str());
      return;
    }
    if (presentation->create_result) {
      presentation->create_result->Error(
          StatusName(status),
          NativeFailureMessage("create", status, context->create_error));
      presentation->create_result.reset();
    }
    pending_.erase(std::remove(pending_.begin(), pending_.end(), presentation),
                   pending_.end());
    ReleaseOwner(presentation);
    return;
  }

  const uint64_t token = context->token.load(std::memory_order_acquire);
  presentations_.emplace(token, presentation);
  pending_.erase(std::remove(pending_.begin(), pending_.end(), presentation),
                 pending_.end());
  if (presentation->close_requested || window_close_requested_ ||
      presentation->quarantined) {
    // A close during create never registers a new texture or returns a token
    // as usable. Complete the native producer/unregister/dispose handshake.
    if (presentation->create_result) {
      presentation->create_result->Error("closing",
                                         "Creation cancelled by window close");
      presentation->create_result.reset();
    }
    RequestClose(presentation);
    return;
  }

  const int64_t texture_id =
      texture_registrar_->RegisterTexture(&presentation->texture);
  if (texture_id < 0) {
    if (presentation->create_result) {
      presentation->create_result->Error(
          "texture_registration_failed",
          "Flutter rejected the Windows GPU texture registration");
      presentation->create_result.reset();
    }
    RequestClose(presentation);
    return;
  }
  presentation->texture_id = texture_id;
  presentation->registered = true;
  if (presentation->create_result) {
    flutter::EncodableMap response;
    response.emplace(flutter::EncodableValue("presentationToken"),
                     flutter::EncodableValue(DecimalToken(token)));
    response.emplace(flutter::EncodableValue("textureId"),
                     flutter::EncodableValue(texture_id));
    presentation->create_result->Success(flutter::EncodableValue(response));
    presentation->create_result.reset();
  }
}

void RdEngineTexturePlugin::ProcessWakeReasons(
    const std::shared_ptr<Presentation> &presentation, uint32_t reasons) {
  if ((reasons & RD_WIN_WAKE_FRAME_AVAILABLE) != 0 &&
      presentation->registered && !presentation->close_requested &&
      !presentation->context->closing.load(std::memory_order_acquire)) {
    presentation->ScheduleWork(kPrepareFrame);
  }

  if ((reasons & RD_WIN_WAKE_UNREGISTER_REQUESTED) != 0) {
    presentation->native_unregister_ready = true;
    presentation->close_handed_off = true;
    presentation->close_requested = true;
    presentation->context->closing.store(true, std::memory_order_release);
    if (presentation->registered && !presentation->unregister_started) {
      StartFlutterUnregister(presentation);
    } else if (!presentation->registered) {
      presentation->flutter_unregister_complete.store(
          true, std::memory_order_release);
    }
  }
}

void RdEngineTexturePlugin::StartFlutterUnregister(
    const std::shared_ptr<Presentation> &presentation) {
  if (!presentation->registered || presentation->unregister_started ||
      texture_registrar_ == nullptr) {
    return;
  }
  presentation->unregister_started = true;
  texture_registrar_->UnregisterTexture(
      presentation->texture_id, [presentation]() {
        presentation->flutter_unregister_complete.store(
            true, std::memory_order_release);
        presentation->context->PostPlatformMessage();
      });
}

void RdEngineTexturePlugin::TryRegistrationRetired(
    const std::shared_ptr<Presentation> &presentation) {
  if (presentation->retirement_started || presentation->quarantined ||
      !presentation->native_unregister_ready ||
      !presentation->flutter_unregister_complete.load(
          std::memory_order_acquire) ||
      presentation->callback_users.load(std::memory_order_acquire) != 0 ||
      presentation->outstanding_loans.load(std::memory_order_acquire) != 0) {
    return;
  }
  presentation->retirement_started = true;
  presentation->ScheduleWork(kRegistrationRetired);
}

void RdEngineTexturePlugin::TryDispose(
    const std::shared_ptr<Presentation> &presentation) {
  if (!presentation->registration_retired.load(std::memory_order_acquire) ||
      presentation->disposed || presentation->quarantined ||
      presentation->dispose_started) {
    return;
  }
  presentation->dispose_started = true;
  presentation->ScheduleWork(kDispose);
}

void RdEngineTexturePlugin::CompleteDisposed(
    const std::shared_ptr<Presentation> &presentation) {
  if (!presentation->dispose_signal.exchange(false,
                                             std::memory_order_acq_rel)) {
    return;
  }
  const RdWinTextureStatus status = presentation->dispose_status;
  if (status == RD_WIN_OK) {
    presentation->disposed = true;
    presentation->registered = false;
    presentation->context->native_created.store(false,
                                                std::memory_order_release);
    if (presentation->dispose_result) {
      presentation->dispose_result->Success();
      presentation->dispose_result.reset();
    }
    const uint64_t token =
        presentation->context->token.load(std::memory_order_acquire);
    presentations_.erase(token);
    ReleaseOwner(presentation);
    return;
  }


  FailPresentation(
      presentation, StatusName(status),
      NativeFailureMessage("dispose", status, presentation->dispose_error).c_str());
}

void RdEngineTexturePlugin::RequestClose(
    const std::shared_ptr<Presentation> &presentation) {
  presentation->close_requested = true;
  presentation->context->closing.store(true, std::memory_order_release);
  if (!presentation->context->create_done.load(std::memory_order_acquire) ||
      !presentation->context->native_created.load(std::memory_order_acquire) ||
      presentation->disposed || presentation->close_handed_off ||
      presentation->close_started) {
    return;
  }
  presentation->close_started = true;
  presentation->ScheduleWork(kRequestClose);
}

void RdEngineTexturePlugin::RequestWindowClose() {
  for (const auto &pending : pending_) {
    pending->close_requested = true;
    pending->context->closing.store(true, std::memory_order_release);
  }
  for (const auto &pair : presentations_) {
    RequestClose(pair.second);
  }
  MaybeContinueWindowClose();
}

void RdEngineTexturePlugin::MaybeContinueWindowClose() {
  if (!window_close_requested_ || !pending_.empty() ||
      !presentations_.empty()) {
    return;
  }
  if (allow_window_close_ || shutting_down_) {
    return;
  }
  const HWND hwnd =
      static_cast<HWND>(platform_state_->hwnd.load(std::memory_order_acquire));
  if (hwnd == nullptr) {
    return;
  }
  allow_window_close_ = true;
  if (!PostMessageW(hwnd, WM_CLOSE, 0, 0)) {
    allow_window_close_ = false;
  }
}

void RdEngineTexturePlugin::FailPresentation(
    const std::shared_ptr<Presentation> &presentation, const char *code,
    const char *message) {
  if (!presentation->quarantined) {
    presentation->failure_code = code;
    presentation->failure_message =
        std::string(message) + "; owner retained; cleanup unconfirmed";
    presentation->quarantined = true;
    std::cerr << "rd_engine_texture: " << presentation->failure_code << ": "
              << presentation->failure_message << std::endl;
  }
  if (presentation->create_result) {
    presentation->create_result->Error(presentation->failure_code,
                                       presentation->failure_message);
    presentation->create_result.reset();
  }
  if (presentation->dispose_result) {
    presentation->dispose_result->Error(presentation->failure_code,
                                        presentation->failure_message);
    presentation->dispose_result.reset();
  }
  // Stop admitting descriptors/producers, but never claim registration or
  // reclamation while an unresolved loan or another error remains.
  RequestClose(presentation);
}



} // namespace rd_engine_texture

extern "C" FLUTTER_PLUGIN_EXPORT void
RdEngineTexturePluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  if (registrar == nullptr) {
    return;
  }
  auto *plugin_registrar = flutter::PluginRegistrarManager::GetInstance()
                               ->GetRegistrar<flutter::PluginRegistrarWindows>(
                                   registrar);
  if (plugin_registrar == nullptr) {
    return;
  }
  rd_engine_texture::RdEngineTexturePlugin::RegisterWithRegistrar(
      plugin_registrar);
}
