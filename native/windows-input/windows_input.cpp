#define RD_INPUT_BUILD
#include "windows_input.h"

#if !defined(_WIN32)
#error "windows_input.cpp is Windows-only"
#endif

#include <windows.h>

#include <atomic>
#include <cstring>

/*
 * See windows_input.h for the contract. Everything in this file is Win32 that
 * the Rust adapter cannot express itself: the input-desktop classification, the
 * guarded SendInput batch, the character->virtual-key translation, and the
 * observation guard.
 *
 * The guard is one process-wide object: a dedicated message thread with
 * WH_KEYBOARD_LL and WH_MOUSE_LL, a fixed table of per-key observations, a fixed
 * table of descriptors for the hold events of the transaction currently being
 * injected, and the one buffer a batch is built in. The hook callbacks take one
 * exclusive SRW lock - a blocking acquisition, not a try-lock, though it is
 * only ever held for a bounded number of fixed-table operations - and never
 * allocate, never do I/O, never call into the caller and never wait for the
 * sending thread. The sending thread publishes the descriptors before SendInput
 * and never holds that lock across SendInput, a sleep, a hook-chain call or a
 * sampling call, so a callback that arrives while the send is in flight cannot
 * wait on the sender for more than such an operation. The batch buffer is the
 * guard's own and is filled under a separate send lock that no callback ever
 * takes, so a batch neither allocates nor shares a buffer with another sender.
 */

namespace {

constexpr uint32_t kWheelDelta = 120;
constexpr uint32_t kMaxWheelNotches = 255;
constexpr int32_t kMaxNormalizedCoordinate = 65535;
constexpr uint32_t kMaxVirtualKey = 0xFE;
constexpr uint32_t kMaxScanCode = 0xFFFF;
constexpr uint32_t kKnownEventFlags =
    RD_INPUT_KEY_UP | RD_INPUT_KEY_EXTENDED | RD_INPUT_KEY_SCANCODE;

/* The canonical hold key space: a virtual key, or that key with the E0 form
 * folded in as 0x100. */
constexpr uint32_t kHoldKeys = 0x200;
/* Hold events one transaction may carry. The caller bounds a batch the same
 * way; a batch that exceeds this is refused before anything is injected. */
constexpr uint32_t kMaxDescriptors = RD_INPUT_MAX_HOLDS;
/* Events one batch may carry, mirroring the caller's own bound. */
constexpr uint32_t kMaxEvents = RD_INPUT_MAX_EVENTS;
/* Leases one guard serves at once. */
constexpr uint32_t kMaxLeases = 8;
/* How long a submitted hold event's receipt may take to become terminal before
 * the guard treats the missing receipt as a fault. SendInput does not return
 * until the hook has run for the events it inserted, so this is a bound on the
 * case where it did not run at all. */
constexpr uint32_t kReceiptWaitMs = 50;
constexpr uint32_t kHeartbeatPeriodMs = 250;
/* A heartbeat older than this says the message thread stopped pumping. It says
 * nothing about whether the hook is still in the chain. */
constexpr uint32_t kHeartbeatTimeoutMs = 2000;
constexpr uint32_t kThreadWaitMs = 5000;
constexpr uint32_t kStopWaitMs = 2000;
/* Mouse hook delivery can discard the high 32 bits of dwExtraInfo even on
 * x64. Mint both input kinds in the common uint32 range. The persistent issued
 * interval recognizes retired tokens without reusing values or truncating a
 * callback's full-width value. This is association, not source authentication. */
constexpr uint64_t kTokenBase = 0x5244494eull;
constexpr uint32_t kMaxTokenSerial =
    static_cast<uint32_t>(0xFFFFFFFFull - kTokenBase);
/* A serial that must never be reused and that a stale value must never compare
 * as current one: at this value the guard latches admission closed instead of
 * handing out another one. */
constexpr uint32_t kMaxSerial = 0xFFFFFFFFu;
/* The observation sequence is never reused either. It is 64 bits wide AND
 * latched at its end: it neither wraps in any practical time nor wraps at all. */
constexpr uint64_t kObservationLimit = 0xFFFFFFFFFFFFFFFFull;
/* The id the heartbeat timer is asked for. SetTimer is free to ignore it and
 * assign another one, and to fail, so the id it returns is what this file uses. */
constexpr UINT_PTR kHeartbeatTimerRequest = 1;
constexpr UINT kGuardStopMessage = WM_USER + 0x51;
constexpr uint32_t kNoDescriptor = 0xFFFFFFFFu;

bool desktop_name(HDESK desktop, wchar_t* buffer, size_t characters) {
  if (desktop == nullptr || buffer == nullptr || characters == 0) return false;
  DWORD needed = 0;
  if (!GetUserObjectInformationW(desktop, UOI_NAME, buffer,
                                 static_cast<DWORD>(characters * sizeof(wchar_t)),
                                 &needed)) {
    buffer[0] = L'\0';
    return false;
  }
  buffer[characters - 1] = L'\0';
  return buffer[0] != L'\0';
}

/*
 * The input desktop of this session, classified. Read-only: the handle is opened
 * for DESKTOP_READOBJECTS and closed again.
 *
 * The desktop handle exposes a name but no session identity, so two sessions
 * that both sit on a desktop named "Default" are indistinguishable here. That
 * does not become a false success: injections aimed at another session's input
 * desktop fail inside SendInput and are reported as INJECTION_FAILED, never as
 * OK. This check exists to keep the adapter off the secure desktop (Winlogon,
 * the UAC prompt) and off any desktop the calling thread does not own, and the
 * guard treats anything but the ordinary interactive desktop as a lost epoch.
 */
uint32_t classify_desktop() {
  HDESK input = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
  if (input == nullptr) {
    /* No readable input desktop: a disconnected session, a service without a
     * window station, or a desktop this process may not read. Not a target. */
    return RD_INPUT_DESKTOP_UNKNOWN;
  }
  wchar_t input_name[64] = {};
  const bool input_named = desktop_name(input, input_name, 64);
  CloseDesktop(input);
  if (!input_named) return RD_INPUT_DESKTOP_UNKNOWN;

  wchar_t thread_name[64] = {};
  const DWORD thread_id = GetCurrentThreadId();
  HDESK thread = GetThreadDesktop(thread_id);
  const bool thread_named = desktop_name(thread, thread_name, 64);
  if (!thread_named || _wcsicmp(input_name, thread_name) != 0) {
    return RD_INPUT_DESKTOP_OTHER;
  }
  if (_wcsicmp(input_name, L"Default") == 0) {
    return RD_INPUT_DESKTOP_INTERACTIVE;
  }
  if (_wcsicmp(input_name, L"Winlogon") == 0) {
    return RD_INPUT_DESKTOP_SECURE;
  }
  return RD_INPUT_DESKTOP_OTHER;
}

/*
 * The canonical hold identity of one key or mouse button: 0 for an event that
 * holds nothing. Both the guard, when it reads an injected event, and the
 * caller, when it plans one, go through this function, so neither can disagree
 * with the other about which events touch the same key. Left and right
 * modifiers fold into their generic virtual key because the merged keyboard
 * state a release acts on is the generic one; the E0 form is kept apart because
 * a main Enter and a numpad Enter are different keys that share VK_RETURN.
 */
uint32_t hold_key_for(uint32_t virtual_key, bool extended) {
  if (virtual_key == 0 || virtual_key > kMaxVirtualKey) return 0;
  switch (virtual_key) {
    case VK_LSHIFT:
    case VK_RSHIFT:
      return VK_SHIFT;
    case VK_LCONTROL:
    case VK_RCONTROL:
      return VK_CONTROL;
    case VK_LMENU:
    case VK_RMENU:
      return VK_MENU;
    default:
      break;
  }
  return virtual_key | (extended ? 0x100u : 0u);
}

uint32_t button_hold_key(uint32_t button) {
  switch (button) {
    case RD_INPUT_BUTTON_LEFT:
      return VK_LBUTTON;
    case RD_INPUT_BUTTON_RIGHT:
      return VK_RBUTTON;
    case RD_INPUT_BUTTON_MIDDLE:
      return VK_MBUTTON;
    case RD_INPUT_BUTTON_BACK:
      return VK_XBUTTON1;
    case RD_INPUT_BUTTON_FORWARD:
      return VK_XBUTTON2;
    default:
      return 0;
  }
}

/*
 * The keyboard layout the foreground window reads virtual keys with. A legacy
 * character code is translated with this layout, because that is the layout the
 * focused application will interpret the injected virtual key with. When there
 * is no foreground window the calling thread's layout is used.
 */
HKL active_layout() {
  const HWND foreground = GetForegroundWindow();
  if (foreground != nullptr) {
    const DWORD thread = GetWindowThreadProcessId(foreground, nullptr);
    if (thread != 0) {
      const HKL layout = GetKeyboardLayout(thread);
      if (layout != nullptr) return layout;
    }
  }
  return GetKeyboardLayout(0);
}

rd_input_status scan_for_key(uint32_t virtual_key, HKL layout,
                             uint32_t* scan_code, uint32_t* extended) {
  *scan_code = 0;
  *extended = 0;
  const UINT scan = MapVirtualKeyExW(virtual_key, MAPVK_VK_TO_VSC_EX, layout);
  if (scan == 0) {
    /* This layout has no scan code for the key (OEM and IME keys). The event
     * then carries the virtual key alone and the OS derives the scan code. */
    return RD_INPUT_OK;
  }
  if (scan > kMaxScanCode) return RD_INPUT_UNSUPPORTED;
  const uint32_t prefix = scan & 0xFF00u;
  if (prefix == 0xE000u) {
    /* MAPVK_VK_TO_VSC_EX prefixes an extended key's scan code with E0.
     * KEYEVENTF_EXTENDEDKEY carries that fact and the scan code is the low
     * octet, which is what a real keyboard sends for the arrow cluster,
     * Insert/Delete, the numpad's Divide and the right-hand modifier keys. */
    *scan_code = scan & 0xFFu;
    *extended = 1;
    return RD_INPUT_OK;
  }
  if (prefix == 0xE100u) {
    /* The Pause key is an E1 sequence, which one scan code and one flag cannot
     * express. The event then carries the virtual key alone and the OS derives
     * the sequence itself, rather than this adapter sending half of it. */
    return RD_INPUT_OK;
  }
  *scan_code = scan;
  return RD_INPUT_OK;
}

/* The pinned Windows sender accepts a byte or an E0-prefixed byte; its Pause
 * exception is a Legacy control key. Preserve rdev's complete wire scan in
 * wScan, not a Unicode character or a second VK-to-scan translation. */
bool map_scan_valid(uint32_t scan_code) {
  return (scan_code & 0xFFu) != 0 &&
         (scan_code <= 0xFFu || (scan_code >> 8) == 0xE0u);
}

rd_input_status validate_event(const rd_input_event& event) {
  if (event.struct_size != sizeof(rd_input_event)) return RD_INPUT_INVALID_ARGUMENT;
  if (event.reserved != 0) return RD_INPUT_INVALID_ARGUMENT;
  switch (event.kind) {
    case RD_INPUT_EVENT_MOUSE: {
      if (event.flags != 0 || event.virtual_key != 0 || event.scan_code != 0 ||
          event.code_unit != 0) {
        return RD_INPUT_INVALID_ARGUMENT;
      }
      switch (event.action) {
        case RD_INPUT_MOUSE_MOVE_ABSOLUTE:
          if (event.button != 0 || event.data != 0) return RD_INPUT_INVALID_ARGUMENT;
          if (event.x < 0 || event.x > kMaxNormalizedCoordinate ||
              event.y < 0 || event.y > kMaxNormalizedCoordinate) {
            return RD_INPUT_INVALID_ARGUMENT;
          }
          return RD_INPUT_OK;
        case RD_INPUT_MOUSE_MOVE_RELATIVE:
          if (event.button != 0 || event.data != 0) return RD_INPUT_INVALID_ARGUMENT;
          return RD_INPUT_OK;
        case RD_INPUT_MOUSE_BUTTON_DOWN:
        case RD_INPUT_MOUSE_BUTTON_UP:
          if (event.button > RD_INPUT_BUTTON_FORWARD || event.data != 0 ||
              event.x != 0 || event.y != 0) {
            return RD_INPUT_INVALID_ARGUMENT;
          }
          return RD_INPUT_OK;
        case RD_INPUT_MOUSE_WHEEL:
        case RD_INPUT_MOUSE_HWHEEL: {
          if (event.button != 0 || event.x != 0 || event.y != 0) {
            return RD_INPUT_INVALID_ARGUMENT;
          }
          if (event.data == 0) return RD_INPUT_INVALID_ARGUMENT;
          const int64_t magnitude =
              event.data < 0 ? -static_cast<int64_t>(event.data) : event.data;
          /* SendInput takes any signed rotation, but a partial notch is not a
           * scroll and a rotation beyond the wire's own bound is not one
           * gesture: both are refused instead of rounded. */
          if (magnitude % static_cast<int64_t>(kWheelDelta) != 0) {
            return RD_INPUT_INVALID_ARGUMENT;
          }
          if (magnitude >
              static_cast<int64_t>(kWheelDelta) * kMaxWheelNotches) {
            return RD_INPUT_INVALID_ARGUMENT;
          }
          return RD_INPUT_OK;
        }
        default:
          return RD_INPUT_INVALID_ARGUMENT;
      }
    }
    case RD_INPUT_EVENT_KEY:
      if (event.flags & ~kKnownEventFlags) return RD_INPUT_INVALID_ARGUMENT;
      if (event.action != 0 || event.button != 0 || event.data != 0 ||
          event.code_unit != 0) {
        return RD_INPUT_INVALID_ARGUMENT;
      }
      if (event.virtual_key == 0 || event.virtual_key > kMaxVirtualKey) {
        return RD_INPUT_INVALID_ARGUMENT;
      }
      if (event.scan_code > kMaxScanCode) return RD_INPUT_INVALID_ARGUMENT;
      if (event.flags & RD_INPUT_KEY_SCANCODE) {
        if (!map_scan_valid(event.scan_code) ||
            ((event.flags & RD_INPUT_KEY_EXTENDED) != 0) !=
                ((event.scan_code >> 8) == 0xE0u) ||
            event.virtual_key <= VK_XBUTTON2 || event.virtual_key == VK_PACKET) {
          return RD_INPUT_INVALID_ARGUMENT;
        }
      }
      return RD_INPUT_OK;
    case RD_INPUT_EVENT_TEXT:
      if (event.flags & ~(RD_INPUT_KEY_UP | RD_INPUT_KEY_EXTENDED)) {
        return RD_INPUT_INVALID_ARGUMENT;
      }
      if (event.action != 0 || event.button != 0 || event.data != 0 ||
          event.virtual_key != 0 || event.scan_code != 0) {
        return RD_INPUT_INVALID_ARGUMENT;
      }
      if (event.code_unit == 0) return RD_INPUT_INVALID_ARGUMENT;
      return RD_INPUT_OK;
    default:
      return RD_INPUT_INVALID_ARGUMENT;
  }
}

/* The hold identity one event carries, or 0 when it holds nothing: a move, a
 * wheel, text (VK_PACKET included) and anything else that only passes through. */
uint32_t event_hold_key(const rd_input_event& event) {
  switch (event.kind) {
    case RD_INPUT_EVENT_MOUSE:
      switch (event.action) {
        case RD_INPUT_MOUSE_BUTTON_DOWN:
        case RD_INPUT_MOUSE_BUTTON_UP:
          return button_hold_key(event.button);
        default:
          return 0;
      }
    case RD_INPUT_EVENT_KEY:
      return hold_key_for(event.virtual_key,
                          (event.flags & RD_INPUT_KEY_EXTENDED) != 0);
    default:
      return 0;
  }
}

INPUT to_input(const rd_input_event& event, uint64_t extra) {
  INPUT input = {};
  switch (event.kind) {
    case RD_INPUT_EVENT_MOUSE:
      input.type = INPUT_MOUSE;
      switch (event.action) {
        case RD_INPUT_MOUSE_MOVE_ABSOLUTE:
          input.mi.dx = event.x;
          input.mi.dy = event.y;
          input.mi.dwFlags =
              MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
          break;
        case RD_INPUT_MOUSE_MOVE_RELATIVE:
          input.mi.dx = event.x;
          input.mi.dy = event.y;
          input.mi.dwFlags = MOUSEEVENTF_MOVE;
          break;
        case RD_INPUT_MOUSE_BUTTON_DOWN:
        case RD_INPUT_MOUSE_BUTTON_UP: {
          const bool down = event.action == RD_INPUT_MOUSE_BUTTON_DOWN;
          switch (event.button) {
            case RD_INPUT_BUTTON_LEFT:
              input.mi.dwFlags = down ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
              break;
            case RD_INPUT_BUTTON_RIGHT:
              input.mi.dwFlags = down ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
              break;
            case RD_INPUT_BUTTON_MIDDLE:
              input.mi.dwFlags = down ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
              break;
            case RD_INPUT_BUTTON_BACK:
              input.mi.dwFlags = down ? MOUSEEVENTF_XDOWN : MOUSEEVENTF_XUP;
              input.mi.mouseData = XBUTTON1;
              break;
            case RD_INPUT_BUTTON_FORWARD:
              input.mi.dwFlags = down ? MOUSEEVENTF_XDOWN : MOUSEEVENTF_XUP;
              input.mi.mouseData = XBUTTON2;
              break;
            default:
              break;
          }
          break;
        }
        case RD_INPUT_MOUSE_WHEEL:
          input.mi.mouseData = static_cast<DWORD>(static_cast<uint32_t>(event.data));
          input.mi.dwFlags = MOUSEEVENTF_WHEEL;
          break;
        case RD_INPUT_MOUSE_HWHEEL:
          input.mi.mouseData = static_cast<DWORD>(static_cast<uint32_t>(event.data));
          input.mi.dwFlags = MOUSEEVENTF_HWHEEL;
          break;
        default:
          break;
      }
      break;
    case RD_INPUT_EVENT_KEY:
      input.type = INPUT_KEYBOARD;
      input.ki.wVk = (event.flags & RD_INPUT_KEY_SCANCODE)
                         ? 0
                         : static_cast<WORD>(event.virtual_key);
      input.ki.wScan = static_cast<WORD>(event.scan_code);
      input.ki.dwFlags =
          (event.flags & RD_INPUT_KEY_UP) ? KEYEVENTF_KEYUP : 0;
      if (event.flags & RD_INPUT_KEY_SCANCODE) {
        input.ki.dwFlags |= KEYEVENTF_SCANCODE;
      }
      if (event.flags & RD_INPUT_KEY_EXTENDED) {
        input.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
      }
      break;
    default:
      input.type = INPUT_KEYBOARD;
      input.ki.wVk = 0;
      input.ki.wScan = static_cast<WORD>(event.code_unit);
      input.ki.dwFlags = KEYEVENTF_UNICODE |
                         ((event.flags & RD_INPUT_KEY_UP) ? KEYEVENTF_KEYUP : 0);
      break;
  }
  /* Only a tracked event carries a token. An event that holds nothing carries
   * none: the guard must be able to tell a token of its own with no transaction
   * (a late event, which it refuses) from an ordinary event of its own. Win32
   * keeps the extra information inside the sub-structure the event uses. */
  if (input.type == INPUT_MOUSE) {
    input.mi.dwExtraInfo = static_cast<ULONG_PTR>(extra);
  } else {
    input.ki.dwExtraInfo = static_cast<ULONG_PTR>(extra);
  }
  return input;
}

/* --- the guard's state ---------------------------------------------------- */

/* The encoding one hold event was injected with, as the hook saw it. A repeat of
 * an episode has to match the encoding its opening down really used, so a repeat
 * can never press a different key, a different form of the same virtual key or a
 * key a layout change moved. All zero for a mouse button, whose identity is the
 * canonical key alone. */
struct EventEncoding {
  uint32_t virtual_key;
  uint32_t scan_code;
  uint32_t extended;
};

/* The guard's observed state for one canonical hold key. Nothing here is a
 * statement about a device: `held` is what the merged input stream last said,
 * `collision` is that something this adapter does not own has been down on this
 * key while this adapter held it. */
struct HoldSlot {
  /* The episode that holds this key, 0 when the guard has no own episode for
   * it. An episode is never retired except by rd_input_episode_retire, so a
   * nonzero value blocks a new episode on this key. */
  uint64_t episode;
  uint64_t lease;
  uint32_t epoch;
  /* The key's state is not established: no sample and no event has said what
   * it is. No new episode may start on an unknown key. */
  uint32_t unknown;
  /* The merged stream last said this key is down (0 after the last up). */
  uint32_t held;
  /* Sticky: a down that was not this adapter's own was observed while this
   * adapter held the key. */
  uint32_t collision;
  /* 1 while every colliding down observed was injected (a foreign injector);
   * 0 once a physical one was seen, which then needs a physical release. */
  uint32_t collision_injected;
  /* 1 once a down of this episode was seen to pass this guard and the rest of
   * the hook chain: only a hold that reached the system may be repeated or
   * released by an own event. */
  uint32_t confirmed;
  /* The encoding the opening down of this episode was injected with, as the hook
   * saw it. */
  uint32_t down_vk;
  uint32_t down_scan;
  uint32_t down_extended;
  uint64_t collision_seq;
  uint64_t external_up_seq;
  /* Observation sequence of the last event seen for this key, 0 when this
   * generation has seen none. */
  uint64_t observed_seq;
  /* Observation sequence at the last usable up sample. */
  uint64_t sample_seq;
  /* The observation generation this state belongs to: a sample taken at arm time
   * may only establish a key of its own generation that no event has touched. */
  uint32_t observed_generation;
};

enum DescriptorState : uint32_t {
  /* Reusable. */
  kDescriptorFree = 0,
  /* Published for the transaction being injected. */
  kDescriptorLive = 1,
  /* Kept for a transaction that was never resolved. Never reused, so a late
   * event of it is still recognized as this adapter's. */
  kDescriptorSealed = 2
};

struct Descriptor {
  uint64_t cookie;
  uint64_t lease;
  uint64_t episode;
  uint64_t transaction;
  uint32_t event_index;
  uint32_t key;
  uint32_t up;
  uint32_t epoch;
  uint32_t state;
  uint32_t receipt;
};

struct Guard {
  SRWLOCK lock;
  /* Held while the one batch buffer is filled and handed to SendInput. Taken
   * outside the guard's lock, never by a hook callback. */
  SRWLOCK send_lock;
  uint32_t state;
  uint32_t epoch;
  uint32_t next_epoch;
  uint32_t flags;
  uint32_t leases;
  uint64_t lease_ids[kMaxLeases];
  /* The observation generation in progress. A start opens one before any hook of
   * that start can observe, and every observation, sample and episode records
   * which generation it belongs to. Monotonic; never reused. */
  uint32_t generation;
  /* The hooks were installed and not yet removed. */
  bool installed;
  bool installing;
  bool hooks_removed;
  /* The message thread on this handle published a complete installation: both
   * hooks and the heartbeat timer. */
  bool install_ok;
  /* The observation sequence is exhausted: no further observation is handed out,
   * so a stale sequence can never compare as a current one. */
  bool observation_exhausted;
  HANDLE thread;
  DWORD thread_id;
  HHOOK keyboard_hook;
  HHOOK mouse_hook;
  /* The id SetTimer assigned to the heartbeat timer, 0 when none is running. */
  UINT_PTR heartbeat_timer;
  uint64_t heartbeat_tick;
  uint32_t heartbeat;
  uint32_t token_serial;
  bool serial_exhausted;
  /* Owned while the message thread may still run: the module reference that
   * keeps this code loaded, and the startup event its thread may still signal.
   * A thread that cannot be joined keeps both, and they are released only after
   * a join. */
  HMODULE module;
  HANDLE start_ready;
  HoldSlot keys[kHoldKeys];
  Descriptor descriptors[kMaxDescriptors];
  std::atomic<uint64_t> observation;
  /* The one buffer a batch is built in, filled and handed to SendInput under
   * send_lock, so no batch allocates and no two senders share a buffer. */
  INPUT scratch[kMaxEvents];

  Guard() : lock(SRWLOCK_INIT), send_lock(SRWLOCK_INIT), observation(0) {
    /* Monotonic for the life of the process: an epoch, a generation, a token
     * serial and an observation sequence are never reused, so a stale one can
     * never be taken for a current one. They survive a stopped guard. */
    next_epoch = 0;
    generation = 0;
    token_serial = 0;
    serial_exhausted = false;
    observation_exhausted = false;
    /* Owned handles: null until a start takes them, and released by the path
     * that confirms the thread which could use them has been joined. */
    module = nullptr;
    start_ready = nullptr;
    clear_state();
  }

  /* Drops the observation state of a guard that stopped cleanly. The handles
   * that outlive a stop - the module reference and the startup event - are the
   * ones the joined-thread path releases, so a clean stop sees them null. */
  void clear_state() {
    state = RD_INPUT_GUARD_IDLE;
    epoch = 0;
    flags = 0;
    leases = 0;
    for (uint32_t i = 0; i < kMaxLeases; ++i) lease_ids[i] = 0;
    installed = false;
    installing = false;
    hooks_removed = true;
    install_ok = false;
    thread = nullptr;
    thread_id = 0;
    keyboard_hook = nullptr;
    mouse_hook = nullptr;
    heartbeat_timer = 0;
    heartbeat_tick = 0;
    heartbeat = 0;
    for (uint32_t i = 0; i < kHoldKeys; ++i) {
      HoldSlot& slot = keys[i];
      slot.episode = 0;
      slot.lease = 0;
      slot.epoch = 0;
      slot.unknown = 1;
      slot.held = 0;
      slot.collision = 0;
      slot.collision_injected = 1;
      slot.confirmed = 0;
      slot.down_vk = 0;
      slot.down_scan = 0;
      slot.down_extended = 0;
      slot.collision_seq = 0;
      slot.external_up_seq = 0;
      slot.observed_seq = 0;
      slot.sample_seq = 0;
      slot.observed_generation = 0;
    }
    for (uint32_t i = 0; i < kMaxDescriptors; ++i) {
      descriptors[i].state = kDescriptorFree;
      descriptors[i].cookie = 0;
      descriptors[i].receipt = RD_INPUT_RECEIPT_UNKNOWN;
    }
  }
};

Guard& guard() {
  static Guard instance;
  return instance;
}

/* One short acquisition of the guard's internal lock. It is an exclusive
 * blocking acquisition, not a try-lock, but it is never held across SendInput, a
 * sleep, a hook chain call, a sampling call or a join, and the hook callbacks
 * only take it for a bounded number of fixed-table operations. */
struct GuardLock {
  GuardLock() { AcquireSRWLockExclusive(&guard().lock); }
  ~GuardLock() { ReleaseSRWLockExclusive(&guard().lock); }
  GuardLock(const GuardLock&) = delete;
  GuardLock& operator=(const GuardLock&) = delete;
};

/* Serialises the one batch buffer of the guard. Taken by a sender around filling
 * that buffer and calling SendInput, never inside the guard's lock and never by
 * a hook callback. */
struct SendLock {
  SendLock() { AcquireSRWLockExclusive(&guard().send_lock); }
  ~SendLock() { ReleaseSRWLockExclusive(&guard().send_lock); }
  SendLock(const SendLock&) = delete;
  SendLock& operator=(const SendLock&) = delete;
};

/* Records both hook handles in the guard's state. `hooks_removed` is exactly
 * "the guard holds no hook handle": a handle that UnhookWindowsHookEx did not
 * remove stays here, so it is never reported as gone. */
void set_hook_handles_locked(Guard& g, HHOOK keyboard, HHOOK mouse) {
  g.keyboard_hook = keyboard;
  g.mouse_hook = mouse;
  g.hooks_removed = keyboard == nullptr && mouse == nullptr;
}

/* Takes both hook handles out of the guard's state, with the lock held, so the
 * caller can remove them without racing another reader. They leave the state
 * here and are only really gone once remove_hooks reports it. */
void take_hooks_locked(Guard& g, HHOOK* keyboard, HHOOK* mouse) {
  *keyboard = g.keyboard_hook;
  *mouse = g.mouse_hook;
  g.keyboard_hook = nullptr;
  g.mouse_hook = nullptr;
  g.hooks_removed = true;
}

/* Removes the two hooks a caller took out of the guard's state, checking what
 * the system did. UnhookWindowsHookEx returning does not mean a concurrent
 * callback has finished, and a failure means the hook is still installed: the
 * handle of one that was not removed goes back into the guard's state, and the
 * guard must not be reported as having nothing left. Never called with the
 * guard's lock held. */
bool remove_hooks(HHOOK keyboard, HHOOK mouse) {
  const bool keyboard_gone =
      keyboard == nullptr || UnhookWindowsHookEx(keyboard) != FALSE;
  const bool mouse_gone =
      mouse == nullptr || UnhookWindowsHookEx(mouse) != FALSE;
  GuardLock lock;
  Guard& g = guard();
  if (!keyboard_gone) g.keyboard_hook = keyboard;
  if (!mouse_gone) g.mouse_hook = mouse;
  g.hooks_removed = g.keyboard_hook == nullptr && g.mouse_hook == nullptr;
  return keyboard_gone && mouse_gone;
}

/* Releases what only a message thread can use, once that thread is gone - joined,
 * or never started: the hook handles still in the guard's state, the module
 * reference that keeps this code loaded, and the startup event its thread may
 * have signalled. True means no hook is left that may still be installed. */
bool reclaim_thread_resources() {
  HHOOK keyboard = nullptr;
  HHOOK mouse = nullptr;
  HMODULE module = nullptr;
  HANDLE ready = nullptr;
  {
    GuardLock lock;
    Guard& g = guard();
    take_hooks_locked(g, &keyboard, &mouse);
    module = g.module;
    g.module = nullptr;
    ready = g.start_ready;
    g.start_ready = nullptr;
    g.installed = false;
    g.install_ok = false;
    g.heartbeat_timer = 0;
    g.thread_id = 0;
  }
  /* FreeLibrary runs loader work: never under the guard's lock. */
  if (ready != nullptr) CloseHandle(ready);
  if (module != nullptr) FreeLibrary(module);
  return remove_hooks(keyboard, mouse);
}

void fault_locked(Guard& g, uint32_t flag) {
  g.flags |= flag;
  if (g.state == RD_INPUT_GUARD_ARMED) g.state = RD_INPUT_GUARD_FAULTED;
}

/* The next observation sequence, only ever called with the guard's lock held.
 * The sequence is monotonic and never wraps: at its limit the guard latches
 * admission closed rather than hand out a value a stale sequence could be taken
 * for. */
uint64_t next_observation_locked(Guard& g) {
  if (g.observation.load(std::memory_order_relaxed) >= kObservationLimit) {
    g.observation_exhausted = true;
    fault_locked(g, RD_INPUT_GUARD_FLAG_SERIAL_EXHAUSTED);
    return kObservationLimit;
  }
  const uint64_t next = g.observation.load(std::memory_order_relaxed) + 1;
  g.observation.store(next, std::memory_order_relaxed);
  return next;
}

uint64_t peek_observation() {
  return guard().observation.load(std::memory_order_relaxed);
}

/* Unresolved holds: keys blocked by a collision that has not been retired, plus
 * own events whose fate is still unknown. Both keep the guard installed. */
uint32_t unresolved_locked(const Guard& g) {
  uint32_t unresolved = 0;
  for (uint32_t i = 1; i < kHoldKeys; ++i) {
    if (g.keys[i].episode != 0 && g.keys[i].collision != 0) ++unresolved;
  }
  for (uint32_t i = 0; i < kMaxDescriptors; ++i) {
    const Descriptor& descriptor = g.descriptors[i];
    if (descriptor.state != kDescriptorFree &&
        descriptor.receipt == RD_INPUT_RECEIPT_UNKNOWN) {
      ++unresolved;
    }
  }
  return unresolved;
}

void fill_snapshot_locked(const Guard& g, rd_input_guard_snapshot* snapshot) {
  snapshot->struct_size = static_cast<uint32_t>(sizeof(rd_input_guard_snapshot));
  snapshot->state = g.state;
  snapshot->epoch = g.state == RD_INPUT_GUARD_IDLE ? 0 : g.epoch;
  snapshot->leases = g.leases;
  snapshot->flags = g.flags;
  snapshot->unresolved = unresolved_locked(g);
}

bool has_own_token_locked(const Guard& g, uint64_t cookie) {
  return cookie > kTokenBase && cookie <= kTokenBase + g.token_serial;
}

uint32_t find_live_descriptor_locked(const Guard& g, uint64_t cookie) {
  if (cookie == 0) return kNoDescriptor;
  for (uint32_t i = 0; i < kMaxDescriptors; ++i) {
    if (g.descriptors[i].state == kDescriptorLive &&
        g.descriptors[i].cookie == cookie) {
      return i;
    }
  }
  return kNoDescriptor;
}

/* One event's fate within its episode: an up or a down whose receipt never
 * became terminal. It blocks a retirement of that episode. */
bool has_unresolved_event_locked(const Guard& g, uint32_t epoch, uint64_t lease,
                                 uint64_t episode, uint32_t key) {
  for (uint32_t i = 0; i < kMaxDescriptors; ++i) {
    const Descriptor& descriptor = g.descriptors[i];
    if (descriptor.state == kDescriptorFree) continue;
    if (descriptor.receipt != RD_INPUT_RECEIPT_UNKNOWN) continue;
    if (descriptor.epoch != epoch || descriptor.lease != lease ||
        descriptor.episode != episode || descriptor.key != key) {
      continue;
    }
    return true;
  }
  return false;
}

/*
 * The decision for one own (tracked) hold event, under the lock. It opens the
 * episode the moment the down is let through - before SendInput has returned -
 * so that a local or foreign down that arrives during the injection is already
 * being watched. A down for a key that already carries an episode is only a
 * repeat: it passes when it names that exact episode of the same lease in the
 * same epoch, in the encoding the opening down really used, over a hold the hook
 * chain confirmed and nothing has collided with or left unknown - and it then
 * reopens nothing, claims nothing and clears no collision history. It never
 * returns a verdict that would let an own event lift a hold this adapter does
 * not own.
 */
bool veto_own_event_locked(Guard& g, uint32_t index, bool up, bool injected,
                           const EventEncoding& encoding) {
  Descriptor& descriptor = g.descriptors[index];
  if (g.state != RD_INPUT_GUARD_ARMED || descriptor.epoch != g.epoch) {
    /* Not observing this epoch: nothing of ours may reach the system. */
    return true;
  }
  if (!injected) {
    /* A physical event cannot be this adapter's own injection, whatever its
     * dwExtraInfo says. It is never ours to release. */
    return true;
  }
  HoldSlot& slot = g.keys[descriptor.key];
  const uint64_t seq = next_observation_locked(g);
  slot.observed_generation = g.generation;
  if (!up) {
    if (slot.episode == 0) {
      if (slot.unknown || slot.held) {
        /* The key is not clear: a down here would duplicate a hold or claim one
         * that is already down. Admission is the caller's query; this is the
         * final check, at the event. */
        slot.observed_seq = seq;
        return true;
      }
      slot.episode = descriptor.episode;
      slot.lease = descriptor.lease;
      slot.epoch = descriptor.epoch;
      slot.unknown = 0;
      slot.held = 1;
      slot.collision = 0;
      slot.collision_injected = 1;
      /* Nothing is confirmed about this hold until the down's own fate is
       * known: a repeat or an up may only rely on a hold that reached the
       * system. */
      slot.confirmed = 0;
      slot.down_vk = encoding.virtual_key;
      slot.down_scan = encoding.scan_code;
      slot.down_extended = encoding.extended;
      slot.collision_seq = 0;
      slot.external_up_seq = 0;
      slot.observed_seq = seq;
      return false;
    }
    if (slot.epoch == descriptor.epoch && slot.lease == descriptor.lease &&
        slot.episode == descriptor.episode && slot.unknown == 0 &&
        slot.held != 0 && slot.collision == 0 && slot.confirmed != 0 &&
        slot.down_vk == encoding.virtual_key &&
        slot.down_scan == encoding.scan_code &&
        slot.down_extended == encoding.extended) {
      /* A repeat of this lease's own confirmed hold. The record keeps its
       * episode, its encoding and its collision history; only the observation
       * that this key was seen again is recorded. */
      slot.observed_seq = seq;
      return false;
    }
    slot.observed_seq = seq;
    return true;
  }
  if (slot.episode != descriptor.episode || slot.epoch != descriptor.epoch ||
      slot.lease != descriptor.lease) {
    /* A stale or unknown episode: this up must not lift whatever holds the key
     * now. */
    return true;
  }
  if (slot.collision != 0) {
    /* A local or foreign hold was observed under this one. Releasing here would
     * release it too, so the up is refused and the caller keeps its record. */
    return true;
  }
  if (slot.confirmed == 0) {
    /* The down this episode was opened for never reached the system, so an up
     * would lift a hold this adapter never pressed. The record stays for an
     * evidence retirement. */
    return true;
  }
  slot.observed_seq = seq;
  return false;
}

/* After the chain ran: the fate of one own event is known. A down that passed
 * this guard and the chain is what makes the episode's hold confirmed; only an
 * up that did the same released the key. */
void finish_own_event_locked(Guard& g, uint32_t index, bool up, bool passed) {
  Descriptor& descriptor = g.descriptors[index];
  HoldSlot& slot = g.keys[descriptor.key];
  if (!up) {
    if (!passed) return;
    if (slot.episode != descriptor.episode || slot.epoch != descriptor.epoch ||
        slot.lease != descriptor.lease) {
      return;
    }
    /* Sticky for the episode: the hold did reach the system, so a repeat the
     * chain later vetoed does not make releasing this hold illegal. */
    slot.confirmed = 1;
    return;
  }
  if (!passed) return;
  if (slot.episode != descriptor.episode || slot.epoch != descriptor.epoch) return;
  slot.episode = 0;
  slot.lease = 0;
  slot.epoch = 0;
  slot.unknown = 0;
  slot.held = 0;
  slot.collision = 0;
  slot.collision_injected = 1;
  slot.confirmed = 0;
  slot.down_vk = 0;
  slot.down_scan = 0;
  slot.down_extended = 0;
  slot.collision_seq = 0;
  slot.external_up_seq = 0;
  slot.observed_seq = next_observation_locked(g);
}

/* One event that is not this adapter's own. */
void observe_locked(Guard& g, uint32_t key, bool up, bool injected) {
  HoldSlot& slot = g.keys[key];
  const uint64_t seq = next_observation_locked(g);
  slot.observed_seq = seq;
  slot.observed_generation = g.generation;
  if (!up) {
    if (slot.episode != 0) {
      /* A down this adapter does not own, while it holds the key. It is not
       * treated as physical when it was injected, but it is occupancy either
       * way: the caller's up must not release it. Physical auto-repeat lands
       * here too, and only makes the collision stickier. */
      if (slot.collision == 0) {
        slot.collision = 1;
        slot.collision_injected = injected ? 1u : 0u;
      } else if (!injected) {
        slot.collision_injected = 0;
      }
      slot.collision_seq = seq;
      slot.external_up_seq = 0;
      slot.held = 1;
      slot.unknown = 0;
      if (injected) g.flags |= RD_INPUT_GUARD_FLAG_FOREIGN_INJECTED_HOLD;
      return;
    }
    slot.held = 1;
    slot.unknown = 0;
    return;
  }
  /* A release that is not this adapter's own. It is the evidence a retirement
   * needs after a collision; a physical collision needs a physical release. */
  if (slot.collision != 0 && (slot.collision_injected != 0 || !injected)) {
    slot.external_up_seq = seq;
  }
  slot.held = 0;
  slot.unknown = 0;
}

/* --- hook callbacks ------------------------------------------------------- */

/* The hook chain's own veto wins over this guard's receipt: CallNextHookEx
 * returns the next hook's result, and a nonzero one means the event was not
 * passed on. The receipt is published only after that call returned. */
LRESULT guard_event(int code, WPARAM wparam, LPARAM lparam, uint64_t cookie,
                    uint32_t key, bool up, bool injected,
                    const EventEncoding& encoding) {
  if (key == 0) {
    /* A move, a wheel or text: no hold state, nothing to decide and no lock. */
    return CallNextHookEx(nullptr, code, wparam, lparam);
  }
  uint32_t tracked = kNoDescriptor;
  {
    GuardLock lock;
    Guard& g = guard();
    if (injected && cookie != 0) {
      tracked = find_live_descriptor_locked(g, cookie);
      if (tracked != kNoDescriptor) {
        const Descriptor& descriptor = g.descriptors[tracked];
        if (descriptor.key != key || (descriptor.up != 0) != up) {
          /* A matching number is not a matching event. Keep the expected
           * event's receipt untouched: this callback cannot prove its fate. */
          fault_locked(g, RD_INPUT_GUARD_FLAG_LATE_SELF_EVENT);
          return 1;
        }
        if (veto_own_event_locked(g, tracked, up, injected, encoding)) {
          g.descriptors[tracked].receipt = RD_INPUT_RECEIPT_SELF_VETOED;
          return 1;
        }
      } else if (has_own_token_locked(g, cookie)) {
        /* This adapter's token with no transaction to belong to: a late event
         * of a transaction that was already resolved, or a forged mark. It is
         * refused, and the guard closes admission rather than guess. */
        fault_locked(g, RD_INPUT_GUARD_FLAG_LATE_SELF_EVENT);
        return 1;
      } else {
        observe_locked(g, key, up, injected);
      }
    } else {
      observe_locked(g, key, up, injected);
    }
  }
  const LRESULT result = CallNextHookEx(nullptr, code, wparam, lparam);
  if (tracked != kNoDescriptor) {
    GuardLock lock;
    Descriptor& descriptor = guard().descriptors[tracked];
    descriptor.receipt = result == 0 ? RD_INPUT_RECEIPT_PASSED
                                     : RD_INPUT_RECEIPT_DOWNSTREAM_VETOED;
    finish_own_event_locked(guard(), tracked, up, result == 0);
  }
  return result;
}

LRESULT CALLBACK guard_keyboard_proc(int code, WPARAM wparam, LPARAM lparam) {
  if (code < 0) return CallNextHookEx(nullptr, code, wparam, lparam);
  const KBDLLHOOKSTRUCT* keyboard =
      reinterpret_cast<const KBDLLHOOKSTRUCT*>(lparam);
  if (keyboard == nullptr) return CallNextHookEx(nullptr, code, wparam, lparam);
  /* LLKHF_LOWER_IL_INJECTED alone does not mean injected: bit 4 is the
   * injection mark, and bit 1 is only set alongside it. */
  const bool injected = (keyboard->flags & LLKHF_INJECTED) != 0;
  const bool up = (keyboard->flags & LLKHF_UP) != 0;
  /* What a repeat of this event has to match, as this hook sees the encoding
   * that was really injected. */
  const EventEncoding encoding = {
      static_cast<uint32_t>(keyboard->vkCode),
      static_cast<uint32_t>(keyboard->scanCode),
      (keyboard->flags & LLKHF_EXTENDED) != 0 ? 1u : 0u,
  };
  const uint32_t key = hold_key_for(encoding.virtual_key, encoding.extended != 0);
  return guard_event(code, wparam, lparam,
                     static_cast<uint64_t>(keyboard->dwExtraInfo), key, up,
                     injected, encoding);
}

LRESULT CALLBACK guard_mouse_proc(int code, WPARAM wparam, LPARAM lparam) {
  if (code < 0) return CallNextHookEx(nullptr, code, wparam, lparam);
  const MSLLHOOKSTRUCT* mouse = reinterpret_cast<const MSLLHOOKSTRUCT*>(lparam);
  if (mouse == nullptr) return CallNextHookEx(nullptr, code, wparam, lparam);
  const bool injected = (mouse->flags & LLMHF_INJECTED) != 0;
  uint32_t key = 0;
  bool up = false;
  /* A mouse button has no virtual key and no scan code: its identity is the
   * canonical hold key below. */
  const EventEncoding encoding = {};
  switch (wparam) {
    case WM_LBUTTONDOWN:
    case WM_LBUTTONUP:
      key = VK_LBUTTON;
      up = wparam == WM_LBUTTONUP;
      break;
    case WM_RBUTTONDOWN:
    case WM_RBUTTONUP:
      key = VK_RBUTTON;
      up = wparam == WM_RBUTTONUP;
      break;
    case WM_MBUTTONDOWN:
    case WM_MBUTTONUP:
      key = VK_MBUTTON;
      up = wparam == WM_MBUTTONUP;
      break;
    case WM_XBUTTONDOWN:
    case WM_XBUTTONUP: {
      const uint32_t which = static_cast<uint32_t>(mouse->mouseData >> 16);
      if (which == XBUTTON1) key = VK_XBUTTON1;
      else if (which == XBUTTON2) key = VK_XBUTTON2;
      up = wparam == WM_XBUTTONUP;
      break;
    }
    default:
      /* Moves and wheels hold nothing. */
      return CallNextHookEx(nullptr, code, wparam, lparam);
  }
  return guard_event(code, wparam, lparam,
                     static_cast<uint64_t>(mouse->dwExtraInfo), key, up,
                     injected, encoding);
}

/* --- the guard's message thread ------------------------------------------- */

void guard_timer_tick() {
  const uint64_t now = GetTickCount64();
  /* Read the desktop outside the lock: this runs on the message thread, not in
   * a hook, but the lock stays for fixed-table work only. */
  const bool interactive = classify_desktop() == RD_INPUT_DESKTOP_INTERACTIVE;
  GuardLock lock;
  Guard& g = guard();
  g.heartbeat_tick = now;
  g.heartbeat += 1;
  if (!interactive) {
    /* Observation is not continuous across a desktop change, so the epoch is
     * invalid: no further admission and no retirement of what is pending. */
    fault_locked(g, RD_INPUT_GUARD_FLAG_DESKTOP_LEFT);
  }
}

DWORD WINAPI guard_thread_entry(void* parameter) {
  const HANDLE ready = static_cast<HANDLE>(parameter);
  rd_input_status outcome = RD_INPUT_OK;
  HMODULE module = nullptr;
  HHOOK keyboard = nullptr;
  HHOOK mouse = nullptr;
  UINT_PTR timer = 0;
  /* A real module reference, not an unchanged-refcount lookup: this code has to
   * stay loaded until the message thread has been joined, and the guard releases
   * the reference only after that join. */
  if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                          reinterpret_cast<LPCWSTR>(&guard_keyboard_proc),
                          &module)) {
    outcome = RD_INPUT_UNSUPPORTED;
  } else {
    /* Force this thread's message queue into existence before anything posts to
     * it. The hook is called by the thread that installed it, so this thread
     * must have a loop. */
    MSG message;
    PeekMessageW(&message, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
    keyboard = SetWindowsHookExW(WH_KEYBOARD_LL, guard_keyboard_proc, module, 0);
    if (keyboard == nullptr) {
      outcome = RD_INPUT_UNSUPPORTED;
    } else {
      mouse = SetWindowsHookExW(WH_MOUSE_LL, guard_mouse_proc, module, 0);
      if (mouse == nullptr) {
        /* No half-installed guard: an unmonitored injection path is exactly
         * what this adapter refuses to provide. */
        outcome = RD_INPUT_UNSUPPORTED;
      }
    }
    if (outcome == RD_INPUT_OK) {
      /* The heartbeat is part of the installation, and SetTimer is free to
       * ignore the id it was asked for and to fail: the id it returns is the one
       * this thread watches and kills, and it has to exist before the guard is
       * published as installed. */
      timer = SetTimer(nullptr, kHeartbeatTimerRequest, kHeartbeatPeriodMs,
                       nullptr);
      if (timer == 0) outcome = RD_INPUT_UNSUPPORTED;
    }
  }
  /* A failed installation removes what it installed, checking what the system
   * did: a hook that could not be removed is published so the reclaim path tries
   * again, and is never reported as gone. */
  if (outcome != RD_INPUT_OK) {
    HHOOK keyboard_gone = keyboard;
    HHOOK mouse_gone = mouse;
    keyboard = (keyboard_gone != nullptr &&
                UnhookWindowsHookEx(keyboard_gone) == FALSE)
                   ? keyboard_gone
                   : nullptr;
    mouse = (mouse_gone != nullptr && UnhookWindowsHookEx(mouse_gone) == FALSE)
                ? mouse_gone
                : nullptr;
  }
  {
    GuardLock lock;
    Guard& g = guard();
    set_hook_handles_locked(g, keyboard, mouse);
    g.heartbeat_timer = timer;
    /* The reference and the startup event stay with the guard until the thread
     * that could still use them has been joined. */
    g.module = module;
    g.thread_id = GetCurrentThreadId();
    g.heartbeat_tick = GetTickCount64();
    g.install_ok = outcome == RD_INPUT_OK && timer != 0 &&
                   g.keyboard_hook != nullptr && g.mouse_hook != nullptr;
    if (!g.install_ok) {
      fault_locked(g, RD_INPUT_GUARD_FLAG_INSTALL_FAILED);
    }
  }
  SetEvent(ready);
  if (outcome != RD_INPUT_OK) return 1;

  MSG message;
  bool services_stopped = false;
  while (GetMessageW(&message, nullptr, 0, 0) > 0) {
    if (message.hwnd == nullptr && message.message == WM_TIMER &&
        message.wParam == timer) {
      guard_timer_tick();
      continue;
    }
    if (message.hwnd == nullptr && message.message == kGuardStopMessage) {
      KillTimer(nullptr, timer);
      HHOOK keyboard_hook = nullptr;
      HHOOK mouse_hook = nullptr;
      {
        GuardLock lock;
        take_hooks_locked(guard(), &keyboard_hook, &mouse_hook);
      }
      /* Checked: a hook the system did not remove stays with the guard, and the
       * stop is then not a clean one. */
      remove_hooks(keyboard_hook, mouse_hook);
      services_stopped = true;
      break;
    }
    TranslateMessage(&message);
    DispatchMessageW(&message);
  }
  {
    GuardLock lock;
    Guard& g = guard();
    if (!services_stopped || !g.hooks_removed) {
      /* The loop stopped for a reason other than the stop message, or a hook
       * could not be removed: the guard can no longer observe, and it must not
       * be reported as armed. */
      fault_locked(g, RD_INPUT_GUARD_FLAG_THREAD_EXITED);
    }
    g.installed = false;
    g.install_ok = false;
    g.thread_id = 0;
  }
  return 0;
}

/* Releases the descriptors this transaction published without injecting. Used
 * on the paths where SendInput was never reached, so no callback can still be
 * coming for them. */
void release_published_locked(Guard& g, const uint32_t* descriptor_of,
                              uint32_t count) {
  for (uint32_t index = 0; index < count; ++index) {
    if (descriptor_of[index] == kNoDescriptor) continue;
    Descriptor& descriptor = g.descriptors[descriptor_of[index]];
    descriptor.state = kDescriptorFree;
    descriptor.cookie = 0;
    descriptor.receipt = RD_INPUT_RECEIPT_UNKNOWN;
  }
}

/*
 * Opens one observation generation. A key that is not blocked by an unresolved
 * collision and whose last observation did not say down starts unknown and
 * without an observed event of this generation, so the arm-time sample may
 * establish it; a key the merged stream last said is down keeps that record,
 * because it is the one observation whose loss would let this generation claim a
 * key something is holding. Called for a start before any hook of that start can
 * observe, and for a guard whose hooks are already installed - where a key an
 * older generation observed keeps what was observed about it instead of being
 * overwritten by a sample of the new one.
 */
void begin_generation_locked(Guard& g, uint32_t generation) {
  for (uint32_t i = 1; i < kHoldKeys; ++i) {
    HoldSlot& slot = g.keys[i];
    if (slot.observed_generation == generation) continue;
    if (slot.episode != 0 && slot.collision != 0) continue;
    slot.episode = 0;
    slot.lease = 0;
    slot.epoch = 0;
    slot.collision = 0;
    slot.collision_injected = 1;
    slot.confirmed = 0;
    slot.down_vk = 0;
    slot.down_scan = 0;
    slot.down_extended = 0;
    slot.collision_seq = 0;
    slot.external_up_seq = 0;
    slot.sample_seq = 0;
    slot.observed_generation = generation;
    if (slot.held != 0) {
      /* The merged stream last said this key is down. The down stays a refusal:
       * a sample of the new generation cannot speak for a down that was
       * observed, and no new episode may claim the key until an event says what
       * it is again. */
      slot.unknown = 0;
      slot.held = 1;
      continue;
    }
    slot.unknown = 1;
    slot.held = 0;
    slot.observed_seq = 0;
  }
}

/*
 * Joins the message thread the guard accounts for - it exited on its own, its
 * installation failed, or the guard is being stopped - and releases everything
 * only that thread could use: its hook handles, the module reference and the
 * startup event. Bounded, never forceful: a thread that cannot be joined keeps
 * its handle, and a hook the system did not remove keeps its handle, so neither
 * is ever reported as gone. True means the guard has no message thread, no hook
 * handle and no module or startup resource left. Called with no lock held.
 */
bool stop_thread_and_release() {
  HANDLE thread = nullptr;
  DWORD thread_id = 0;
  {
    GuardLock lock;
    Guard& g = guard();
    thread = g.thread;
    thread_id = g.thread_id;
  }
  if (thread == nullptr) {
    /* No message thread: release whatever the guard still holds. */
    return reclaim_thread_resources();
  }
  if (thread_id != 0) PostThreadMessageW(thread_id, kGuardStopMessage, 0, 0);
  if (WaitForSingleObject(thread, kStopWaitMs) != WAIT_OBJECT_0) {
    GuardLock lock;
    Guard& g = guard();
    g.thread = thread;
    g.thread_id = thread_id;
    fault_locked(g, RD_INPUT_GUARD_FLAG_THREAD_EXITED);
    return false;
  }
  {
    GuardLock lock;
    Guard& g = guard();
    /* The thread has exited, so nothing can be calling through its hooks any
     * more; the handles it left are removed below, checked. */
    g.thread = nullptr;
    g.thread_id = 0;
    g.installed = false;
  }
  const bool reclaimed = reclaim_thread_resources();
  CloseHandle(thread);
  if (!reclaimed) {
    GuardLock lock;
    fault_locked(guard(), RD_INPUT_GUARD_FLAG_THREAD_EXITED);
    return false;
  }
  return true;
}

/* Starts the message thread and waits until it has installed both hooks and the
 * heartbeat timer, or reported that it could not. The observation generation is
 * opened before the thread exists, so a start can never erase an event its own
 * hooks have already observed. `generation` receives that generation (0 when the
 * hooks were already installed and the caller has to open one). Returns
 * RD_INPUT_OK when the guard is installed, a defined failure when the attempt
 * left nothing behind, and RD_INPUT_RECLAMATION_UNCONFIRMED when what the
 * attempt created could not be reclaimed - that thread, its startup event, its
 * module reference and its hook handles are then held for a later attempt or
 * release to reclaim, and are never closed or wiped here. */
rd_input_status install_guard(uint32_t* generation) {
  *generation = 0;
  {
    GuardLock lock;
    Guard& g = guard();
    if (g.installed) return RD_INPUT_OK;
    if (g.installing) return RD_INPUT_GUARD_UNAVAILABLE;
    g.installing = true;
  }
  /* A message thread from an earlier attempt is still accounted for: join it, or
   * refuse if it will not come back, before another one is started. */
  if (!stop_thread_and_release()) {
    GuardLock lock;
    guard().installing = false;
    return RD_INPUT_RECLAMATION_UNCONFIRMED;
  }
  uint32_t start_generation = 0;
  {
    GuardLock lock;
    Guard& g = guard();
    if (g.generation >= kMaxSerial) {
      g.flags |= RD_INPUT_GUARD_FLAG_SERIAL_EXHAUSTED;
      g.installing = false;
      return RD_INPUT_GUARD_UNAVAILABLE;
    }
    start_generation = ++g.generation;
    begin_generation_locked(g, start_generation);
  }
  const HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (ready == nullptr) {
    GuardLock lock;
    guard().installing = false;
    return RD_INPUT_GUARD_UNAVAILABLE;
  }
  {
    GuardLock lock;
    /* Held until the worker that may signal it has been joined. */
    guard().start_ready = ready;
  }
  DWORD thread_id = 0;
  const HANDLE thread =
      CreateThread(nullptr, 0, guard_thread_entry, ready, 0, &thread_id);
  if (thread == nullptr) {
    /* No worker exists, so nothing can use the event. */
    {
      GuardLock lock;
      guard().start_ready = nullptr;
      guard().installing = false;
    }
    CloseHandle(ready);
    return RD_INPUT_GUARD_UNAVAILABLE;
  }
  bool adopted = false;
  if (WaitForSingleObject(ready, kThreadWaitMs) == WAIT_OBJECT_0) {
    GuardLock lock;
    Guard& g = guard();
    if (g.install_ok && g.keyboard_hook != nullptr && g.mouse_hook != nullptr &&
        g.heartbeat_timer != 0) {
      g.thread = thread;
      g.thread_id = thread_id;
      g.installed = true;
      adopted = true;
      /* The worker has signalled it, so no one will use the startup event
       * again. */
      g.start_ready = nullptr;
    }
  }
  if (adopted) {
    CloseHandle(ready);
    GuardLock lock;
    guard().installing = false;
    *generation = start_generation;
    return RD_INPUT_OK;
  }
  /* It reported a failure, or did not answer in time. Ask it to stop and join
   * it. */
  if (thread_id != 0) PostThreadMessageW(thread_id, kGuardStopMessage, 0, 0);
  if (WaitForSingleObject(thread, kStopWaitMs) == WAIT_OBJECT_0) {
    /* Joined: nothing of this attempt is running, so what it created can be
     * released here. */
    {
      GuardLock lock;
      Guard& g = guard();
      g.thread = nullptr;
      g.thread_id = 0;
      g.installing = false;
      g.installed = false;
    }
    const bool reclaimed = reclaim_thread_resources();
    CloseHandle(thread);
    if (!reclaimed) {
      GuardLock lock;
      fault_locked(guard(), RD_INPUT_GUARD_FLAG_THREAD_EXITED);
      return RD_INPUT_RECLAMATION_UNCONFIRMED;
    }
    return RD_INPUT_GUARD_UNAVAILABLE;
  }
  /* Not joined: the worker may still be installing hooks and signalling the
   * startup event, so its thread handle, that event, its module reference and
   * whatever it published are all kept - never closed, never wiped - and the
   * guard says the attempt did not reclaim them. */
  {
    GuardLock lock;
    Guard& g = guard();
    g.thread = thread;
    g.thread_id = thread_id;
    g.start_ready = ready;
    g.installing = false;
    fault_locked(g, RD_INPUT_GUARD_FLAG_THREAD_EXITED);
  }
  return RD_INPUT_RECLAMATION_UNCONFIRMED;
}

/* Removes both hooks and stops the message thread, checking what the system did.
 * Bounded, never forceful: a thread that cannot be joined, or a hook that did
 * not come out of the chain, is reported rather than assumed gone. */
bool stop_guard() {
  return stop_thread_and_release();
}

/*
 * Whether the merged stream holds one virtual key, as far as a GetAsyncKeyState
 * sample can say. Shift, Control and Menu are the fold of two side-specific
 * keys: a sample of the wildcard alone does not say whether either side is down,
 * so both sides are read there and either one down marks the family down. A down
 * sample must never be lost, because the sample is what establishes that a key
 * is free at arm time.
 */
bool sample_key_down(uint32_t virtual_key) {
  const SHORT state = GetAsyncKeyState(static_cast<int>(virtual_key));
  if ((state & static_cast<SHORT>(0x8000)) != 0) return true;
  uint32_t left = 0;
  uint32_t right = 0;
  switch (virtual_key) {
    case VK_SHIFT:
      left = VK_LSHIFT;
      right = VK_RSHIFT;
      break;
    case VK_CONTROL:
      left = VK_LCONTROL;
      right = VK_RCONTROL;
      break;
    case VK_MENU:
      left = VK_LMENU;
      right = VK_RMENU;
      break;
    default:
      return false;
  }
  const SHORT left_state = GetAsyncKeyState(static_cast<int>(left));
  const SHORT right_state = GetAsyncKeyState(static_cast<int>(right));
  return (left_state & static_cast<SHORT>(0x8000)) != 0 ||
         (right_state & static_cast<SHORT>(0x8000)) != 0;
}

/*
 * Establishes every key's state for one observation generation, from a sample
 * taken in this thread's usable ordinary-desktop context, and only for a key of
 * this generation that no event has touched and that is not already established.
 * An event of this generation is never overwritten by a sample that read the
 * state before the event took effect. GetAsyncKeyState takes one virtual key,
 * which does not separate a key from its E0 twin (a main Enter from a numpad
 * Enter, the extended Insert from the one beside the numpad), so a key that reads
 * down marks both canonical forms down - nothing may claim either form while the
 * sample cannot say which one is down - and a key that reads up establishes both.
 * An earlier generation's unresolved episode keeps its record.
 */
void initialize_keys(uint32_t generation) {
  for (uint32_t virtual_key = 1; virtual_key <= kMaxVirtualKey; ++virtual_key) {
    const bool down = sample_key_down(virtual_key);
    const uint32_t keys[2] = {hold_key_for(virtual_key, false),
                              hold_key_for(virtual_key, true)};
    GuardLock lock;
    Guard& g = guard();
    for (uint32_t i = 0; i < 2; ++i) {
      const uint32_t key = keys[i];
      if (key == 0) continue;
      HoldSlot& slot = g.keys[key];
      if (slot.episode != 0 || slot.unknown == 0) continue;
      if (slot.observed_generation != generation || slot.observed_seq != 0) {
        continue;
      }
      slot.unknown = 0;
      slot.held = down ? 1 : 0;
      slot.sample_seq = peek_observation();
    }
  }
}

/*
 * Mints the epoch and arms the guard. `generation` is the observation generation
 * a fresh installation opened before its hooks could observe; 0 means the hooks
 * were already installed, so this start opens its own generation here. The
 * initial key state is established before the guard is published as armed:
 * admission and injection stay closed until it is.
 */
rd_input_status arm_guard(uint32_t generation) {
  uint32_t armed_generation = generation;
  {
    GuardLock lock;
    Guard& g = guard();
    if (g.next_epoch >= kMaxSerial || g.serial_exhausted ||
        g.observation_exhausted) {
      g.flags |= RD_INPUT_GUARD_FLAG_SERIAL_EXHAUSTED;
      return RD_INPUT_GUARD_UNAVAILABLE;
    }
    if (armed_generation == 0) {
      if (g.generation >= kMaxSerial) {
        g.flags |= RD_INPUT_GUARD_FLAG_SERIAL_EXHAUSTED;
        return RD_INPUT_GUARD_UNAVAILABLE;
      }
      armed_generation = ++g.generation;
      begin_generation_locked(g, armed_generation);
    }
  }
  initialize_keys(armed_generation);
  GuardLock lock;
  Guard& g = guard();
  if (!g.installed || g.state == RD_INPUT_GUARD_STOPPING) {
    /* The guard stopped, or lost its hooks, while the state was established:
     * arming it now would publish an epoch nothing is observing for. */
    return RD_INPUT_GUARD_UNAVAILABLE;
  }
  if (g.next_epoch >= kMaxSerial) {
    g.flags |= RD_INPUT_GUARD_FLAG_SERIAL_EXHAUSTED;
    return RD_INPUT_GUARD_UNAVAILABLE;
  }
  g.epoch = ++g.next_epoch;
  g.state = RD_INPUT_GUARD_ARMED;
  g.heartbeat_tick = GetTickCount64();
  return RD_INPUT_OK;
}

bool lease_present_locked(const Guard& g, uint64_t lease) {
  for (uint32_t i = 0; i < kMaxLeases; ++i) {
    if (g.lease_ids[i] == lease) return true;
  }
  return false;
}

bool add_lease_locked(Guard& g, uint64_t lease) {
  for (uint32_t i = 0; i < kMaxLeases; ++i) {
    if (g.lease_ids[i] == 0) {
      g.lease_ids[i] = lease;
      g.leases += 1;
      return true;
    }
  }
  return false;
}

bool remove_lease_locked(Guard& g, uint64_t lease) {
  for (uint32_t i = 0; i < kMaxLeases; ++i) {
    if (g.lease_ids[i] == lease) {
      g.lease_ids[i] = 0;
      g.leases -= 1;
      return true;
    }
  }
  return false;
}

}  // namespace

extern "C" rd_input_status RD_INPUT_CALL rd_input_desktop_state(
    uint32_t* kind) {
  if (kind == nullptr) return RD_INPUT_INVALID_ARGUMENT;
  const uint32_t state = classify_desktop();
  *kind = state;
  /* A probe that could not read the desktop reports a status: "cannot tell"
   * must never reach the caller looking like an ordinary desktop. */
  return state == RD_INPUT_DESKTOP_UNKNOWN ? RD_INPUT_DESKTOP_UNAVAILABLE
                                           : RD_INPUT_OK;
}

extern "C" rd_input_status RD_INPUT_CALL rd_input_virtual_screen(
    int32_t* left, int32_t* top, int32_t* width, int32_t* height) {
  if (left == nullptr || top == nullptr || width == nullptr || height == nullptr) {
    return RD_INPUT_INVALID_ARGUMENT;
  }
  *left = GetSystemMetrics(SM_XVIRTUALSCREEN);
  *top = GetSystemMetrics(SM_YVIRTUALSCREEN);
  *width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
  *height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
  if (*width <= 0 || *height <= 0) return RD_INPUT_DESKTOP_UNAVAILABLE;
  return RD_INPUT_OK;
}

extern "C" uint32_t RD_INPUT_CALL rd_input_hold_key(uint32_t virtual_key,
                                                    uint32_t extended) {
  return hold_key_for(virtual_key, extended != 0);
}

extern "C" rd_input_status RD_INPUT_CALL rd_input_guard_acquire(
    uint64_t lease, rd_input_guard_snapshot* snapshot) {
  if (snapshot == nullptr || lease == 0) return RD_INPUT_INVALID_ARGUMENT;
  {
    GuardLock lock;
    Guard& g = guard();
    fill_snapshot_locked(g, snapshot);
    if (g.state == RD_INPUT_GUARD_STOPPING) return RD_INPUT_GUARD_UNAVAILABLE;
    if (lease_present_locked(g, lease)) return RD_INPUT_INVALID_ARGUMENT;
    if (g.leases >= kMaxLeases) {
      g.flags |= RD_INPUT_GUARD_FLAG_STORAGE_EXHAUSTED;
      return RD_INPUT_GUARD_UNAVAILABLE;
    }
  }
  /* The state a new epoch starts from can only be established in a usable
   * ordinary-desktop context. */
  if (classify_desktop() != RD_INPUT_DESKTOP_INTERACTIVE) {
    GuardLock lock;
    fill_snapshot_locked(guard(), snapshot);
    return RD_INPUT_DESKTOP_UNAVAILABLE;
  }
  bool arm = false;
  {
    GuardLock lock;
    Guard& g = guard();
    arm = g.state != RD_INPUT_GUARD_ARMED;
  }
  if (arm) {
    /* The whole start - opening the observation generation, installing the hooks
     * and the heartbeat timer, establishing the key state - is driven by this
     * caller. A start that cannot reclaim what it created says so instead of
     * reporting a clean failure. */
    uint32_t generation = 0;
    const rd_input_status installed = install_guard(&generation);
    if (installed != RD_INPUT_OK) {
      GuardLock lock;
      fill_snapshot_locked(guard(), snapshot);
      return installed;
    }
    const rd_input_status armed = arm_guard(generation);
    if (armed != RD_INPUT_OK) {
      GuardLock lock;
      fill_snapshot_locked(guard(), snapshot);
      return armed;
    }
  }
  /* One final decision: the lease is added only to a guard that is armed and
   * installed right now. A guard that stopped or faulted in between gets no
   * lease, so no lease is ever left behind on a guard that is not observing for
   * it, and OK never comes with an idle guard. */
  GuardLock lock;
  Guard& g = guard();
  if (g.state != RD_INPUT_GUARD_ARMED || !g.installed || g.installing) {
    fill_snapshot_locked(g, snapshot);
    return RD_INPUT_GUARD_UNAVAILABLE;
  }
  if (lease_present_locked(g, lease)) {
    fill_snapshot_locked(g, snapshot);
    return RD_INPUT_INVALID_ARGUMENT;
  }
  if (!add_lease_locked(g, lease)) {
    g.flags |= RD_INPUT_GUARD_FLAG_STORAGE_EXHAUSTED;
    fill_snapshot_locked(g, snapshot);
    return RD_INPUT_GUARD_UNAVAILABLE;
  }
  fill_snapshot_locked(g, snapshot);
  return RD_INPUT_OK;
}

extern "C" rd_input_status RD_INPUT_CALL rd_input_guard_health(
    uint32_t epoch, rd_input_guard_snapshot* snapshot) {
  if (snapshot == nullptr) return RD_INPUT_INVALID_ARGUMENT;
  GuardLock lock;
  Guard& g = guard();
  fill_snapshot_locked(g, snapshot);
  if (epoch != 0 && epoch != g.epoch) return RD_INPUT_GUARD_UNAVAILABLE;
  return g.state == RD_INPUT_GUARD_ARMED ? RD_INPUT_OK
                                         : RD_INPUT_GUARD_UNAVAILABLE;
}

extern "C" rd_input_status RD_INPUT_CALL rd_input_guard_release(
    uint64_t lease, rd_input_guard_snapshot* snapshot) {
  if (snapshot == nullptr || lease == 0) return RD_INPUT_INVALID_ARGUMENT;
  {
    GuardLock lock;
    Guard& g = guard();
    if (!lease_present_locked(g, lease)) {
      /* A lease this guard does not know: never report that as released. */
      fill_snapshot_locked(g, snapshot);
      return RD_INPUT_RECLAMATION_UNCONFIRMED;
    }
    if (g.leases > 1) {
      /* Another lease keeps the guard observing: this one is gone. */
      remove_lease_locked(g, lease);
      fill_snapshot_locked(g, snapshot);
      return RD_INPUT_OK;
    }
    /* The last lease. It is consumed only when the guard's own resources really
     * are given up: while something is unresolved the guard has to keep
     * observing (that is what this lease was for), so the lease is given back
     * with a snapshot that says what is still unresolved, and while a stop is
     * attempted the lease is held until that stop is confirmed. */
    if (unresolved_locked(g) != 0 || (!g.installed && g.thread == nullptr)) {
      remove_lease_locked(g, lease);
      fill_snapshot_locked(g, snapshot);
      return RD_INPUT_OK;
    }
    g.state = RD_INPUT_GUARD_STOPPING;
    fill_snapshot_locked(g, snapshot);
  }
  if (!stop_guard()) {
    /* Hooks or the message thread are still there: that is not a clean stop, it
     * is not this lease's release, and the next call retries the same stop. */
    GuardLock lock;
    Guard& g = guard();
    g.state = RD_INPUT_GUARD_FAULTED;
    fill_snapshot_locked(g, snapshot);
    return RD_INPUT_RECLAMATION_UNCONFIRMED;
  }
  GuardLock lock;
  Guard& g = guard();
  remove_lease_locked(g, lease);
  g.clear_state();
  fill_snapshot_locked(g, snapshot);
  return RD_INPUT_OK;
}

extern "C" rd_input_status RD_INPUT_CALL rd_input_key_admit(
    uint32_t epoch, uint64_t lease, uint32_t key, uint32_t* verdict,
    rd_input_guard_snapshot* snapshot) {
  if (verdict == nullptr || snapshot == nullptr || lease == 0 || key == 0 ||
      key >= kHoldKeys) {
    return RD_INPUT_INVALID_ARGUMENT;
  }
  GuardLock lock;
  Guard& g = guard();
  fill_snapshot_locked(g, snapshot);
  if (g.state != RD_INPUT_GUARD_ARMED || g.epoch != epoch) {
    *verdict = RD_INPUT_KEY_GUARD_UNAVAILABLE;
    return RD_INPUT_GUARD_UNAVAILABLE;
  }
  const HoldSlot& slot = g.keys[key];
  if (slot.unknown != 0) {
    *verdict = RD_INPUT_KEY_HELD_UNKNOWN;
  } else if (slot.episode != 0) {
    *verdict = RD_INPUT_KEY_HELD_ENGINE;
  } else if (slot.held != 0) {
    *verdict = RD_INPUT_KEY_HELD_EXTERNAL;
  } else {
    *verdict = RD_INPUT_KEY_ADMIT;
  }
  return RD_INPUT_OK;
}

extern "C" rd_input_status RD_INPUT_CALL rd_input_episode_retire(
    uint32_t epoch, uint64_t lease, uint64_t episode, uint32_t key,
    rd_input_guard_snapshot* snapshot) {
  if (snapshot == nullptr || lease == 0 || episode == 0 || key == 0 ||
      key >= kHoldKeys) {
    return RD_INPUT_INVALID_ARGUMENT;
  }
  /* The sample is taken outside the lock and outside any hook: it is a state
   * read of the merged input stream, which the hook callbacks must not make. */
  const bool interactive = classify_desktop() == RD_INPUT_DESKTOP_INTERACTIVE;
  const uint64_t seq_before = peek_observation();
  const SHORT state =
      interactive ? GetAsyncKeyState(static_cast<int>(key & 0xFFu)) : 0;
  GuardLock lock;
  Guard& g = guard();
  fill_snapshot_locked(g, snapshot);
  if (!interactive) return RD_INPUT_RECLAMATION_UNCONFIRMED;
  if (g.state != RD_INPUT_GUARD_ARMED || g.epoch != epoch) {
    /* Continuity for this episode is gone: no sample can replace what the
     * guard did not observe. */
    return RD_INPUT_RECLAMATION_UNCONFIRMED;
  }
  if ((state & static_cast<SHORT>(0x8000)) != 0) {
    /* The merged state is down: something may still hold this key. */
    return RD_INPUT_RECLAMATION_UNCONFIRMED;
  }
  if (has_unresolved_event_locked(g, epoch, lease, episode, key)) {
    return RD_INPUT_RECLAMATION_UNCONFIRMED;
  }
  HoldSlot& slot = g.keys[key];
  if (slot.observed_seq > seq_before) {
    /* An event for this key arrived after the sample was taken. */
    return RD_INPUT_RECLAMATION_UNCONFIRMED;
  }
  if (slot.episode != 0 && slot.episode != episode) {
    /* Some other episode holds this key. It is never touched by a request that
     * names this one. */
    return RD_INPUT_RECLAMATION_UNCONFIRMED;
  }
  if (slot.episode == 0 && slot.held != 0) {
    /* The merged stream last said this key is down and no episode of the guard
     * holds it: a sample that reads up cannot speak for a down that was
     * observed, and the record stays until an event says otherwise. */
    return RD_INPUT_RECLAMATION_UNCONFIRMED;
  }
  uint32_t clear_unknown = 0;
  if (slot.episode == episode && slot.epoch == epoch) {
    if (slot.collision != 0) {
      /* The colliding source has to have released after the last collision: a
       * physical collision needs a physical release, an injected one any
       * release that is not this adapter's. A repeated physical down right up
       * to the retirement is fine; the release after it is what is required. */
      if (slot.external_up_seq == 0 || slot.external_up_seq <= slot.collision_seq ||
          slot.external_up_seq > seq_before) {
        return RD_INPUT_RECLAMATION_UNCONFIRMED;
      }
      /* The episode is resolved; the key is not. No low-level hook carries a
       * device id, so a release that is not this adapter's, an automatic repeat
       * and a second device holding the same key cannot be told apart. The key
       * therefore stays unknown - not clear - until an event establishes what it
       * is again, and the caller is told that this retirement could not
       * attribute the collision. */
      g.flags |= RD_INPUT_GUARD_FLAG_RETIRED_UNATTRIBUTED;
    } else {
      clear_unknown = 1;
    }
    slot.episode = 0;
    slot.lease = 0;
    slot.epoch = 0;
    slot.collision = 0;
    slot.collision_injected = 1;
    slot.confirmed = 0;
    slot.down_vk = 0;
    slot.down_scan = 0;
    slot.down_extended = 0;
    slot.collision_seq = 0;
    slot.external_up_seq = 0;
  } else {
    /* No episode of this guard holds the key: the sample establishes the merged
     * state, which is the same evidence arming uses. */
    clear_unknown = 1;
  }
  slot.unknown = clear_unknown != 0 ? 0u : 1u;
  slot.held = 0;
  slot.sample_seq = seq_before;
  slot.observed_seq = seq_before;
  fill_snapshot_locked(g, snapshot);
  return RD_INPUT_OK;
}

namespace {

/* Every event of a refused batch: a hold event never reached SendInput, and an
 * event with no hold identity carries no ownership decision. */
void fill_refused_receipts(const rd_input_send_request* request) {
  for (uint32_t index = 0; index < request->count; ++index) {
    request->receipts[index] =
        event_hold_key(request->events[index]) != 0
            ? RD_INPUT_RECEIPT_NOT_SUBMITTED
            : RD_INPUT_RECEIPT_NOT_TRACKED;
  }
}

/* True when this request can be read and its receipts written: the structure
 * this build knows, with the arrays it points at and a count it can hold. */
bool request_readable(const rd_input_send_request* request) {
  return request != nullptr &&
         request->struct_size == sizeof(rd_input_send_request) &&
         request->events != nullptr && request->episodes != nullptr &&
         request->receipts != nullptr && request->count != 0 &&
         request->count <= kMaxEvents;
}

/*
 * The one envelope for a refusal that never reached SendInput: a coherent
 * snapshot of the guard (its current epoch, state and flags), inserted and
 * submitted at 0, and a full set of receipts - NOT_SUBMITTED for every hold
 * event, NOT_TRACKED for every event that holds nothing. The caller can tell
 * this confirmed zero submission from a submission whose fate is unknown, and
 * never has to read a zero epoch as a contradiction. `receipts_usable` is false
 * only for a request this build cannot read, where nothing can be written into
 * the caller's arrays.
 */
void refuse_batch(const rd_input_send_request* request,
                  rd_input_send_result* result, bool receipts_usable) {
  GuardLock lock;
  Guard& g = guard();
  if (receipts_usable) fill_refused_receipts(request);
  result->epoch = g.epoch;
  result->guard_state = g.state;
  result->flags = g.flags;
  result->inserted = 0;
  result->submitted = 0;
}

/* One batch, and the defensive boundary an unexpected fault inside it goes
 * through. Neither allocates: the file has no allocation on this path at all. */
rd_input_status send_batch(const rd_input_send_request* request,
                           rd_input_send_result* result);
rd_input_status send_interrupted(const rd_input_send_request* request,
                                 rd_input_send_result* result);

}  // namespace

extern "C" rd_input_status RD_INPUT_CALL rd_input_send(
    const rd_input_send_request* request, rd_input_send_result* result) {
#if defined(_CPPUNWIND) || defined(__EXCEPTIONS)
  /* There is no allocation on this path, so this boundary is defensive: an
   * exception that escaped would leave published descriptors behind and would
   * cross back into the caller's C code. */
  try {
    return send_batch(request, result);
  } catch (...) {
    return send_interrupted(request, result);
  }
#else
  return send_batch(request, result);
#endif
}

namespace {

rd_input_status send_batch(const rd_input_send_request* request,
                           rd_input_send_result* result) {
  if (result == nullptr) return RD_INPUT_INVALID_ARGUMENT;
  std::memset(result, 0, sizeof(*result));
  result->struct_size = static_cast<uint32_t>(sizeof(rd_input_send_result));
  const bool readable = request_readable(request);
  if (!readable || request->reserved != 0) {
    /* A structure this build cannot read says nothing about the events, but the
     * guard's own state is still reported coherently. */
    refuse_batch(request, result, readable);
    return RD_INPUT_INVALID_ARGUMENT;
  }
  const uint32_t count = request->count;
  /* Validate the whole batch, and the episode bookkeeping with it, before any
   * of it is injected: nothing below is reached by a batch that is refused
   * here, and every refusal of this kind reports the same zero-submission
   * envelope. */
  uint32_t tracked_count = 0;
  for (uint32_t index = 0; index < count; ++index) {
    const rd_input_status status = validate_event(request->events[index]);
    if (status != RD_INPUT_OK) {
      refuse_batch(request, result, true);
      return status;
    }
    const uint32_t key = event_hold_key(request->events[index]);
    const uint64_t episode = request->episodes[index];
    if (key != 0 && episode == 0) {
      refuse_batch(request, result, true);
      return RD_INPUT_INVALID_ARGUMENT;
    }
    if (key == 0 && episode != 0) {
      refuse_batch(request, result, true);
      return RD_INPUT_INVALID_ARGUMENT;
    }
    if (key != 0 && ++tracked_count > kMaxDescriptors) {
      /* More holds than one transaction may carry: a parameter refusal, not a
       * submission and not a fault. The caller bounds a batch the same way. */
      refuse_batch(request, result, true);
      return RD_INPUT_INVALID_ARGUMENT;
    }
  }

  /* The event index of each tracked event, or kNoDescriptor. */
  uint32_t descriptor_of[kMaxEvents];
  uint64_t cookie_of[kMaxDescriptors];
  uint32_t descriptor_count = 0;
  const uint64_t now = GetTickCount64();
  rd_input_status refused = RD_INPUT_OK;
  {
    GuardLock lock;
    Guard& g = guard();
    if (g.state != RD_INPUT_GUARD_ARMED || g.epoch != request->epoch) {
      refused = RD_INPUT_GUARD_UNAVAILABLE;
    } else if (g.heartbeat_tick != 0 &&
               now - g.heartbeat_tick > kHeartbeatTimeoutMs) {
      fault_locked(g, RD_INPUT_GUARD_FLAG_HEARTBEAT_STALE);
      refused = RD_INPUT_GUARD_UNAVAILABLE;
    } else if (g.serial_exhausted || g.observation_exhausted) {
      g.flags |= RD_INPUT_GUARD_FLAG_SERIAL_EXHAUSTED;
      refused = RD_INPUT_GUARD_UNAVAILABLE;
    } else {
      /* These receipts belong to the epoch the guard is armed for, which is the
       * one the batch was planned under. */
      result->epoch = g.epoch;
      /* Publish every descriptor before SendInput runs, so a callback that
       * arrives while the batch is in flight already has the stable record. */
      uint32_t next_free = 0;
      for (uint32_t index = 0; index < count; ++index) {
        const rd_input_event& event = request->events[index];
        const uint32_t key = event_hold_key(event);
        if (key == 0) {
          descriptor_of[index] = kNoDescriptor;
          continue;
        }
        while (next_free < kMaxDescriptors &&
               g.descriptors[next_free].state != kDescriptorFree) {
          ++next_free;
        }
        if (next_free == kMaxDescriptors) {
          release_published_locked(g, descriptor_of, index);
          fault_locked(g, RD_INPUT_GUARD_FLAG_STORAGE_EXHAUSTED);
          refused = RD_INPUT_GUARD_UNAVAILABLE;
          break;
        }
        if (g.token_serial >= kMaxTokenSerial) {
          release_published_locked(g, descriptor_of, index);
          g.serial_exhausted = true;
          g.flags |= RD_INPUT_GUARD_FLAG_SERIAL_EXHAUSTED;
          refused = RD_INPUT_GUARD_UNAVAILABLE;
          break;
        }
        const uint32_t serial = ++g.token_serial;
        Descriptor& descriptor = g.descriptors[next_free];
        descriptor.cookie = kTokenBase + serial;
        descriptor.lease = request->lease;
        descriptor.episode = request->episodes[index];
        descriptor.transaction = request->transaction;
        descriptor.event_index = index;
        descriptor.key = key;
        descriptor.up = event.kind == RD_INPUT_EVENT_MOUSE
                            ? event.action == RD_INPUT_MOUSE_BUTTON_UP
                            : (event.flags & RD_INPUT_KEY_UP) != 0;
        descriptor.epoch = request->epoch;
        descriptor.state = kDescriptorLive;
        descriptor.receipt = RD_INPUT_RECEIPT_UNKNOWN;
        descriptor_of[index] = next_free;
        cookie_of[descriptor_count] = descriptor.cookie;
        ++descriptor_count;
        ++next_free;
      }
    }
  }
  if (refused != RD_INPUT_OK) {
    /* Nothing of this batch reached SendInput: the caller gets the same
     * zero-submission envelope as any other refusal, with the guard's state as
     * it is after the fault this refusal recorded. */
    refuse_batch(request, result, true);
    return refused;
  }

  /* SendInput is never reached on any desktop other than the ordinary
   * interactive one. */
  if (classify_desktop() != RD_INPUT_DESKTOP_INTERACTIVE) {
    {
      GuardLock lock;
      Guard& g = guard();
      release_published_locked(g, descriptor_of, count);
      fault_locked(g, RD_INPUT_GUARD_FLAG_DESKTOP_LEFT);
    }
    refuse_batch(request, result, true);
    return RD_INPUT_DESKTOP_UNAVAILABLE;
  }

  uint32_t inserted = 0;
  {
    /* The guard owns the one buffer a batch is built in: no allocation happens
     * here, none can fail, and no other sender can be filling it while this
     * call is in SendInput. */
    SendLock batch_lock;
    Guard& g = guard();
    uint32_t tracked_index = 0;
    for (uint32_t index = 0; index < count; ++index) {
      /* A tracked event carries its descriptor's token; an event that holds
       * nothing carries none, so the guard never has to read a token of its own
       * without a transaction to match it. */
      const uint64_t token = descriptor_of[index] == kNoDescriptor
                                 ? 0
                                 : cookie_of[tracked_index++];
      g.scratch[index] = to_input(request->events[index], token);
    }
    inserted = SendInput(count, g.scratch, sizeof(INPUT));
  }
  result->inserted = inserted;
  result->submitted = count;

  /* SendInput does not return before the hook has run for the events it
   * inserted, so a terminal receipt is normally already there. Wait a bounded
   * time anyway: a tracked event with no receipt afterwards is exactly the case
   * this guard exists to notice. */
  bool missing = false;
  {
    uint32_t waited = 0;
    for (;;) {
      bool terminal = true;
      {
        GuardLock lock;
        Guard& g = guard();
        for (uint32_t index = 0; index < count; ++index) {
          if (descriptor_of[index] == kNoDescriptor) continue;
          if (g.descriptors[descriptor_of[index]].receipt ==
              RD_INPUT_RECEIPT_UNKNOWN) {
            terminal = false;
            break;
          }
        }
      }
      if (terminal) break;
      if (waited >= kReceiptWaitMs) {
        missing = true;
        break;
      }
      Sleep(1);
      ++waited;
    }
  }

  rd_input_status outcome = RD_INPUT_OK;
  {
    GuardLock lock;
    Guard& g = guard();
    for (uint32_t index = 0; index < count; ++index) {
      if (descriptor_of[index] == kNoDescriptor) {
        request->receipts[index] = RD_INPUT_RECEIPT_NOT_TRACKED;
        continue;
      }
      Descriptor& descriptor = g.descriptors[descriptor_of[index]];
      request->receipts[index] = descriptor.receipt;
      if (descriptor.receipt == RD_INPUT_RECEIPT_UNKNOWN) {
        /* Its fate is unknown: keep the record so a late event of it is still
         * recognized, and never reuse the token. */
        missing = true;
        descriptor.state = kDescriptorSealed;
      } else {
        descriptor.state = kDescriptorFree;
        descriptor.cookie = 0;
      }
    }
    if (missing) {
      fault_locked(g, RD_INPUT_GUARD_FLAG_MISSING_RECEIPT);
      outcome = RD_INPUT_GUARD_UNAVAILABLE;
    } else if (inserted != count) {
      outcome = RD_INPUT_INJECTION_FAILED;
    } else if (g.state != RD_INPUT_GUARD_ARMED) {
      outcome = RD_INPUT_GUARD_UNAVAILABLE;
    }
    result->guard_state = g.state;
    result->flags = g.flags;
  }
  if (outcome != RD_INPUT_OK) return outcome;
  if (inserted == 0 && classify_desktop() != RD_INPUT_DESKTOP_INTERACTIVE) {
    GuardLock lock;
    Guard& g = guard();
    fault_locked(g, RD_INPUT_GUARD_FLAG_DESKTOP_LEFT);
    result->guard_state = g.state;
    result->flags = g.flags;
    return RD_INPUT_DESKTOP_UNAVAILABLE;
  }
  return RD_INPUT_OK;
}

/*
 * The defensive boundary for an unexpected fault inside send_batch. No path
 * there allocates, so this is not an expected state - but a descriptor published
 * before the call must never be left as if its transaction had been resolved, and
 * no exception may cross back into the caller's C.
 *
 * Nothing is claimed about the events: every hold event reads UNKNOWN (they may
 * or may not have reached the system), their descriptors are sealed so a late
 * event of them is still recognized and no token is reused, the guard closes
 * admission, and submitted is reported as the batch's event count - never 0,
 * which would assert that SendInput was not reached. submitted with UNKNOWN
 * receipts is not the zero-submission envelope of a parameter refusal.
 */
rd_input_status send_interrupted(const rd_input_send_request* request,
                                 rd_input_send_result* result) {
  if (result == nullptr) return RD_INPUT_INVALID_ARGUMENT;
  std::memset(result, 0, sizeof(*result));
  result->struct_size = static_cast<uint32_t>(sizeof(rd_input_send_result));
  const bool readable = request_readable(request);
  GuardLock lock;
  Guard& g = guard();
  if (readable) {
    for (uint32_t index = 0; index < request->count; ++index) {
      request->receipts[index] =
          event_hold_key(request->events[index]) != 0
              ? RD_INPUT_RECEIPT_UNKNOWN
              : RD_INPUT_RECEIPT_NOT_TRACKED;
    }
    for (uint32_t i = 0; i < kMaxDescriptors; ++i) {
      Descriptor& descriptor = g.descriptors[i];
      if (descriptor.state != kDescriptorLive ||
          descriptor.transaction != request->transaction) {
        continue;
      }
      descriptor.state = kDescriptorSealed;
      descriptor.receipt = RD_INPUT_RECEIPT_UNKNOWN;
    }
  }
  fault_locked(g, RD_INPUT_GUARD_FLAG_MISSING_RECEIPT);
  result->epoch = g.epoch;
  result->guard_state = g.state;
  result->flags = g.flags;
  result->submitted = readable ? request->count : 0u;
  return RD_INPUT_GUARD_UNAVAILABLE;
}

}  // namespace

extern "C" rd_input_status RD_INPUT_CALL rd_input_key_for_character(
    uint32_t character, uint32_t* virtual_key, uint32_t* scan_code,
    uint32_t* extended, uint32_t* shift_state) {
  if (virtual_key == nullptr || scan_code == nullptr || extended == nullptr ||
      shift_state == nullptr) {
    return RD_INPUT_INVALID_ARGUMENT;
  }
  if (character == 0 || character > 0xFFFF) return RD_INPUT_INVALID_ARGUMENT;
  const HKL layout = active_layout();
  const SHORT translated = VkKeyScanExW(static_cast<WCHAR>(character), layout);
  if (translated == -1) return RD_INPUT_UNSUPPORTED;
  const uint32_t key = static_cast<uint32_t>(translated) & 0xFFu;
  *virtual_key = key;
  *shift_state = (static_cast<uint32_t>(translated) >> 8) & 0xFFu;
  return scan_for_key(key, layout, scan_code, extended);
}

extern "C" rd_input_status RD_INPUT_CALL rd_input_key_scan(
    uint32_t virtual_key, uint32_t* scan_code, uint32_t* extended) {
  if (scan_code == nullptr || extended == nullptr) {
    return RD_INPUT_INVALID_ARGUMENT;
  }
  if (virtual_key == 0 || virtual_key > kMaxVirtualKey) {
    return RD_INPUT_INVALID_ARGUMENT;
  }
  return scan_for_key(virtual_key, active_layout(), scan_code, extended);
}

extern "C" rd_input_status RD_INPUT_CALL rd_input_key_for_scancode(
    uint32_t scan_code, uint32_t* virtual_key) {
  if (virtual_key == nullptr) return RD_INPUT_INVALID_ARGUMENT;
  *virtual_key = 0;
  if (!map_scan_valid(scan_code)) return RD_INPUT_INVALID_ARGUMENT;
  const UINT key = MapVirtualKeyExW(scan_code, MAPVK_VSC_TO_VK_EX, active_layout());
  if (key <= VK_XBUTTON2 || key > kMaxVirtualKey || key == VK_PACKET) {
    return RD_INPUT_UNSUPPORTED;
  }
  *virtual_key = key;
  return RD_INPUT_OK;
}

static_assert(WHEEL_DELTA == 120, "wheel unit");
static_assert(kWheelDelta == static_cast<uint32_t>(WHEEL_DELTA), "wheel unit");
static_assert(kMaxVirtualKey < 256, "virtual key space");
static_assert(MOUSEEVENTF_ABSOLUTE == 0x8000, "absolute mouse flag");
static_assert(MOUSEEVENTF_VIRTUALDESK == 0x4000, "virtual desktop flag");
static_assert(XBUTTON1 == 1 && XBUTTON2 == 2, "extra mouse button tags");
static_assert(LLKHF_INJECTED == 0x10, "keyboard injection mark");
static_assert(LLKHF_LOWER_IL_INJECTED == 0x02, "keyboard lower-IL mark");
static_assert(LLKHF_UP == 0x80, "keyboard transition mark");
static_assert(LLMHF_INJECTED == 0x01, "mouse injection mark");
static_assert(KEYEVENTF_SCANCODE == 0x0008, "physical keyboard flag");
