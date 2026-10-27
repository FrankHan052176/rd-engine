//! Checked Windows input injection for the modern host.
//!
//! One [`InputSession`] is one authenticated peer's lease on the local desktop.
//! Everything it injects goes through the native adapter in
//! `native/windows-input/`, which classifies the input desktop and calls
//! `SendInput`; this module owns the wire decode, the output binding, the
//! ownership bookkeeping and the reclamation verdicts.
//!
//! # Wire decode (established kinds and buttons only)
//!
//! `MouseEvent.mask` is `kind | (button_bits << 3)`. The low three bits are the
//! kind and bits 3..8 the button field, exactly as `Viewer::send_mouse` encodes
//! it:
//!
//! | kind | meaning | button field | x, y |
//! | --- | --- | --- | --- |
//! | 0 | move to a display-local point | the client's held-button declaration, not acted on | display-local pixels |
//! | 1 | button down | exactly one of 1, 2, 4, 8, 16 | display-local pixels of the pointer the client believes it has |
//! | 2 | button up | exactly one of 1, 2, 4, 8, 16 | as kind 1 |
//! | 3 | wheel | 0 | signed notches, x horizontal and y vertical |
//! | 4 | trackpad scroll | 0 | signed eighth-notches |
//! | 5 | relative move | 0 | signed pixels |
//!
//! Any other kind, any button field that is not exactly one established bit on
//! kinds 1 and 2, and any nonzero button field on kinds 3 to 5, is refused.
//! A `(0, 0)` relative move is the legacy relative-mouse-mode marker: it asks
//! for no motion, so it is accepted without injecting anything. `(0, 0)` wheel
//! and trackpad events carry no rotation and are refused.
//!
//! `MouseEvent.modifiers` is not acted on: the legacy pointer message announces
//! modifier state and the keyboard messages are what establish it, so a mouse
//! event never presses or releases a key here.
//!
//! # Coordinates
//!
//! The wire is selected-display-local. Kinds 0 to 2 are validated as
//! `0 <= x < width` and `0 <= y < height` of the frozen binding, and kind 0
//! translates them exactly once (`checked_add` of the display's left/top) into
//! virtual-desktop coordinates, which are then normalized for
//! `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK` into 0..65535, with the last
//! pixel of the virtual screen as the 65535 endpoint. Negative virtual origins
//! and a one-pixel virtual screen are handled explicitly. Kinds 1 and 2 never
//! reposition the pointer: the client positions it with its own move (both Resk
//! paths do), and warping on a transition would fight relative-mouse mode, whose
//! transitions carry the client's virtual-cursor model rather than the pointer's
//! real position. Kinds 3 to 5 are deltas and are never translated: their x and y
//! reach the OS unchanged in sign and magnitude.
//!
//! # Wheel, trackpad and relative signs
//!
//! One wheel notch is one wire unit. The vertical sign is the engine's own:
//! `rfb_pointer` in `viewer.rs` maps a negative y to RFB's wheel-up bit, so
//! `y < 0` is one notch up and `MOUSEEVENTF_WHEEL` (whose positive value is a
//! rotation away from the user) receives `-y * WHEEL_DELTA`. The horizontal sign
//! mirrors the same client-side negation: `x > 0` is right and
//! `MOUSEEVENTF_HWHEEL` receives `x * WHEEL_DELTA`. More than
//! `MAX_WHEEL_NOTCHES` notches in one event is refused rather than clipped.
//!
//! A trackpad event carries the same axes in eighth-notches, which is how the
//! client scales a gesture against the wheel's one-step normalization. Windows
//! has no sub-notch scroll injection through `SendInput`, so whole notches are
//! emitted and the remainder is kept in this lease until the next event: no
//! gesture is lost and none is inflated. The remainder is never OS state, so it
//! needs no reclamation.
//!
//! # Keys
//!
//! `KeyboardMode::Map` carries the pinned official sender's Windows physical
//! scan code in `chr`, not a character. It goes through this same guarded batch
//! with `KEYEVENTF_SCANCODE`, retaining the complete E0-prefixed wire code and
//! the OS-mapped canonical key in the opening down's encoding. Repeat/up and
//! cleanup find that record before querying any new layout. If Windows changes
//! the actual hook VK, the existing guard vetoes the mismatch and retains the
//! episode; it never migrates ownership or falls back to virtual-key injection.
//! Pause is the pinned sender's genuine Legacy control-key exception; Map E1
//! sequences and zero/unknown scans are not synthesized or relabelled.
//!
//! In `Legacy`, a control key becomes its Win32 virtual key, with a scan code
//! from `MapVirtualKeyExW`. A `chr` is translated with `VkKeyScanExW` in the
//! foreground window's layout, with its transient shift/ctrl/alt requirements.
//! `unicode` and bounded `seq` text use UTF-16 input. `win2win_hotkey`,
//! `Translate`/`Auto`, `CtrlAltDel`, `LockScreen`, the phone-only power key and
//! `Unknown` remain refused: no secure attention sequence, shell lock action,
//! integrity elevation or UIAccess is synthesized here. Map modifier metadata
//! does not repair global modifier/lock state; physical transitions own it.
//!
//! # Desktop policy and Win32 boundaries
//!
//! Every batch re-checks that the calling session's input desktop is the ordinary
//! interactive one and that the bound output is still exactly the bound output,
//! and the native adapter checks the desktop again before `SendInput`. Input is
//! never injected while the secure desktop (UAC prompt, Ctrl+Alt+Del, logon) or
//! any other desktop is in front, and this engine has no path around UIPI: a
//! `SendInput` return value counts inserted events, not delivered ones, so input
//! aimed at a higher-integrity window can be withheld by the OS while the call
//! reports success. That is reported as what it is and never worked around.
//!
//! # Ownership, arbitration and reclamation
//!
//! Only a down this engine actually injected is recorded, in one process-wide
//! table keyed by the canonical hold key (mouse buttons live in the same Win32
//! virtual-key space). That gives two guarantees on its own:
//!
//! * One lease can only release what it claimed, so peer A disconnecting cannot
//!   lift peer B's hold, and a recorded hold cannot be stolen.
//! * Before a down is injected the guard reports whether a hold of anyone's is
//!   known on the key. If one is, and no lease owns it, the down is not injected
//!   and not recorded, so the hold - typically the operator's own hand - stays
//!   untouched and this lease can never lift it.
//!
//! On top of that table the native adapter holds an observation guard: a
//! dedicated message thread with `WH_KEYBOARD_LL` and `WH_MOUSE_LL`, one state
//! entry per canonical hold key, one descriptor per hold event of the batch
//! being injected, and a per-event receipt. Every own hold event carries the
//! descriptor's token, so the guard can decide at the event - not at the next
//! send - whether letting it through would lift something it does not own. The
//! protection that follows, and its exact conditions:
//!
//! * While the guard is observing an epoch, an up is refused if a down that is
//!   not this engine's own was seen on that key after this engine's down. That
//!   is what stops the remote release - and a disconnect - from lifting the
//!   operator's own key press or another input source's hold. Local and
//!   third-party events always pass through: only an event carrying a token of
//!   this adapter's that the guard knows is unsafe or stale is refused.
//! * The up carries the episode of the down it releases, and the record keeps
//!   the encoding that down really used, so a release cannot hit a different
//!   press, a different lease, a re-pressed key or a key a layout change moved.
//! * A down for a key this lease already holds - an ordinary repeat of a held
//!   key, or a `press` on it - repeats that episode and its original encoding
//!   instead of opening a second one, and never becomes an up: the hold the
//!   first down took stays until its own release. The repeat claims nothing and
//!   releases nothing, so the record, its episode and its collision history are
//!   exactly what they were.
//! * Only a receipt saying the event passed the guard and the rest of the hook
//!   chain releases a record. A refused, unknown or partially inserted event
//!   leaves the record owned, so a collision, a downstream hook's veto, a
//!   partial batch or a missing receipt never turns into a false release. A
//!   reply that contradicts itself is not consumed at all: nothing of such a
//!   batch is trusted to release an owner or to confirm a hold.
//! * Once such a hold is in doubt it is resolved by evidence instead of by
//!   sending another up: the guard retires the episode only when the key's
//!   merged state reads up in a usable ordinary-desktop context, no event for
//!   that key arrived after that sample, the episode has no event in flight, and
//!   - when a colliding source was seen - that source released after the last
//!   collision. Retiring clears the record; it does not lift anything and it
//!   sends nothing. Every later up, click, repeat and cleanup for that key takes
//!   this path too: a hold in doubt is never released, repeated or confirmed, a
//!   click on it stops at resolving the doubt, and it is that retirement alone -
//!   never a new up - that ends the doubt.
//!
//! What that does not claim, stated rather than papered over:
//!
//! * A low-level hook can be silently removed by Windows when it exceeds
//!   `LowLevelHooksTimeout`, with no API to observe it. A missing receipt
//!   notices that after the fact - the event that was not observed may already
//!   have been delivered - and the guard then closes admission and keeps the
//!   records. A heartbeat says the message thread pumped; it does not say the
//!   hook is still in the chain. The window between such a removal and the
//!   first event that misses a receipt is real, and nothing here can close it.
//! * A low-level hook carries no device id, so "up" is a statement about the
//!   merged input stream of this session, not about every keyboard and mouse.
//!   Two devices holding the same key, or a key that was already down before
//!   this guard existed, cannot be told apart from one; such a key is treated as
//!   unknown and is not claimed again. A fault, a desktop change or a lost
//!   receipt ends observation continuity for the epoch, and an episode from such
//!   an epoch can never be retired: it stays unresolved, and the guard stays
//!   installed behind it.
//! * Third-party injected input is not the operator's hand either, but it is
//!   occupancy this engine must not lift, so it is treated the same way. A
//!   process may forge the token, and the token is only an association mark, not
//!   a credential; a forged or late token is refused and faults the guard.
//! * `SendInput` inserts a batch in order and does not promise that a short
//!   count means a leading prefix took effect, so the count is never used to
//!   decide which events happened here: the receipts are. Two peers injecting on
//!   one desktop still cannot be attributed to a device, and a hidden injector
//!   at a higher integrity level is not visible to this engine at all.
//!
//! `SendInput` also does not reset the keyboard's state, so a down this engine
//! injects can be refused before it is sent when the guard reports the key is
//! already down. [`InputSession::release_all`] releases everything this lease
//! still owns, in as many bounded batches as the guard has descriptor room for,
//! and answers [`InputError::ReclamationUnconfirmed`] while anything is
//! unresolved, keeping the record and the guard lease - and therefore the
//! message thread, the descriptors and the observed state - alive. A batch the
//! adapter refused whole, before it handed anything to `SendInput`, is a
//! parameter refusal: it moves no ownership and does not end this lease's
//! admission, which is what keeps a malformed event from quarantining a hold
//! that was taken normally. Drop is best effort only; `release_all` is the
//! checked boundary, and a session whose holds could not be resolved never gives
//! its guard lease back. Neither does a session whose lease the guard could not
//! stop: that obligation is kept and retried, so a later `release_all` answers
//! the same way instead of reporting a clean stop it did not get.
//!
//! # No input content leaves this module
//!
//! There is no input-content logging or telemetry. The owner can observe only
//! all-peer submission/receipt sequence, click/mouse wall-clock milliseconds and
//! uncertainty, with a separate monotonic sensitive-action gate. Every error is
//! a constant string: no key, coordinate, character or text leaves this module.

use crate::windows_native::{OutputId, OutputInfo, enumerate_outputs};
use crate::windows_publisher::ProducerError;
use base::message_proto::{ControlKey, KeyEvent, KeyboardMode, MouseEvent, key_event};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The legacy pointer mask's kind bits.
const MASK_KIND: u32 = 0x07;
/// The legacy pointer mask's button field starts at bit 3.
const MASK_BUTTON_SHIFT: u32 = 3;
/// The legacy pointer mask's five-bit button field.
const MASK_BUTTON: u32 = 0x1f << MASK_BUTTON_SHIFT;
/// Bits the established mask may carry; anything else is refused.
const MASK_KNOWN: u32 = MASK_KIND | MASK_BUTTON;

const KIND_MOVE: u32 = 0;
const KIND_BUTTON_DOWN: u32 = 1;
const KIND_BUTTON_UP: u32 = 2;
const KIND_WHEEL: u32 = 3;
const KIND_TRACKPAD: u32 = 4;
const KIND_MOVE_RELATIVE: u32 = 5;

const BUTTON_LEFT_BIT: u32 = 0x01;
const BUTTON_RIGHT_BIT: u32 = 0x02;
const BUTTON_MIDDLE_BIT: u32 = 0x04;
const BUTTON_BACK_BIT: u32 = 0x08;
const BUTTON_FORWARD_BIT: u32 = 0x10;

/// One wheel notch, in the unit `MOUSEEVENTF_WHEEL` counts.
const WHEEL_DELTA: i32 = 120;
/// Largest rotation one event may carry, in notches.
const MAX_WHEEL_NOTCHES: i32 = 255;
/// The trackpad kind's unit: eighths of a notch.
const TRACKPAD_UNITS_PER_NOTCH: i32 = 8;
const MAX_TRACKPAD_UNITS: i32 = MAX_WHEEL_NOTCHES * TRACKPAD_UNITS_PER_NOTCH;
/// Largest relative pointer delta one event may carry, in pixels.
const MAX_RELATIVE_PIXELS: i32 = 0x7fff;
/// Most UTF-16 code units one `seq` event may type.
const MAX_SEQ_UNITS: usize = 2048;
/// Upper bound on one batch: a bounded `seq` plus its modifiers. Mirrors
/// `RD_INPUT_MAX_EVENTS` in `native/windows-input/windows_input.h`.
const MAX_BATCH_EVENTS: usize = MAX_SEQ_UNITS * 2 + 16;
/// Upper bound on the hold events (key and mouse button down/up events) one
/// batch may carry, which is what the guard has descriptor space for. Mirrors
/// `RD_INPUT_MAX_HOLDS`.
const MAX_BATCH_HOLDS: usize = 64;
/// Most distinct modifiers one key event may require.
const MAX_TRANSIENT_MODIFIERS: usize = 8;
/// Canonical hold keys this adapter tracks: a virtual key, and that key with its
/// E0 form folded in as 0x100. Mirrors the guard's own table.
const MAX_HOLD_KEYS: usize = 0x200;

/// Win32 virtual keys this adapter injects, from `winuser.h`; the adapter ABI is
/// plain integers, so the values live here.
const VK_LBUTTON: u32 = 0x01;
const VK_RBUTTON: u32 = 0x02;
const VK_CANCEL: u32 = 0x03;
const VK_MBUTTON: u32 = 0x04;
const VK_XBUTTON1: u32 = 0x05;
const VK_XBUTTON2: u32 = 0x06;
const VK_BACK: u32 = 0x08;
const VK_TAB: u32 = 0x09;
const VK_CLEAR: u32 = 0x0c;
const VK_RETURN: u32 = 0x0d;
const VK_SHIFT: u32 = 0x10;
const VK_CONTROL: u32 = 0x11;
const VK_MENU: u32 = 0x12;
const VK_PAUSE: u32 = 0x13;
const VK_CAPITAL: u32 = 0x14;
const VK_KANA: u32 = 0x15;
const VK_HANGUL: u32 = 0x15;
const VK_JUNJA: u32 = 0x17;
const VK_FINAL: u32 = 0x18;
const VK_HANJA: u32 = 0x19;
const VK_KANJI: u32 = 0x19;
const VK_ESCAPE: u32 = 0x1b;
const VK_CONVERT: u32 = 0x1c;
const VK_SPACE: u32 = 0x20;
const VK_PRIOR: u32 = 0x21;
const VK_NEXT: u32 = 0x22;
const VK_END: u32 = 0x23;
const VK_HOME: u32 = 0x24;
const VK_LEFT: u32 = 0x25;
const VK_UP: u32 = 0x26;
const VK_RIGHT: u32 = 0x27;
const VK_DOWN: u32 = 0x28;
const VK_SELECT: u32 = 0x29;
const VK_PRINT: u32 = 0x2a;
const VK_EXECUTE: u32 = 0x2b;
const VK_SNAPSHOT: u32 = 0x2c;
const VK_INSERT: u32 = 0x2d;
const VK_DELETE: u32 = 0x2e;
const VK_HELP: u32 = 0x2f;
const VK_LWIN: u32 = 0x5b;
const VK_RWIN: u32 = 0x5c;
const VK_APPS: u32 = 0x5d;
const VK_SLEEP: u32 = 0x5f;
const VK_NUMPAD0: u32 = 0x60;
const VK_NUMPAD1: u32 = 0x61;
const VK_NUMPAD2: u32 = 0x62;
const VK_NUMPAD3: u32 = 0x63;
const VK_NUMPAD4: u32 = 0x64;
const VK_NUMPAD5: u32 = 0x65;
const VK_NUMPAD6: u32 = 0x66;
const VK_NUMPAD7: u32 = 0x67;
const VK_NUMPAD8: u32 = 0x68;
const VK_NUMPAD9: u32 = 0x69;
const VK_MULTIPLY: u32 = 0x6a;
const VK_ADD: u32 = 0x6b;
const VK_SEPARATOR: u32 = 0x6c;
const VK_SUBTRACT: u32 = 0x6d;
const VK_DECIMAL: u32 = 0x6e;
const VK_DIVIDE: u32 = 0x6f;
const VK_F1: u32 = 0x70;
const VK_F2: u32 = 0x71;
const VK_F3: u32 = 0x72;
const VK_F4: u32 = 0x73;
const VK_F5: u32 = 0x74;
const VK_F6: u32 = 0x75;
const VK_F7: u32 = 0x76;
const VK_F8: u32 = 0x77;
const VK_F9: u32 = 0x78;
const VK_F10: u32 = 0x79;
const VK_F11: u32 = 0x7a;
const VK_F12: u32 = 0x7b;
const VK_NUMLOCK: u32 = 0x90;
const VK_SCROLL: u32 = 0x91;
const VK_OEM_PLUS: u32 = 0xbb;
const VK_RSHIFT: u32 = 0xa1;
const VK_RCONTROL: u32 = 0xa3;
const VK_RMENU: u32 = 0xa5;
const VK_VOLUME_MUTE: u32 = 0xad;
const VK_VOLUME_DOWN: u32 = 0xae;
const VK_VOLUME_UP: u32 = 0xaf;

/// The numpad's Enter, which shares `VK_RETURN` with the main Enter and is told
/// apart only by its E0-prefixed scan code.
const SCAN_NUMPAD_ENTER: u32 = 0x1c;

/// One input failure. Every message is a constant: no coordinate, key, character
/// or text can reach a caller's log or UI through this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InputError {
    /// This build, adapter or wire form cannot express the request.
    Unsupported,
    /// The request is not valid on the wire contract.
    InvalidInput,
    /// There is no ordinary interactive input desktop to inject into.
    DesktopUnavailable,
    /// The bound output is no longer the one that was bound.
    OutputChanged,
    /// The operating system did not accept the input.
    InjectionFailed,
    /// An injected key or button may still be down, or a hold the guard was
    /// watching could not be resolved and stays owned.
    ReclamationUnconfirmed,
}

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "this input form is not supported on the Windows host",
            Self::InvalidInput => "the input event is not valid on the wire contract",
            Self::DesktopUnavailable => {
                "the ordinary interactive desktop is not available for injection"
            }
            Self::OutputChanged => "the bound desktop output is no longer the one that was bound",
            Self::InjectionFailed => "the operating system did not accept the input",
            Self::ReclamationUnconfirmed => {
                "an injected key or button may still be down, and a hold was left unresolved"
            }
        })
    }
}

impl std::error::Error for InputError {}

/// The frozen identity of one desktop output: the adapter's own output key plus
/// the native id and rectangle it named at the moment it was frozen.
///
/// A binding is only built from an enumerated output with a non-empty rectangle,
/// so `width` and `height` are positive for every binding that exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TargetBinding {
    key: String,
    output_id: OutputId,
    desktop_rect: [i32; 4],
}

impl TargetBinding {
    /// The stable output key this binding was resolved from.
    pub(crate) fn key(&self) -> &str {
        &self.key
    }

    /// The native output id, for the publisher and the capture open.
    pub(crate) fn output_id(&self) -> OutputId {
        self.output_id
    }

    /// The desktop-space rectangle frozen at binding time.
    pub(crate) fn desktop_rect(&self) -> [i32; 4] {
        self.desktop_rect
    }

    /// Frozen width in pixels.
    pub(crate) fn width(&self) -> i32 {
        self.desktop_rect[2] - self.desktop_rect[0]
    }

    /// Frozen height in pixels.
    pub(crate) fn height(&self) -> i32 {
        self.desktop_rect[3] - self.desktop_rect[1]
    }

    /// Requires the exact same native output, at the exact same rectangle, to
    /// still be attached. A replaced or moved display fails rather than being
    /// accepted as "the same screen".
    pub(crate) fn verify_current(&self) -> Result<(), InputError> {
        if self.width() <= 0 || self.height() <= 0 {
            return Err(InputError::OutputChanged);
        }
        let outputs = enumerate_outputs().map_err(map_enumerate_error)?;
        let current = outputs
            .iter()
            .find(|output| output.id == self.output_id)
            .ok_or(InputError::OutputChanged)?;
        if current.desktop_rect != self.desktop_rect {
            return Err(InputError::OutputChanged);
        }
        Ok(())
    }
}

/// The stable key of one enumerated output: the adapter's LUID and the output's
/// native index, both as the adapter reports them, in a form that is
/// deterministic and carries no user data (no device name, no position).
pub(crate) fn output_key(id: OutputId) -> String {
    let adapter = id.adapter_luid.0;
    format!(
        "{:08x}:{:08x}:{}",
        (adapter >> 32) as u32,
        adapter as u32,
        id.output_index
    )
}

/// Resolves one stable output key to a frozen binding, or fails.
///
/// The key is matched against the outputs the adapter reports right now, exactly:
/// there is no fallback to an ordinal, a device name or a size, so an output that
/// was replaced cannot be silently bound in place of the one the caller chose.
pub(crate) fn bind_output_key(key: &str) -> Result<TargetBinding, InputError> {
    if !output_key_is_well_formed(key) {
        return Err(InputError::InvalidInput);
    }
    let outputs = enumerate_outputs().map_err(map_enumerate_error)?;
    let mut matched = None;
    for output in outputs {
        if output_key(output.id) == key {
            matched = Some(output);
            break;
        }
    }
    let output = matched.ok_or(InputError::OutputChanged)?;
    binding_from(output)
}

/// Resolves one position in the adapter's own output list: discovery for a local
/// picker or CLI, which then keeps the frozen binding.
pub(crate) fn binding_for_index(index: usize) -> Result<TargetBinding, InputError> {
    let outputs = enumerate_outputs().map_err(map_enumerate_error)?;
    let output = outputs
        .into_iter()
        .nth(index)
        .ok_or(InputError::OutputChanged)?;
    binding_from(output)
}

fn binding_from(output: OutputInfo) -> Result<TargetBinding, InputError> {
    let binding = TargetBinding {
        key: output_key(output.id),
        output_id: output.id,
        desktop_rect: output.desktop_rect,
    };
    if binding.width() <= 0 || binding.height() <= 0 {
        return Err(InputError::OutputChanged);
    }
    Ok(binding)
}

/// The shape `output_key` writes: two eight-digit LUID halves and the native
/// output index, colon separated and nothing else.
fn output_key_is_well_formed(key: &str) -> bool {
    const MAX_KEY_CHARS: usize = 32;
    if key.is_empty() || key.len() > MAX_KEY_CHARS || !key.is_ascii() {
        return false;
    }
    let mut parts = key.split(':');
    let (Some(high), Some(low), Some(index), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    high.len() == 8
        && low.len() == 8
        && high.bytes().all(|byte| byte.is_ascii_hexdigit())
        && low.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !index.is_empty()
        && index.len() <= 10
        && index.bytes().all(|byte| byte.is_ascii_digit())
}

fn map_enumerate_error(error: ProducerError) -> InputError {
    match error {
        ProducerError::UnsupportedPlatform | ProducerError::UnsupportedDirectInput => {
            InputError::Unsupported
        }
        // Enumerating the outputs is the desktop-topology read. When the adapter
        // cannot read it, the frozen binding cannot be confirmed as current, and
        // input is not injected on a guess.
        _ => InputError::DesktopUnavailable,
    }
}

/// One `rd_input_event` from `native/windows-input/windows_input.h`, matched
/// field for field.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RdInputEvent {
    struct_size: u32,
    kind: u32,
    flags: u32,
    action: u32,
    button: u32,
    virtual_key: u32,
    scan_code: u32,
    reserved: u32,
    x: i32,
    y: i32,
    data: i32,
    code_unit: i32,
}

/// The ABI the native adapter is compiled against.
const _: () = {
    assert!(std::mem::size_of::<RdInputEvent>() == 48);
    assert!(std::mem::align_of::<RdInputEvent>() == 4);
    assert!(MAX_BATCH_EVENTS == native::MAX_EVENTS as usize);
    assert!(MAX_BATCH_HOLDS == native::MAX_HOLDS as usize);
};

const EVENT_SIZE: u32 = std::mem::size_of::<RdInputEvent>() as u32;

/// One snapshot of the native guard, matched field for field.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RdInputGuardSnapshot {
    struct_size: u32,
    state: u32,
    epoch: u32,
    leases: u32,
    flags: u32,
    unresolved: u32,
}

/// One guarded batch, matched field for field. The arrays it points at live for
/// the duration of the call and are never touched by the guard's callbacks.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RdInputSendRequest {
    struct_size: u32,
    epoch: u32,
    lease: u64,
    transaction: u64,
    events: *const RdInputEvent,
    count: u32,
    reserved: u32,
    episodes: *const u64,
    receipts: *mut u32,
}

/// What one batch did, matched field for field.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RdInputSendResult {
    struct_size: u32,
    inserted: u32,
    submitted: u32,
    epoch: u32,
    guard_state: u32,
    flags: u32,
}

const _: () = {
    assert!(std::mem::size_of::<RdInputGuardSnapshot>() == 24);
    assert!(std::mem::align_of::<RdInputGuardSnapshot>() == 4);
    assert!(std::mem::size_of::<RdInputSendRequest>() == 56);
    assert!(std::mem::align_of::<RdInputSendRequest>() == 8);
    assert!(std::mem::offset_of!(RdInputSendRequest, events) == 24);
    assert!(std::mem::offset_of!(RdInputSendRequest, episodes) == 40);
    assert!(std::mem::offset_of!(RdInputSendRequest, receipts) == 48);
    assert!(std::mem::size_of::<RdInputSendResult>() == 24);
    assert!(std::mem::align_of::<RdInputSendResult>() == 4);
};

const SNAPSHOT_SIZE: u32 = std::mem::size_of::<RdInputGuardSnapshot>() as u32;
const REQUEST_SIZE: u32 = std::mem::size_of::<RdInputSendRequest>() as u32;
const RESULT_SIZE: u32 = std::mem::size_of::<RdInputSendResult>() as u32;

fn empty_snapshot() -> RdInputGuardSnapshot {
    RdInputGuardSnapshot {
        struct_size: SNAPSHOT_SIZE,
        ..Default::default()
    }
}

mod native {
    //! The checked adapter in `native/windows-input/windows_input.cpp`.

    use super::{RdInputGuardSnapshot, RdInputSendRequest, RdInputSendResult};

    pub(super) const OK: i32 = 0;
    pub(super) const INVALID_ARGUMENT: i32 = 1;
    pub(super) const DESKTOP_UNAVAILABLE: i32 = 2;
    pub(super) const INJECTION_FAILED: i32 = 3;
    pub(super) const UNSUPPORTED: i32 = 4;
    pub(super) const GUARD_UNAVAILABLE: i32 = 5;
    pub(super) const RECLAMATION_UNCONFIRMED: i32 = 6;

    pub(super) const MAX_EVENTS: u32 = 4112;
    pub(super) const MAX_HOLDS: u32 = 64;

    pub(super) const DESKTOP_INTERACTIVE: u32 = 1;

    pub(super) const GUARD_ARMED: u32 = 1;

    pub(super) const RECEIPT_UNKNOWN: u32 = 0;
    pub(super) const RECEIPT_PASSED: u32 = 1;
    pub(super) const RECEIPT_SELF_VETOED: u32 = 2;
    pub(super) const RECEIPT_DOWNSTREAM_VETOED: u32 = 3;
    pub(super) const RECEIPT_NOT_SUBMITTED: u32 = 4;
    pub(super) const RECEIPT_NOT_TRACKED: u32 = 5;

    pub(super) const KEY_ADMIT: u32 = 0;
    pub(super) const KEY_HELD_EXTERNAL: u32 = 1;
    pub(super) const KEY_HELD_ENGINE: u32 = 2;
    pub(super) const KEY_HELD_UNKNOWN: u32 = 3;
    pub(super) const KEY_GUARD_UNAVAILABLE: u32 = 4;

    pub(super) const EVENT_MOUSE: u32 = 0;
    pub(super) const EVENT_KEY: u32 = 1;
    pub(super) const EVENT_TEXT: u32 = 2;

    pub(super) const FLAG_UP: u32 = 1;
    pub(super) const FLAG_EXTENDED: u32 = 2;
    pub(super) const FLAG_SCANCODE: u32 = 4;

    pub(super) const MOUSE_MOVE_ABSOLUTE: u32 = 0;
    pub(super) const MOUSE_MOVE_RELATIVE: u32 = 1;
    pub(super) const MOUSE_BUTTON_DOWN: u32 = 2;
    pub(super) const MOUSE_BUTTON_UP: u32 = 3;
    pub(super) const MOUSE_WHEEL: u32 = 4;
    pub(super) const MOUSE_HWHEEL: u32 = 5;

    pub(super) const BUTTON_LEFT: u32 = 0;
    pub(super) const BUTTON_RIGHT: u32 = 1;
    pub(super) const BUTTON_MIDDLE: u32 = 2;
    pub(super) const BUTTON_BACK: u32 = 3;
    pub(super) const BUTTON_FORWARD: u32 = 4;

    unsafe extern "C" {
        pub(super) fn rd_input_desktop_state(kind: *mut u32) -> i32;
        pub(super) fn rd_input_virtual_screen(
            left: *mut i32,
            top: *mut i32,
            width: *mut i32,
            height: *mut i32,
        ) -> i32;
        pub(super) fn rd_input_hold_key(virtual_key: u32, extended: u32) -> u32;
        pub(super) fn rd_input_guard_acquire(
            lease: u64,
            snapshot: *mut RdInputGuardSnapshot,
        ) -> i32;
        pub(super) fn rd_input_guard_release(
            lease: u64,
            snapshot: *mut RdInputGuardSnapshot,
        ) -> i32;
        pub(super) fn rd_input_key_admit(
            epoch: u32,
            lease: u64,
            key: u32,
            verdict: *mut u32,
            snapshot: *mut RdInputGuardSnapshot,
        ) -> i32;
        pub(super) fn rd_input_episode_retire(
            epoch: u32,
            lease: u64,
            episode: u64,
            key: u32,
            snapshot: *mut RdInputGuardSnapshot,
        ) -> i32;
        pub(super) fn rd_input_send(
            request: *const RdInputSendRequest,
            result: *mut RdInputSendResult,
        ) -> i32;
        pub(super) fn rd_input_key_for_character(
            character: u32,
            virtual_key: *mut u32,
            scan_code: *mut u32,
            extended: *mut u32,
            shift_state: *mut u32,
        ) -> i32;
        pub(super) fn rd_input_key_scan(
            virtual_key: u32,
            scan_code: *mut u32,
            extended: *mut u32,
        ) -> i32;
        pub(super) fn rd_input_key_for_scancode(
            scan_code: u32,
            virtual_key: *mut u32,
        ) -> i32;
    }
}

/// Maps one native status to the failure it means here.
///
/// `OK` where a result was required, and any status this build does not know,
/// are failures: neither is ever a success, and neither is mapped to
/// [`InputError::Unsupported`], which a caller may treat as a non-fatal refusal
/// of one event. A guard that cannot be asked is not a guard that said yes.
fn map_status(status: i32) -> InputError {
    match status {
        native::INVALID_ARGUMENT => InputError::InvalidInput,
        native::DESKTOP_UNAVAILABLE => InputError::DesktopUnavailable,
        native::INJECTION_FAILED => InputError::InjectionFailed,
        native::UNSUPPORTED => InputError::Unsupported,
        native::GUARD_UNAVAILABLE => InputError::InjectionFailed,
        native::RECLAMATION_UNCONFIRMED => InputError::ReclamationUnconfirmed,
        _ => InputError::InjectionFailed,
    }
}

/// The fate one receipt reports, as this build reads it.
///
/// The adapter reports one of a fixed set of values; a value outside that set is
/// a reply this build cannot make sense of, and is never read as a release or a
/// confirmed hold.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Receipt {
    /// No terminal receipt was observed: the event may or may not have been
    /// delivered.
    Unknown,
    /// The event passed this guard and the rest of the hook chain.
    Passed,
    /// Refused by this guard.
    SelfVetoed,
    /// A hook later in the chain refused it.
    DownstreamVetoed,
    /// The event never reached `SendInput`.
    NotSubmitted,
    /// The event carries no ownership decision at all.
    NotTracked,
}

impl Receipt {
    fn of(value: u32) -> Option<Self> {
        Some(match value {
            native::RECEIPT_UNKNOWN => Self::Unknown,
            native::RECEIPT_PASSED => Self::Passed,
            native::RECEIPT_SELF_VETOED => Self::SelfVetoed,
            native::RECEIPT_DOWNSTREAM_VETOED => Self::DownstreamVetoed,
            native::RECEIPT_NOT_SUBMITTED => Self::NotSubmitted,
            native::RECEIPT_NOT_TRACKED => Self::NotTracked,
            _ => return None,
        })
    }
}

fn desktop_is_interactive() -> Result<(), InputError> {
    let mut kind = 0u32;
    let status = unsafe { native::rd_input_desktop_state(&mut kind) };
    if status != native::OK {
        return Err(map_status(status));
    }
    if kind != native::DESKTOP_INTERACTIVE {
        return Err(InputError::DesktopUnavailable);
    }
    Ok(())
}

fn virtual_screen() -> Result<Screen, InputError> {
    let (mut left, mut top, mut width, mut height) = (0i32, 0i32, 0i32, 0i32);
    let status =
        unsafe { native::rd_input_virtual_screen(&mut left, &mut top, &mut width, &mut height) };
    if status != native::OK {
        return Err(map_status(status));
    }
    Ok(Screen {
        left,
        top,
        width,
        height,
    })
}

/// The canonical hold identity of one key or mouse button: 0 for an event that
/// holds nothing, otherwise the virtual key with its E0 form folded in as 0x100
/// and the left/right modifier families folded to their generic virtual key.
///
/// The rule lives in the adapter so this table and the guard cannot disagree
/// about which events touch the same key; a key or button this function gives 0
/// for is not a hold and is never arbitrated.
fn hold_key(virtual_key: u32, extended: bool) -> Result<u32, InputError> {
    let key = unsafe { native::rd_input_hold_key(virtual_key, u32::from(extended)) };
    if key == 0 || key as usize >= MAX_HOLD_KEYS {
        return Err(InputError::Unsupported);
    }
    Ok(key)
}

fn slot_for(key: u32) -> Result<usize, InputError> {
    let slot = key as usize;
    if key == 0 || slot >= MAX_HOLD_KEYS {
        return Err(InputError::InvalidInput);
    }
    Ok(slot)
}

/// Takes one guard lease, or fails. The lease is what keeps the guard's message
/// thread, hooks, descriptors and observed key state alive, so a caller only
/// gives it back through [`release_guard`] and only when its own holds are
/// resolved.
fn acquire_guard(lease: u64, registry: &mut Arbitration) -> Result<u32, InputError> {
    let mut snapshot = empty_snapshot();
    let status = unsafe { native::rd_input_guard_acquire(lease, &mut snapshot) };
    if status != native::OK || snapshot.state != native::GUARD_ARMED || snapshot.epoch == 0 {
        // A reply that is not an armed epoch is never a lease this module may
        // plan under. If the adapter nevertheless reports the acquire as done, the
        // lease it took is handed straight back: a guard whose state cannot be
        // vouched for must not be left holding a lease nobody owns.
        if status == native::OK && !release_guard(lease) {
            registry.activity.snapshot.uncertain = true;
        }
        let error = map_status(status);
        if error == InputError::ReclamationUnconfirmed {
            registry.activity.snapshot.uncertain = true;
        }
        return Err(error);
    }
    Ok(snapshot.epoch)
}

/// Gives one guard lease back. `false` says the guard could not reach a stopped
/// state although nothing else was holding it, which is not a clean stop.
fn release_guard(lease: u64) -> bool {
    let mut snapshot = empty_snapshot();
    unsafe { native::rd_input_guard_release(lease, &mut snapshot) == native::OK }
}

/// Whether the guard may admit a new episode for `key` under `epoch`.
fn admit_hold(epoch: u32, lease: u64, key: u32) -> Result<u32, InputError> {
    let mut verdict = 0u32;
    let mut snapshot = empty_snapshot();
    let status =
        unsafe { native::rd_input_key_admit(epoch, lease, key, &mut verdict, &mut snapshot) };
    if status != native::OK {
        return Err(map_status(status));
    }
    Ok(verdict)
}

/// Asks the guard to retire one episode of one key by evidence alone. It sends
/// nothing and lifts nothing; `true` means the episode is resolved.
fn retire_episode(epoch: u32, lease: u64, episode: u64, key: u32) -> bool {
    let mut snapshot = empty_snapshot();
    unsafe {
        native::rd_input_episode_retire(epoch, lease, episode, key, &mut snapshot) == native::OK
    }
}

fn key_scan(virtual_key: u32) -> Result<(u32, bool), InputError> {
    let (mut scan_code, mut extended) = (0u32, 0u32);
    let status = unsafe { native::rd_input_key_scan(virtual_key, &mut scan_code, &mut extended) };
    if status != native::OK {
        return Err(map_status(status));
    }
    Ok((scan_code, extended != 0))
}

/// The pinned receiver uses `chr` as a target Windows scan and `down` as its
/// transition. The pinned sender excludes non-E0 multi-byte scans and sends
/// Pause as a genuine Legacy control key. No truncation, text interpretation,
/// global modifier repair or alternate injector is part of this adaptation.
fn decode_windows_map(event: &KeyEvent) -> Result<u32, InputError> {
    if event.press {
        return Err(InputError::InvalidInput);
    }
    let Some(key_event::Union::Chr(scan_code)) = &event.union else {
        return Err(InputError::InvalidInput);
    };
    if scan_code & 0xff == 0 || (*scan_code > 0xff && scan_code >> 8 != 0xe0) {
        return Err(InputError::InvalidInput);
    }
    Ok(*scan_code)
}

fn map_key_encoding(scan_code: u32) -> Result<Encoding, InputError> {
    let mut virtual_key = 0u32;
    let status = unsafe { native::rd_input_key_for_scancode(scan_code, &mut virtual_key) };
    if status != native::OK {
        return Err(map_status(status));
    }
    // This is a read-only Windows layout query, never a handwritten VK table.
    hold_key(virtual_key, scan_code >> 8 == 0xe0)?;
    Ok(Encoding::Key {
        virtual_key,
        scan_code,
        extended: scan_code >> 8 == 0xe0,
        scan_code_mode: true,
    })
}

/// What one legacy character code means in the foreground window's layout.
struct CharacterKey {
    virtual_key: u32,
    scan_code: u32,
    extended: bool,
    /// The layout's own requirement, not the client's modifier state.
    shift: bool,
    control: bool,
    alt: bool,
}

fn character_key(character: u32) -> Result<CharacterKey, InputError> {
    if character == 0 || (0xd800..=0xdfff).contains(&character) {
        // `chr` is a character; a NUL or a lone surrogate is not one.
        return Err(InputError::InvalidInput);
    }
    if character > 0xffff {
        // The legacy character field is one UTF-16 code unit, which is what a
        // keyboard layout is asked about; a character above the BMP is text and
        // belongs to the `unicode`/`seq` forms, not to this one.
        return Err(InputError::Unsupported);
    }
    let (mut virtual_key, mut scan_code, mut extended, mut shift_state) = (0u32, 0u32, 0u32, 0u32);
    let status = unsafe {
        native::rd_input_key_for_character(
            character,
            &mut virtual_key,
            &mut scan_code,
            &mut extended,
            &mut shift_state,
        )
    };
    if status != native::OK {
        return Err(map_status(status));
    }
    if virtual_key == 0 {
        return Err(InputError::Unsupported);
    }
    Ok(CharacterKey {
        virtual_key,
        scan_code,
        extended: extended != 0,
        shift: shift_state & 0x01 != 0,
        control: shift_state & 0x02 != 0,
        alt: shift_state & 0x04 != 0,
    })
}

/// The virtual-screen rectangle `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK`
/// normalizes against.
struct Screen {
    left: i32,
    top: i32,
    width: i32,
    height: i32,
}

/// Normalizes one virtual-desktop coordinate into the 0..65535 the absolute
/// mouse flag takes, with the last pixel of the virtual screen as the 65535
/// endpoint.
fn normalize(desktop: i32, origin: i32, extent: i32) -> Result<i32, InputError> {
    if extent < 1 {
        return Err(InputError::DesktopUnavailable);
    }
    let last = extent - 1;
    if last == 0 {
        // A one-pixel virtual screen has exactly one point, and it is 0.
        return if desktop == origin {
            Ok(0)
        } else {
            Err(InputError::OutputChanged)
        };
    }
    let offset = desktop
        .checked_sub(origin)
        .ok_or(InputError::InvalidInput)?;
    if offset < 0 || offset > last {
        // The frozen display no longer lies inside the virtual screen: the
        // topology changed under the binding.
        return Err(InputError::OutputChanged);
    }
    let numerator = i64::from(offset) * 65535 + i64::from(last) / 2;
    let scaled = numerator / i64::from(last);
    Ok(i32::try_from(scaled.clamp(0, 65535)).unwrap_or(65535))
}

/// How sure the engine is that one hold reached the system.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Certainty {
    /// The guard observed the down pass its gate: this lease holds the key.
    Confirmed,
    /// The down may have reached the system - a partial batch, a hook chain that
    /// vetoed it, a receipt that never arrived. It blocks the key for every
    /// lease, and it is never treated as a release.
    MayDown,
}

/// The exact encoding a release has to repeat: the encoding of the down that was
/// really injected, kept in the record so a layout change, a different Enter or a
/// different modifier side cannot move it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Key {
        virtual_key: u32,
        scan_code: u32,
        extended: bool,
        /// True only for Map: `scan_code` is also the complete frozen wire-code
        /// association, including E0. The VK is guard identity, not injection.
        scan_code_mode: bool,
    },
    Button(u32),
}

/// One key or button one lease injected down and has not released.
#[derive(Clone, Copy)]
struct HoldRecord {
    session: u64,
    /// The guard episode this hold belongs to, never reused.
    episode: u64,
    /// The guard epoch the episode was created under. Evidence for retiring it
    /// only counts within that epoch.
    epoch: u32,
    certainty: Certainty,
    /// A release attempt was refused or left unresolved. From here the hold is
    /// resolved by the guard's evidence, never by sending another up.
    retained: bool,
    encoding: Encoding,
}

/// Minimal all-peer evidence for the host owner. These are Unix wall-clock
/// milliseconds for the official Dart guards, not key/coordinate content.
/// `uncertain` must be checked even when local policy permits remote CM access.
#[derive(Clone, Copy)]
pub(crate) struct RemoteActivitySnapshot {
    pub sequence: u64,
    pub click_wall_ms: u64,
    pub mouse_wall_ms: u64,
    pub uncertain: bool,
}

/// Protected by the same lock held across every native batch and receipt
/// commit. A snapshot cannot race an in-flight send or observe another peer's
/// batch as if it had not happened. A fresh process's empty history means no
/// submission, not a fallback value for a failed query.
struct RemoteActivity {
    snapshot: RemoteActivitySnapshot,
    last_submission: Option<Instant>,
}

impl RemoteActivity {
    const fn new() -> Self {
        Self {
            snapshot: RemoteActivitySnapshot {
                sequence: 0,
                click_wall_ms: 0,
                mouse_wall_ms: 0,
                uncertain: false,
            },
            last_submission: None,
        }
    }

    /// Called only at the native submission/receipt boundary, before any early
    /// return for a partial or contradictory result. A later successful peer's
    /// batch never clears a prior unknown submission or its real timestamps.
    fn observe(&mut self, batch: &Batch, epoch: u32, status: i32, result: &RdInputSendResult) {
        if status == native::RECLAMATION_UNCONFIRMED {
            self.snapshot.uncertain = true;
        }
        let count = batch.events.len() as u32;
        let known_status = matches!(status,
            native::OK | native::INVALID_ARGUMENT | native::DESKTOP_UNAVAILABLE
                | native::INJECTION_FAILED | native::UNSUPPORTED
                | native::GUARD_UNAVAILABLE | native::RECLAMATION_UNCONFIRMED);
        let zero_submission = result.struct_size == RESULT_SIZE
            && known_status && status != native::OK
            && result.submitted == 0 && result.inserted == 0
            && batch.episodes.iter().zip(&batch.receipts).all(|(episode, receipt)| {
                *receipt == if *episode == 0 {
                    native::RECEIPT_NOT_TRACKED
                } else {
                    native::RECEIPT_NOT_SUBMITTED
                }
            });
        if zero_submission {
            // No submission time or sequence is invented. An explicit native
            // reclamation failure above still closes the sensitive-action gate.
            return;
        }
        let terminal_receipts = batch.episodes.iter().zip(&batch.receipts).all(|(episode, receipt)| {
            if *episode == 0 {
                *receipt == native::RECEIPT_NOT_TRACKED
            } else {
                matches!(*receipt, native::RECEIPT_PASSED | native::RECEIPT_SELF_VETOED
                    | native::RECEIPT_DOWNSTREAM_VETOED)
            }
        });
        let confirmed_batch = result.struct_size == RESULT_SIZE
            && result.epoch == epoch && status == native::OK
            && result.guard_state == native::GUARD_ARMED
            && result.submitted == count && result.inserted == count
            && terminal_receipts;
        self.snapshot.uncertain |= !confirmed_batch;
        match self.snapshot.sequence.checked_add(1) {
            Some(sequence) => self.snapshot.sequence = sequence,
            None => self.snapshot.uncertain = true,
        }
        // A submitted batch (even one vetoed in the hook chain), or an unknown
        // result, closes the monotonic gate. No elapsed wall clock can open it.
        self.last_submission = Some(Instant::now());

        let mut click = false;
        let mut mouse = false;
        for (event, receipt) in batch.events.iter().zip(&batch.receipts) {
            let observed = *receipt == native::RECEIPT_PASSED;
            // Non-hold events have no per-event receipt. A positive insertion
            // count is submission evidence, never a claim about which prefix
            // was inserted; any short/unknown batch remains uncertain above.
            let untracked = *receipt == native::RECEIPT_NOT_TRACKED
                && result.submitted != 0 && result.inserted != 0;
            let unconfirmed = result.submitted != 0
                && (*receipt == native::RECEIPT_UNKNOWN || Receipt::of(*receipt).is_none());
            if !observed && !untracked && !unconfirmed {
                continue;
            }
            match event.kind {
                native::EVENT_MOUSE => {
                    if event.action == native::MOUSE_BUTTON_UP && event.button == native::BUTTON_LEFT {
                        click = true;
                    } else {
                        mouse = true;
                    }
                }
                native::EVENT_KEY => {
                    // The frozen native VK classifies both real Map and Legacy
                    // Enter, including numpad Enter and both directions.
                    click |= event.virtual_key == VK_RETURN;
                    mouse = true;
                }
                native::EVENT_TEXT => mouse = true,
                _ => self.snapshot.uncertain = true,
            }
        }
        if !click && !mouse {
            return;
        }
        let wall_ms = SystemTime::now().duration_since(UNIX_EPOCH).ok()
            .and_then(|time| u64::try_from(time.as_millis()).ok());
        let Some(wall_ms) = wall_ms else {
            self.snapshot.uncertain = true;
            return;
        };
        if click {
            self.snapshot.click_wall_ms = self.snapshot.click_wall_ms.max(wall_ms);
        }
        if mouse {
            self.snapshot.mouse_wall_ms = self.snapshot.mouse_wall_ms.max(wall_ms);
        }
    }
}

/// One process-wide table of what each engine lease injected down and has not
/// released, indexed by canonical hold key. Mouse buttons live in the Win32
/// virtual-key space (`VK_LBUTTON` 0x01 through `VK_XBUTTON2` 0x06), which no
/// keyboard key uses, so one table covers keys and buttons.
struct Arbitration {
    holds: [Option<HoldRecord>; MAX_HOLD_KEYS],
    next_session: u64,
    next_episode: u64,
    next_transaction: u64,
    activity: RemoteActivity,
}

impl Arbitration {
    const fn new() -> Self {
        Self {
            holds: [None; MAX_HOLD_KEYS],
            next_session: 0,
            next_episode: 0,
            next_transaction: 0,
            activity: RemoteActivity::new(),
        }
    }

    /// A lease id, an episode id or a transaction id that is never reused. An id
    /// that would have to repeat is refused instead, so a record left behind by a
    /// lease that could not release can never be mistaken for a live one.
    fn take(counter: &mut u64, uncertain: &mut bool) -> Result<u64, InputError> {
        let Some(id) = counter.checked_add(1) else {
            *uncertain = true;
            return Err(InputError::ReclamationUnconfirmed);
        };
        *counter = id;
        Ok(id)
    }

    fn open_session(&mut self) -> Result<u64, InputError> {
        Self::take(&mut self.next_session, &mut self.activity.snapshot.uncertain)
    }

    fn open_episode(&mut self) -> Result<u64, InputError> {
        Self::take(&mut self.next_episode, &mut self.activity.snapshot.uncertain)
    }

    fn open_transaction(&mut self) -> Result<u64, InputError> {
        Self::take(&mut self.next_transaction, &mut self.activity.snapshot.uncertain)
    }

    /// The record on one key, whoever owns it.
    fn holding(&self, slot: usize) -> Option<&HoldRecord> {
        self.holds[slot].as_ref()
    }

    /// The record on one key, when it is this lease's own.
    fn mine(&self, slot: usize, session: u64) -> Option<&HoldRecord> {
        match &self.holds[slot] {
            Some(record) if record.session == session => Some(record),
            _ => None,
        }
    }

    /// The single held ledger also owns the Map wire association. Search across
    /// peers so a layout change cannot let another peer claim the same physical
    /// scan under a new VK. No separate Map held-owner table is created.
    fn map_slot(&self, wire_scan: u32) -> Option<usize> {
        self.holds.iter().position(|record| {
            matches!(
                record,
                Some(HoldRecord {
                    encoding: Encoding::Key { scan_code, scan_code_mode: true, .. },
                    ..
                }) if *scan_code == wire_scan
            )
        })
    }

    fn claim(&mut self, slot: usize, record: HoldRecord) {
        if record.retained || record.certainty != Certainty::Confirmed {
            // Retirement can end this episode, not erase the process's history
            // of unconfirmed ownership. Only the uncertainty bit changes here.
            self.activity.snapshot.uncertain = true;
        }
        self.holds[slot] = Some(record);
    }

    /// Clears the record only when it is this lease's own, so a stale release
    /// can never take another lease's hold away.
    fn relinquish(&mut self, slot: usize, session: u64) {
        if self.mine(slot, session).is_some() {
            self.holds[slot] = None;
        }
    }

    fn retain(&mut self, slot: usize, session: u64) {
        if let Some(record) = self.holds[slot].as_mut() {
            if record.session == session {
                record.retained = true;
                self.activity.snapshot.uncertain = true;
            }
        }
    }
}

static ARBITRATION: Mutex<Arbitration> = Mutex::new(Arbitration::new());

fn lock_arbitration() -> MutexGuard<'static, Arbitration> {
    ARBITRATION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Whether the ownership table was left poisoned by a panic while a plan, a send
/// or a commit was in progress. The records a release needs are still there, but
/// nothing new is injected through a table whose state is in doubt.
fn arbitration_poisoned() -> bool {
    ARBITRATION.is_poisoned()
}

fn activity_uncertain(registry: &Arbitration) -> bool {
    // Uncertain ownership is latched at claim/retain, not inferred from the
    // current table: successful retirement must never reopen this gate.
    arbitration_poisoned() || registry.activity.snapshot.uncertain
}

pub(crate) fn remote_activity_snapshot() -> RemoteActivitySnapshot {
    let registry = lock_arbitration();
    let mut snapshot = registry.activity.snapshot;
    snapshot.uncertain = activity_uncertain(&registry);
    snapshot
}

/// The owner rechecks this at its sensitive-command boundary. This is the
/// official 120ms time policy, not proof of a hardware-local user identity.
/// Unknown submissions/reclamation latch closed for this process; a clean
/// later batch or a peer disconnect cannot erase them.
pub(crate) fn remote_input_allows_sensitive_action() -> bool {
    let registry = lock_arbitration();
    if activity_uncertain(&registry) {
        return false;
    }
    registry.activity.last_submission.is_none_or(|last| {
        Instant::now().checked_duration_since(last)
            .is_some_and(|elapsed| elapsed > Duration::from_millis(120))
    })
}

/// What one hold event of the batch does to the record it names.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Effect {
    /// A down of a fresh episode: only a receipt that passed claims the record.
    Claim,
    /// A down repeating an episode this lease already holds. It changes nothing:
    /// the record keeps its episode, its encoding, its certainty and its
    /// collision history, and only its own release can end it.
    Repeat,
    /// A release of an episode this lease owns: only a receipt that passed
    /// relinquishes the record.
    Release,
}

/// One hold event of the batch, in event order, with the ownership decision it
/// carries.
struct Hold {
    /// Index of the event in the batch.
    event: u32,
    /// The canonical hold key, which is also this record's index in the table.
    slot: usize,
    episode: u64,
    /// The encoding the event uses: the one a claim records, and the one a
    /// repeat has to match. A release carries the encoding of the down it
    /// releases.
    encoding: Option<Encoding>,
    effect: Effect,
}

/// What the table and the guard say about one down.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DownPlan {
    /// Nothing holds the key: press it with a fresh episode.
    Claim,
    /// This lease already holds the key with a live episode: the down repeats
    /// that episode, and nothing is claimed or released by it.
    Repeat { episode: u64, encoding: Encoding },
    /// Nothing is injected: a hold this engine did not inject is on the key, so
    /// it is left alone and never claimed.
    Skip,
}

/// Whether the guard may admit a fresh episode on a key that is this lease's to
/// claim.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// The key is clear: press it with a fresh episode.
    Claim,
    /// A hold this engine did not inject is on the key: leave it alone.
    Skip,
}

/// What this lease's own table says about the key one event names.
enum OwnHold {
    /// A confirmed, unretained hold that this event may repeat or release.
    Live(HoldRecord),
    /// This lease had a record on the key and it was in doubt: evidence has just
    /// retired it, which claims nothing, lifts nothing and sends nothing. The
    /// doubted episode is gone and the key is free again, but nothing of that
    /// episode is ever reused.
    Retired,
    /// This lease has no record on the key.
    None,
}

/// The reusable batch one request builds before it is injected.
#[derive(Default)]
struct Batch {
    events: Vec<RdInputEvent>,
    /// One episode per event: the never-reused episode a hold event belongs to,
    /// or 0 for an event that holds nothing.
    episodes: Vec<u64>,
    holds: Vec<Hold>,
    /// One receipt per event, written by the adapter.
    receipts: Vec<u32>,
}

impl Batch {
    fn clear(&mut self) {
        self.events.clear();
        self.episodes.clear();
        self.holds.clear();
        self.receipts.clear();
    }

    fn push(&mut self, event: RdInputEvent, episode: u64) {
        self.events.push(event);
        self.episodes.push(episode);
    }
}

/// One peer's lease on the local desktop: the frozen binding it was opened for,
/// its never-reused session id, the guard lease observing for it, and the batch
/// it reuses.
pub(crate) struct InputSession {
    binding: TargetBinding,
    session: u64,
    batch: Batch,
    /// The guard epoch this lease observes under. `None` means the lease was
    /// given back: a reusable session acquires again before its next input.
    guard: Option<u32>,
    /// A checked release that did not reach a stopped guard. This lease keeps
    /// the epoch and the obligation: it never injects again, and every later
    /// release retries the stop instead of reporting a clean one.
    stop_pending: bool,
    /// Set by a known fault, a contradiction in the guard's answers or a lost
    /// epoch. This lease never injects again; its records stay owned and are
    /// resolved by evidence.
    faulted: bool,
    /// Trackpad remainder, in eighth-notches, kept until it makes a whole notch.
    trackpad_horizontal: i32,
    trackpad_vertical: i32,
}

impl InputSession {
    /// Opens a lease on `binding`.
    ///
    /// This verifies the ordinary interactive input desktop, the adapter and the
    /// binding itself, takes the observation guard's lease for this session and
    /// performs no injection and no other OS state change, so it is a usable
    /// availability check for a host starting with input enabled. A guard that
    /// cannot be armed fails the open: there is no unmonitored injection path.
    ///
    /// The guard's lifecycle is serialized with every other lease through the
    /// same process-wide table as planning and injecting, because a guard that is
    /// being stopped must not be able to race one that is being armed. It is
    /// normally a few milliseconds; only a failing installation makes it visible.
    pub(crate) fn open(binding: TargetBinding) -> Result<Self, InputError> {
        desktop_is_interactive()?;
        binding.verify_current()?;
        let mut registry = lock_arbitration();
        let session = registry.open_session()?;
        let guard = acquire_guard(session, &mut registry)?;
        Ok(Self {
            binding,
            session,
            batch: Batch::default(),
            guard: Some(guard),
            stop_pending: false,
            faulted: false,
            trackpad_horizontal: 0,
            trackpad_vertical: 0,
        })
    }

    /// Injects one wire pointer event.
    pub(crate) fn mouse(&mut self, event: &MouseEvent) -> Result<(), InputError> {
        // Decode and validate before touching the desktop: a malformed event
        // never becomes a batch and never costs a topology read.
        let mask = u32::try_from(event.mask).map_err(|_| InputError::InvalidInput)?;
        if mask & !MASK_KNOWN != 0 {
            return Err(InputError::InvalidInput);
        }
        let kind = mask & MASK_KIND;
        let buttons = (mask >> MASK_BUTTON_SHIFT) & 0x1f;
        match kind {
            KIND_MOVE => self.prepare_move_absolute(event.x, event.y),
            KIND_BUTTON_DOWN | KIND_BUTTON_UP => {
                self.prepare_button(kind == KIND_BUTTON_DOWN, buttons, event.x, event.y)
            }
            KIND_WHEEL | KIND_TRACKPAD | KIND_MOVE_RELATIVE => {
                // These three carry deltas or a marker in x and y, so a button
                // field on them is not an established event.
                if buttons != 0 {
                    return Err(InputError::InvalidInput);
                }
                match kind {
                    KIND_WHEEL => self.prepare_wheel(event.x, event.y),
                    KIND_TRACKPAD => self.prepare_trackpad(event.x, event.y),
                    _ => self.prepare_move_relative(event.x, event.y),
                }
            }
            _ => Err(InputError::InvalidInput),
        }
    }

    /// Injects one wire keyboard event.
    pub(crate) fn key(&mut self, event: &KeyEvent) -> Result<(), InputError> {
        let mode = event
            .mode
            .enum_value()
            .map_err(|_| InputError::Unsupported)?;
        if mode == KeyboardMode::Map {
            return self.prepare_map_key(event);
        }
        if mode != KeyboardMode::Legacy {
            return Err(InputError::Unsupported);
        }
        if event.press && event.down {
            // A click and a hold at once is not a state the wire defines.
            return Err(InputError::InvalidInput);
        }
        let direction = if event.press {
            Direction::Click
        } else if event.down {
            Direction::Down
        } else {
            Direction::Up
        };
        self.prepare_key(event, direction)
    }

    /// Releases every key and button this lease still owns, and reports whether
    /// that is confirmed.
    ///
    /// The binding is deliberately not re-verified here: a display change must
    /// not be able to block the release of keys and buttons, which carry no
    /// coordinates. Every release goes through the same guarded gate as ordinary
    /// input, carrying the episode of the down it releases and that down's own
    /// encoding; a hold the guard has already refused, or one whose confirmed
    /// state is gone, is resolved by [`retire_episode`] instead, which sends
    /// nothing. The guard tracks a bounded number of holds per batch, so a lease
    /// holding more keys than one batch carries is released over several batches,
    /// each one's receipts applied before the next is planned.
    /// `Err(ReclamationUnconfirmed)` means this lease is still responsible for
    /// something - a hold that stays owned, or a guard lease whose stop was not
    /// confirmed - and its record and guard stay alive so a later call can try
    /// again.
    ///
    /// Calling this twice is safe, and releasing a lease that holds nothing still
    /// gives the guard lease back, which is what stops the message thread when
    /// the last clean lease leaves. It is not safe to treat a call that answered
    /// `Err` as done: the next call retries the same stop.
    pub(crate) fn release_all(&mut self) -> Result<(), InputError> {
        self.batch.clear();
        let outcome = self.release_all_locked();
        self.batch.clear();
        outcome
    }

    fn release_all_locked(&mut self) -> Result<(), InputError> {
        let session = self.session;
        let mut registry = lock_arbitration();

        // 1. Guarded ups for the holds that are still confirmed, in as many
        //    bounded batches as that takes. Nothing is injected while the guard
        //    cannot observe, and a lease with nothing owned never re-arms it.
        let mut owned = false;
        for slot in 1..MAX_HOLD_KEYS {
            if registry.mine(slot, session).is_some() {
                owned = true;
                break;
            }
        }
        if owned && !self.faulted && !arbitration_poisoned() {
            if self.guard.is_none() {
                if let Ok(epoch) = acquire_guard(session, &mut registry) {
                    self.guard = Some(epoch);
                }
            }
            if let Some(epoch) = self.guard {
                if desktop_is_interactive().is_ok() {
                    while !self.faulted && !arbitration_poisoned() {
                        let mut planned = 0usize;
                        for slot in 1..MAX_HOLD_KEYS {
                            if planned == MAX_BATCH_HOLDS {
                                break;
                            }
                            let Some(record) = registry.mine(slot, session) else {
                                continue;
                            };
                            if record.retained || record.certainty != Certainty::Confirmed {
                                // A hold in doubt is never released by sending
                                // another up; it is left to the evidence pass
                                // below.
                                continue;
                            }
                            let (episode, encoding) = (record.episode, record.encoding);
                            // The release repeats the encoding of the down that
                            // was really injected, never a fresh one.
                            self.push_release(slot, encoding, episode);
                            planned += 1;
                        }
                        if planned == 0 {
                            break;
                        }
                        // The receipts decide what happened; a refused up keeps
                        // the record and is not a batch failure. Every record
                        // this batch named is either released or left retained
                        // and out of the next batch, so this loop ends.
                        let _ = self.flush(&mut registry, epoch);
                        self.batch.clear();
                    }
                }
            }
        }

        // 2. Everything still owned is resolved by evidence alone.
        for slot in 1..MAX_HOLD_KEYS {
            let Some(record) = registry.mine(slot, session) else {
                continue;
            };
            let (epoch, episode, key) = (record.epoch, record.episode, slot as u32);
            if retire_episode(epoch, session, episode, key) {
                registry.relinquish(slot, session);
            } else {
                registry.retain(slot, session);
            }
        }

        // 3. Report, and give the guard lease back only when nothing of this
        //    lease's is left unresolved. A lease kept here is the quarantine:
        //    the guard stays installed, so a late own event is still refused
        //    instead of being passed as third-party input.
        let mut unresolved = false;
        for slot in 1..MAX_HOLD_KEYS {
            if registry.mine(slot, session).is_some() {
                unresolved = true;
                break;
            }
        }
        if unresolved {
            registry.activity.snapshot.uncertain = true;
            return Err(InputError::ReclamationUnconfirmed);
        }
        if self.guard.is_some() {
            // The holds are resolved, but the lease is only consumed once the
            // guard confirmed that it stopped. A stop that did not get there -
            // hooks or the message thread still present - keeps this session's
            // obligation, so the next call retries it instead of reporting a
            // clean release nothing confirmed.
            if !release_guard(session) {
                self.stop_pending = true;
                registry.activity.snapshot.uncertain = true;
                return Err(InputError::ReclamationUnconfirmed);
            }
            self.guard = None;
            self.stop_pending = false;
        }
        Ok(())
    }

    /// Requires the ordinary interactive desktop, the bound output and a guard
    /// lease observing for this session.
    fn ensure_ready(&mut self) -> Result<u32, InputError> {
        desktop_is_interactive()?;
        self.binding.verify_current()?;
        if arbitration_poisoned() {
            return Err(InputError::ReclamationUnconfirmed);
        }
        self.ensure_guard()
    }

    /// The guard epoch to plan under, taking the lease again if it was given
    /// back. A faulted session never acquires: its continuity is gone, and so
    /// does a session whose checked release is not confirmed yet.
    fn ensure_guard(&mut self) -> Result<u32, InputError> {
        if self.stop_pending {
            // A release was asked for and the guard has not confirmed stopping:
            // this lease never injects again, and a later release keeps retrying
            // the same stop.
            return Err(InputError::ReclamationUnconfirmed);
        }
        if let Some(epoch) = self.guard {
            return Ok(epoch);
        }
        if self.faulted {
            return Err(InputError::InjectionFailed);
        }
        // Arming is a lifecycle step exactly like starting, stopping and
        // injecting, so it runs inside the same process-wide serialization: a
        // guard being stopped with the last other lease cannot race one being
        // armed here, which would leave a lease on a guard that is going away.
        let mut registry = lock_arbitration();
        let epoch = acquire_guard(self.session, &mut registry)?;
        self.guard = Some(epoch);
        Ok(epoch)
    }

    /// This lease's own record on `key`, read for one event.
    ///
    /// A record in doubt is never handed out and is never claimed, repeated or
    /// released: it is first retired by evidence alone, which sends nothing and
    /// lifts nothing, and only a retirement that succeeds resolves it. A doubt
    /// that cannot be resolved is an error, and the record stays owned. Another
    /// lease's hold on the key is a conflict, never a shared hold, and is
    /// reported before anything is injected.
    fn own_hold(
        &self,
        registry: &mut Arbitration,
        slot: usize,
        key: u32,
    ) -> Result<OwnHold, InputError> {
        match registry.holding(slot) {
            Some(record) if record.session == self.session => {
                if record.certainty == Certainty::Confirmed && !record.retained {
                    return Ok(OwnHold::Live(*record));
                }
                let (record_epoch, episode) = (record.epoch, record.episode);
                if !retire_episode(record_epoch, self.session, episode, key) {
                    registry.retain(slot, self.session);
                    return Err(InputError::ReclamationUnconfirmed);
                }
                registry.relinquish(slot, self.session);
                Ok(OwnHold::Retired)
            }
            Some(_) => Err(InputError::InjectionFailed),
            None => Ok(OwnHold::None),
        }
    }

    /// What one down on `key` has to do, asking the guard when the table holds no
    /// record.
    ///
    /// A key this lease already holds is never re-claimed and never released by a
    /// down: the down repeats the episode this lease is holding, with the encoding
    /// its own down used, and the record is left exactly as it is. A record in
    /// doubt is never repeated and never re-confirmed either; since a down carries
    /// no release of its own, it may press the key again only as a fresh episode,
    /// and only once the evidence has cleared the doubt.
    ///
    /// `Skip` means nothing is injected: a hold this engine did not inject is on
    /// the key, so it is left alone and never claimed. A rejected down - another
    /// lease's hold, or an unresolved doubt - is an error before anything is
    /// injected.
    fn plan_down(
        &mut self,
        registry: &mut Arbitration,
        epoch: u32,
        slot: usize,
        key: u32,
    ) -> Result<DownPlan, InputError> {
        match self.own_hold(registry, slot, key)? {
            OwnHold::Live(record) => Ok(DownPlan::Repeat {
                episode: record.episode,
                encoding: record.encoding,
            }),
            OwnHold::None | OwnHold::Retired => match self.admit(registry, epoch, key)? {
                Admission::Claim => Ok(DownPlan::Claim),
                Admission::Skip => Ok(DownPlan::Skip),
            },
        }
    }

    /// The release this lease's own record on `key` calls for, if it calls for
    /// one.
    ///
    /// A record in doubt releases nothing: it is retired by evidence instead,
    /// which is what [`Self::own_hold`] does and sends nothing. A key this lease
    /// does not hold releases nothing either, so an up for a key this engine never
    /// injected is not sent and cannot clear anyone's record.
    fn plan_up(
        &mut self,
        registry: &mut Arbitration,
        slot: usize,
        key: u32,
    ) -> Result<Option<(u64, Encoding)>, InputError> {
        match self.own_hold(registry, slot, key)? {
            OwnHold::Live(record) => Ok(Some((record.episode, record.encoding))),
            OwnHold::Retired | OwnHold::None => Ok(None),
        }
    }

    /// Whether the guard may admit a fresh episode for a free `key`.
    fn admit(&mut self, registry: &mut Arbitration, epoch: u32, key: u32) -> Result<Admission, InputError> {
        match admit_hold(epoch, self.session, key) {
            Ok(native::KEY_ADMIT) => Ok(Admission::Claim),
            // A hold that is not a lease's own: the down is not injected and
            // not recorded, so the hold stays untouched.
            Ok(native::KEY_HELD_EXTERNAL) => Ok(Admission::Skip),
            // Another engine episode holds it: a conflict, never a shared
            // hold, reported before anything is injected.
            Ok(native::KEY_HELD_ENGINE) => Err(InputError::InjectionFailed),
            // The guard cannot say the key is clear. Claiming it could mean
            // lifting something it does not own, so it is left alone.
            Ok(native::KEY_HELD_UNKNOWN) => {
                registry.activity.snapshot.uncertain = true;
                Err(InputError::ReclamationUnconfirmed)
            }
            Ok(native::KEY_GUARD_UNAVAILABLE) => Err(InputError::InjectionFailed),
            // Any verdict this build does not know is never a licence to
            // claim a key.
            Ok(_) => Err(InputError::InjectionFailed),
            Err(error) => {
                if error == InputError::ReclamationUnconfirmed {
                    registry.activity.snapshot.uncertain = true;
                }
                self.faulted = true;
                Err(error)
            }
        }
    }

    /// Runs one request with the reusable batch, clearing it whatever happens so
    /// a failed request can never leave events for the next one. The ownership
    /// lock is taken for the whole request, which is what makes two leases'
    /// injections and their bookkeeping agree.
    fn with_batch(
        &mut self,
        request: impl FnOnce(&mut Self) -> Result<(), InputError>,
    ) -> Result<(), InputError> {
        self.batch.clear();
        let outcome = request(self);
        self.batch.clear();
        outcome
    }

    fn prepare_move_absolute(&mut self, x: i32, y: i32) -> Result<(), InputError> {
        let epoch = self.ensure_ready()?;
        let (normalized_x, normalized_y) = self.absolute_coordinates(x, y)?;
        self.with_batch(|session| {
            let mut registry = lock_arbitration();
            session.batch.push(
                RdInputEvent {
                    struct_size: EVENT_SIZE,
                    kind: native::EVENT_MOUSE,
                    action: native::MOUSE_MOVE_ABSOLUTE,
                    x: normalized_x,
                    y: normalized_y,
                    ..Default::default()
                },
                0,
            );
            session.flush(&mut registry, epoch)
        })
    }

    fn prepare_button(
        &mut self,
        down: bool,
        buttons: u32,
        x: i32,
        y: i32,
    ) -> Result<(), InputError> {
        let (button, virtual_key) = match buttons {
            BUTTON_LEFT_BIT => (native::BUTTON_LEFT, VK_LBUTTON),
            BUTTON_RIGHT_BIT => (native::BUTTON_RIGHT, VK_RBUTTON),
            BUTTON_MIDDLE_BIT => (native::BUTTON_MIDDLE, VK_MBUTTON),
            BUTTON_BACK_BIT => (native::BUTTON_BACK, VK_XBUTTON1),
            BUTTON_FORWARD_BIT => (native::BUTTON_FORWARD, VK_XBUTTON2),
            _ => return Err(InputError::InvalidInput),
        };
        let epoch = self.ensure_ready()?;
        // The transition's coordinates are validated like every other absolute
        // pair and then not applied; see the module note on coordinates.
        self.display_point_is_inside(x, y)?;
        let key = hold_key(virtual_key, false)?;
        let slot = slot_for(key)?;
        self.with_batch(|session| {
            let mut registry = lock_arbitration();
            if down {
                match session.plan_down(&mut registry, epoch, slot, key)? {
                    DownPlan::Claim => {
                        let episode = registry.open_episode()?;
                        session.push_button_hold(slot, button, Effect::Claim, episode);
                    }
                    // This lease already holds the button: the down repeats that
                    // episode, with the encoding its own down used, instead of
                    // ending it or opening a second one.
                    DownPlan::Repeat { episode, encoding } => {
                        session.push_repeat(slot, encoding, episode)
                    }
                    // A hold that is not this lease's own: nothing is injected
                    // and nothing is recorded.
                    DownPlan::Skip => return Ok(()),
                }
            } else {
                // The release repeats the encoding of the down that was really
                // injected, not a fresh guess from this event. A hold in doubt was
                // resolved by evidence instead, which sends nothing, and a hold
                // this lease never took is not lifted: either way there is no
                // release to send.
                let Some((episode, encoding)) = session.plan_up(&mut registry, slot, key)? else {
                    return Ok(());
                };
                session.push_release(slot, encoding, episode);
            }
            session.flush(&mut registry, epoch)
        })
    }

    fn prepare_wheel(&mut self, x: i32, y: i32) -> Result<(), InputError> {
        if x == 0 && y == 0 {
            return Err(InputError::InvalidInput);
        }
        let epoch = self.ensure_ready()?;
        self.with_batch(|session| {
            let mut registry = lock_arbitration();
            if x != 0 {
                session.push_wheel(x, native::MOUSE_HWHEEL)?;
            }
            if y != 0 {
                session.push_wheel(y, native::MOUSE_WHEEL)?;
            }
            session.flush(&mut registry, epoch)
        })
    }

    fn prepare_trackpad(&mut self, x: i32, y: i32) -> Result<(), InputError> {
        if x == 0 && y == 0 {
            return Err(InputError::InvalidInput);
        }
        if x.unsigned_abs() > MAX_TRACKPAD_UNITS as u32
            || y.unsigned_abs() > MAX_TRACKPAD_UNITS as u32
        {
            return Err(InputError::InvalidInput);
        }
        let epoch = self.ensure_ready()?;
        let horizontal = accumulate_trackpad(&mut self.trackpad_horizontal, x)?;
        let vertical = accumulate_trackpad(&mut self.trackpad_vertical, y)?;
        self.with_batch(|session| {
            let mut registry = lock_arbitration();
            if horizontal != 0 {
                session.push_wheel(horizontal, native::MOUSE_HWHEEL)?;
            }
            if vertical != 0 {
                session.push_wheel(vertical, native::MOUSE_WHEEL)?;
            }
            session.flush(&mut registry, epoch)
        })
    }

    fn prepare_move_relative(&mut self, x: i32, y: i32) -> Result<(), InputError> {
        if x == 0 && y == 0 {
            // The legacy relative-mouse-mode marker. It asks for no motion, so
            // there is nothing to inject and nothing to remember.
            return Ok(());
        }
        if x.unsigned_abs() > MAX_RELATIVE_PIXELS as u32
            || y.unsigned_abs() > MAX_RELATIVE_PIXELS as u32
        {
            return Err(InputError::InvalidInput);
        }
        let epoch = self.ensure_ready()?;
        self.with_batch(|session| {
            let mut registry = lock_arbitration();
            session.batch.push(
                RdInputEvent {
                    struct_size: EVENT_SIZE,
                    kind: native::EVENT_MOUSE,
                    action: native::MOUSE_MOVE_RELATIVE,
                    x,
                    y,
                    ..Default::default()
                },
                0,
            );
            session.flush(&mut registry, epoch)
        })
    }

    fn prepare_map_key(&mut self, event: &KeyEvent) -> Result<(), InputError> {
        let wire_scan = decode_windows_map(event)?;
        let epoch = self.ensure_ready()?;
        self.with_batch(|session| {
            let mut registry = lock_arbitration();
            if let Some(slot) = registry.map_slot(wire_scan) {
                match session.own_hold(&mut registry, slot, slot as u32)? {
                    OwnHold::Live(record) => {
                        if event.down {
                            session.push_repeat(slot, record.encoding, record.episode);
                        } else {
                            session.push_release(slot, record.encoding, record.episode);
                        }
                        return session.flush(&mut registry, epoch);
                    }
                    // Only real retirement ends the frozen association. A new
                    // down may then query the current layout for a new episode.
                    OwnHold::Retired => {}
                    OwnHold::None => return Err(InputError::InjectionFailed),
                }
            }
            if !event.down {
                return Ok(());
            }
            let encoding = map_key_encoding(wire_scan)?;
            let Encoding::Key { virtual_key, extended, .. } = encoding else {
                return Err(InputError::Unsupported);
            };
            let key = hold_key(virtual_key, extended)?;
            let slot = slot_for(key)?;
            if registry.holding(slot).is_some() {
                // A different wire key/mode already occupies this canonical
                // family. Do not relabel or steal its hold.
                return Err(InputError::InjectionFailed);
            }
            if matches!(session.admit(&mut registry, epoch, key)?, Admission::Claim) {
                let episode = registry.open_episode()?;
                session.push_key_hold(slot, encoding, Effect::Claim, episode);
            }
            session.flush(&mut registry, epoch)
        })
    }

    fn prepare_key(&mut self, event: &KeyEvent, direction: Direction) -> Result<(), InputError> {
        match &event.union {
            Some(key_event::Union::ControlKey(key)) => {
                let key = key.enum_value().map_err(|_| InputError::Unsupported)?;
                let virtual_key = control_key_virtual_key(key).ok_or(InputError::Unsupported)?;
                let scan = match key {
                    // The numpad's Enter is the one key a layout lookup cannot
                    // express: it shares VK_RETURN and is told apart by its
                    // E0-prefixed scan code, which is a fact of the scancode set.
                    ControlKey::NumpadEnter => (SCAN_NUMPAD_ENTER, true),
                    _ => key_scan(virtual_key)?,
                };
                let epoch = self.ensure_ready()?;
                self.with_batch(|session| {
                    let mut registry = lock_arbitration();
                    session.prepare_legacy_key(
                        &mut registry,
                        epoch,
                        event,
                        virtual_key,
                        scan,
                        direction,
                        &[],
                    )
                })
            }
            Some(key_event::Union::Chr(character)) => {
                let character = character_key(*character)?;
                let mut layout = [Modifier::Shift; 3];
                let mut layout_len = 0usize;
                if character.shift {
                    layout[layout_len] = Modifier::Shift;
                    layout_len += 1;
                }
                if character.control {
                    layout[layout_len] = Modifier::Control;
                    layout_len += 1;
                }
                if character.alt {
                    layout[layout_len] = Modifier::Alt;
                    layout_len += 1;
                }
                let epoch = self.ensure_ready()?;
                self.with_batch(|session| {
                    let mut registry = lock_arbitration();
                    session.prepare_legacy_key(
                        &mut registry,
                        epoch,
                        event,
                        character.virtual_key,
                        (character.scan_code, character.extended),
                        direction,
                        &layout[..layout_len],
                    )
                })
            }
            Some(key_event::Union::Unicode(value)) => {
                let (units, len) = unicode_units(*value)?;
                let epoch = self.ensure_ready()?;
                self.with_batch(|session| {
                    let mut registry = lock_arbitration();
                    session.push_text(&units[..len], direction);
                    session.flush(&mut registry, epoch)
                })
            }
            Some(key_event::Union::Seq(text)) => {
                if text.is_empty() {
                    return Err(InputError::InvalidInput);
                }
                if text.contains('\0') {
                    // A NUL is not a character this host types, and it is refused
                    // here rather than at the adapter: a payload refused before any
                    // batch is built cannot cost the desktop read, cannot reach
                    // `SendInput` and cannot touch ownership.
                    return Err(InputError::InvalidInput);
                }
                let epoch = self.ensure_ready()?;
                self.with_batch(|session| {
                    let mut registry = lock_arbitration();
                    session.prepare_text(text, &mut registry, epoch)
                })
            }
            Some(key_event::Union::Win2winHotkey(_)) => Err(InputError::Unsupported),
            // The one-of is non-exhaustive: a form this build does not know is
            // refused, never guessed at.
            Some(_) => Err(InputError::Unsupported),
            None => Err(InputError::InvalidInput),
        }
    }

    /// Injects one legacy key with the modifiers its event requires.
    ///
    /// A modifier this lease already holds stays held; a modifier another lease
    /// holds refuses the event, because this engine will not type into a state it
    /// does not control and will never lift another lease's key; a modifier that
    /// is already down without belonging to a lease (the operator's own hand) or
    /// that the guard cannot vouch for is used as it is and is not lifted
    /// afterwards. Every down here is one episode, and every up carries the
    /// episode and the encoding of the down it releases.
    ///
    /// Modifiers are collected by canonical hold identity, so an alias of the
    /// event's own key - `RShift` on a `Shift` event, say - is that key being
    /// pressed rather than a modifier for it, and two aliases of one key are one
    /// modifier rather than two downs on one slot.
    fn prepare_legacy_key(
        &mut self,
        registry: &mut Arbitration,
        epoch: u32,
        event: &KeyEvent,
        virtual_key: u32,
        scan: (u32, bool),
        direction: Direction,
        layout_modifiers: &[Modifier],
    ) -> Result<(), InputError> {
        let key = hold_key(virtual_key, scan.1)?;
        let slot = slot_for(key)?;

        let mut required = [TransientModifier::EMPTY; MAX_TRANSIENT_MODIFIERS];
        let mut required_len = 0usize;
        for modifier in event.modifiers.iter() {
            let control = modifier.enum_value().map_err(|_| InputError::Unsupported)?;
            let modifier = Modifier::from_control_key(control).ok_or(InputError::InvalidInput)?;
            insert_modifier(
                &mut required,
                &mut required_len,
                modifier_encoding(modifier.virtual_key())?,
                key,
            )?;
        }
        for modifier in layout_modifiers {
            insert_modifier(
                &mut required,
                &mut required_len,
                modifier_encoding(modifier.virtual_key())?,
                key,
            )?;
        }

        // The modifiers this event presses for itself, and their own episodes.
        let mut pressed = [(0usize, 0u64, Encoding::Button(0)); MAX_TRANSIENT_MODIFIERS];
        let mut pressed_len = 0usize;
        for &TransientModifier { canonical, encoding } in &required[..required_len] {
            let modifier_slot = slot_for(canonical)?;
            if !matches!(
                self.plan_down(registry, epoch, modifier_slot, canonical)?,
                DownPlan::Claim
            ) {
                // Already held by this lease, held by someone else, or not
                // vouchable: it is used as it is and never pressed again as a
                // fresh episode of its own.
                continue;
            }
            let episode = registry.open_episode()?;
            self.push_key_hold(modifier_slot, encoding, Effect::Claim, episode);
            pressed[pressed_len] = (modifier_slot, episode, encoding);
            pressed_len += 1;
        }

        let encoding = Encoding::Key {
            virtual_key,
            scan_code: scan.0,
            extended: scan.1,
            scan_code_mode: false,
        };
        match direction {
            Direction::Down => match self.plan_down(registry, epoch, slot, key)? {
                DownPlan::Claim => {
                    let episode = registry.open_episode()?;
                    self.push_key_hold(slot, encoding, Effect::Claim, episode);
                }
                // An ordinary repeat of a key this lease is holding: it carries
                // the episode and the encoding of the down that took the hold, so
                // the hold is neither re-claimed nor released.
                DownPlan::Repeat { episode, encoding } => {
                    self.push_key_hold(slot, encoding, Effect::Repeat, episode)
                }
                // A hold that is not this lease's own: nothing is injected.
                DownPlan::Skip => {}
            },
            Direction::Up => {
                // A hold in doubt was resolved by evidence, which sends nothing,
                // and a key this lease never took is not lifted: either way there
                // is no release to send.
                if let Some((episode, encoding)) = self.plan_up(registry, slot, key)? {
                    self.push_key_hold(slot, encoding, Effect::Release, episode);
                }
            }
            // A click on a key this lease already holds is a repeat of the
            // episode holding it, never a release of that hold. A click on a key
            // whose hold was in doubt stops at that: a click carries a release,
            // which is what a hold in doubt may not be given, so resolving the
            // doubt is all this event does. A click on a free key presses and
            // releases one episode of its own.
            Direction::Click => match self.own_hold(registry, slot, key)? {
                OwnHold::Live(record) => {
                    self.push_key_hold(slot, record.encoding, Effect::Repeat, record.episode)
                }
                OwnHold::Retired => {}
                OwnHold::None => {
                    if matches!(self.admit(registry, epoch, key)?, Admission::Claim) {
                        let episode = registry.open_episode()?;
                        self.push_key_hold(slot, encoding, Effect::Claim, episode);
                        self.push_key_hold(slot, encoding, Effect::Release, episode);
                    }
                }
            },
        }

        // The modifiers this event pressed for itself are released again, with
        // their own episodes, so a hold this lease did not take is never lifted.
        for &(modifier_slot, episode, encoding) in &pressed[..pressed_len] {
            self.push_key_hold(modifier_slot, encoding, Effect::Release, episode);
        }
        self.flush(registry, epoch)
    }

    /// Types one `seq` text: every UTF-16 code unit as one Unicode keystroke.
    fn prepare_text(
        &mut self,
        text: &str,
        registry: &mut Arbitration,
        epoch: u32,
    ) -> Result<(), InputError> {
        let mut units = 0usize;
        for unit in text.encode_utf16() {
            units += 1;
            if units > MAX_SEQ_UNITS {
                return Err(InputError::InvalidInput);
            }
            self.push_text_unit(unit, false);
            self.push_text_unit(unit, true);
        }
        self.flush(registry, epoch)
    }

    fn push_text(&mut self, units: &[u16], direction: Direction) {
        for &unit in units {
            match direction {
                Direction::Down => self.push_text_unit(unit, false),
                Direction::Up => self.push_text_unit(unit, true),
                Direction::Click => {
                    self.push_text_unit(unit, false);
                    self.push_text_unit(unit, true);
                }
            }
        }
    }

    fn push_text_unit(&mut self, code_unit: u16, up: bool) {
        // Text holds nothing: it carries no episode and no token, so it can
        // never be mistaken for an own hold event.
        self.batch.push(
            RdInputEvent {
                struct_size: EVENT_SIZE,
                kind: native::EVENT_TEXT,
                flags: if up { native::FLAG_UP } else { 0 },
                code_unit: i32::from(code_unit),
                ..Default::default()
            },
            0,
        );
    }

    /// Pushes one mouse button event that carries an ownership decision.
    fn push_button_hold(&mut self, slot: usize, button: u32, effect: Effect, episode: u64) {
        let up = effect == Effect::Release;
        let event = self.push_mouse_button(button, !up, episode);
        self.batch.holds.push(Hold {
            event,
            slot,
            episode,
            encoding: if up {
                None
            } else {
                Some(Encoding::Button(button))
            },
            effect,
        });
    }

    /// Pushes a down that repeats an episode this lease already holds, with the
    /// encoding of the down that took the hold. The ownership it carries is
    /// explicitly a repeat: no receipt of it may claim, release or re-confirm the
    /// record.
    fn push_repeat(&mut self, slot: usize, encoding: Encoding, episode: u64) {
        self.push_owned(slot, encoding, episode, Effect::Repeat);
    }

    /// Pushes the release of an episode this lease owns, repeating the encoding
    /// of the down that was really injected.
    fn push_release(&mut self, slot: usize, encoding: Encoding, episode: u64) {
        self.push_owned(slot, encoding, episode, Effect::Release);
    }

    /// Pushes one hold event of `encoding`'s own kind (the encoding says which,
    /// because the kind of hold a slot carries is fixed by the path that claimed
    /// it) with the ownership effect it is to be applied under.
    fn push_owned(&mut self, slot: usize, encoding: Encoding, episode: u64, effect: Effect) {
        match encoding {
            Encoding::Key { .. } => self.push_key_hold(slot, encoding, effect, episode),
            Encoding::Button(button) => self.push_button_hold(slot, button, effect, episode),
        }
    }

    /// Pushes one key event that carries an ownership decision.
    fn push_key_hold(&mut self, slot: usize, encoding: Encoding, effect: Effect, episode: u64) {
        let Encoding::Key {
            virtual_key,
            scan_code,
            extended,
            scan_code_mode,
        } = encoding
        else {
            return;
        };
        let up = effect == Effect::Release;
        let event = self.push_key_event(
            virtual_key, scan_code, extended, scan_code_mode, up, episode,
        );
        self.batch.holds.push(Hold {
            event,
            slot,
            episode,
            encoding: if up { None } else { Some(encoding) },
            effect,
        });
    }

    fn push_mouse_button(&mut self, button: u32, down: bool, episode: u64) -> u32 {
        let event = self.batch.events.len() as u32;
        self.batch.push(
            RdInputEvent {
                struct_size: EVENT_SIZE,
                kind: native::EVENT_MOUSE,
                action: if down {
                    native::MOUSE_BUTTON_DOWN
                } else {
                    native::MOUSE_BUTTON_UP
                },
                button,
                ..Default::default()
            },
            episode,
        );
        event
    }

    /// One wheel axis. The wire unit is a notch and the sign convention is the
    /// module's: `y < 0` is up, `x > 0` is right.
    fn push_wheel(&mut self, notches: i32, action: u32) -> Result<(), InputError> {
        if notches.unsigned_abs() > MAX_WHEEL_NOTCHES as u32 {
            return Err(InputError::InvalidInput);
        }
        let turns = notches
            .checked_mul(WHEEL_DELTA)
            .ok_or(InputError::InvalidInput)?;
        let rotation = if action == native::MOUSE_WHEEL {
            // Windows counts a positive rotation away from the user, which is
            // one notch up, and the wire's vertical axis is negative upwards.
            -turns
        } else {
            // Tilted right is positive in both, so the horizontal axis keeps the
            // sign it arrived with.
            turns
        };
        self.batch.push(
            RdInputEvent {
                struct_size: EVENT_SIZE,
                kind: native::EVENT_MOUSE,
                action,
                data: rotation,
                ..Default::default()
            },
            0,
        );
        Ok(())
    }

    fn push_key_event(
        &mut self,
        virtual_key: u32,
        scan_code: u32,
        extended: bool,
        scan_code_mode: bool,
        up: bool,
        episode: u64,
    ) -> u32 {
        let event = self.batch.events.len() as u32;
        let mut flags = if up { native::FLAG_UP } else { 0 };
        if extended {
            flags |= native::FLAG_EXTENDED;
        }
        if scan_code_mode {
            flags |= native::FLAG_SCANCODE;
        }
        self.batch.push(
            RdInputEvent {
                struct_size: EVENT_SIZE,
                kind: native::EVENT_KEY,
                flags,
                virtual_key,
                scan_code,
                ..Default::default()
            },
            episode,
        );
        event
    }

    /// Requires a selected-display-local pair to be inside the frozen display.
    fn display_point_is_inside(&self, x: i32, y: i32) -> Result<(), InputError> {
        let width = self.binding.width();
        let height = self.binding.height();
        if width <= 0 || height <= 0 {
            return Err(InputError::OutputChanged);
        }
        if x < 0 || y < 0 || x >= width || y >= height {
            return Err(InputError::InvalidInput);
        }
        Ok(())
    }

    /// Validates a selected-display-local pair and translates it once into the
    /// virtual desktop the absolute mouse flag counts in.
    fn absolute_coordinates(&self, x: i32, y: i32) -> Result<(i32, i32), InputError> {
        self.display_point_is_inside(x, y)?;
        let rect = self.binding.desktop_rect();
        let desktop_x = x.checked_add(rect[0]).ok_or(InputError::InvalidInput)?;
        let desktop_y = y.checked_add(rect[1]).ok_or(InputError::InvalidInput)?;
        let screen = virtual_screen()?;
        Ok((
            normalize(desktop_x, screen.left, screen.width)?,
            normalize(desktop_y, screen.top, screen.height)?,
        ))
    }

    /// Injects the batch through the guard and applies ownership for exactly the
    /// events whose receipts say they passed it.
    ///
    /// The reply as a whole is validated before any of it is believed: the size,
    /// the counts against each other and this batch, the epoch it was planned
    /// under, the guard's state, and that every receipt is one this build can
    /// read. A reply that contradicts itself is not consumed at all - no passed
    /// receipt releases an owner or confirms a hold - and closes this lease's
    /// admission. A batch refused whole before anything was submitted is
    /// different: it injected nothing, so it moves no ownership and keeps the
    /// admission. The inserted count is never used to decide which events
    /// happened: a short count is a failure, but the per-event receipt is what
    /// says whether a hold was really taken or released.
    fn flush(&mut self, registry: &mut Arbitration, epoch: u32) -> Result<(), InputError> {
        if self.batch.events.is_empty() {
            return Ok(());
        }
        if self.batch.events.len() > MAX_BATCH_EVENTS || self.batch.holds.len() > MAX_BATCH_HOLDS {
            // Unreachable through this module's own builders; refused rather than
            // submitted, because the guard has no room to track it.
            return Err(InputError::InvalidInput);
        }
        if self.faulted || arbitration_poisoned() {
            // A known fault closed admission: what is owned stays owned, and the
            // records are resolved by evidence.
            registry.activity.snapshot.uncertain = true;
            return Err(InputError::ReclamationUnconfirmed);
        }
        let session = self.session;
        let transaction = registry.open_transaction()?;
        let count = self.batch.events.len() as u32;
        self.batch
            .receipts
            .resize(self.batch.events.len(), native::RECEIPT_NOT_TRACKED);
        let mut result = RdInputSendResult {
            struct_size: RESULT_SIZE,
            ..Default::default()
        };
        let request = RdInputSendRequest {
            struct_size: REQUEST_SIZE,
            epoch,
            lease: session,
            transaction,
            events: self.batch.events.as_ptr(),
            count,
            reserved: 0,
            episodes: self.batch.episodes.as_ptr(),
            receipts: self.batch.receipts.as_mut_ptr(),
        };
        let status = unsafe { native::rd_input_send(&request, &mut result) };
        registry.activity.observe(&self.batch, epoch, status, &result);

        // The whole reply is read before any of it is believed: a structure the
        // adapter did not write, a count that cannot come from this batch, an
        // epoch that is not the one this batch was planned under, or a receipt
        // this build cannot read is a contradiction, not a partial success.
        let receipts_readable = self
            .batch
            .receipts
            .iter()
            .all(|receipt| Receipt::of(*receipt).is_some());
        let contradiction = result.struct_size != RESULT_SIZE
            || result.epoch != epoch
            || result.inserted > count
            || result.submitted > count
            || result.inserted > result.submitted
            || !receipts_readable;
        // A batch the adapter refused whole, before it handed anything to
        // SendInput, is a parameter refusal: it injected nothing, so it cannot
        // have moved a hold, and it must not end this lease's admission or the
        // records it owns.
        let refused_nothing_submitted = status == native::INVALID_ARGUMENT
            && result.struct_size == RESULT_SIZE
            && result.inserted == 0
            && result.submitted == 0
            && self.batch.receipts.iter().all(|receipt| {
                matches!(
                    *receipt,
                    native::RECEIPT_NOT_SUBMITTED | native::RECEIPT_NOT_TRACKED
                )
            });
        if refused_nothing_submitted {
            return Err(InputError::InvalidInput);
        }

        if contradiction {
            // No receipt of a self-contradicting reply releases an owner or
            // confirms a hold. A down that may have reached the system is kept as
            // a may-down, an up that may have gone through keeps its record, and
            // this lease stops injecting until the evidence pass resolves them.
            for hold in &self.batch.holds {
                match hold.effect {
                    Effect::Claim => {
                        let Some(encoding) = hold.encoding else {
                            continue;
                        };
                        if registry.mine(hold.slot, session).is_none() {
                            registry.claim(
                                hold.slot,
                                HoldRecord {
                                    session,
                                    episode: hold.episode,
                                    epoch,
                                    certainty: Certainty::MayDown,
                                    retained: true,
                                    encoding,
                                },
                            );
                        }
                    }
                    // A repeat changes nothing, and a release may or may not
                    // have happened: either way this lease's record stays owned.
                    Effect::Repeat | Effect::Release => registry.retain(hold.slot, session),
                }
            }
            self.faulted = true;
            return Err(InputError::InjectionFailed);
        }

        let mut tainted = result.guard_state != native::GUARD_ARMED || status != native::OK;

        // Apply the decisions in event order. Only a receipt that says the event
        // passed this guard and the rest of the hook chain releases a record, and
        // only a down that passed creates a confirmed one.
        for hold in &self.batch.holds {
            // The whole reply was checked to be readable above, so this is one of
            // the receipts this build knows.
            let Some(receipt) = Receipt::of(self.batch.receipts[hold.event as usize]) else {
                tainted = true;
                continue;
            };
            match hold.effect {
                Effect::Claim => match receipt {
                    Receipt::Passed => {
                        let Some(encoding) = hold.encoding else {
                            tainted = true;
                            continue;
                        };
                        registry.claim(
                            hold.slot,
                            HoldRecord {
                                session,
                                episode: hold.episode,
                                epoch,
                                certainty: Certainty::Confirmed,
                                retained: false,
                                encoding,
                            },
                        );
                    }
                    // It may have reached the system without this guard watching
                    // it pass: owned, blocked, never assumed released. A receipt
                    // that says a hold event is not tracked at all is a
                    // contradiction of the same kind and takes the same
                    // conservative record.
                    Receipt::DownstreamVetoed | Receipt::Unknown | Receipt::NotTracked => {
                        if receipt == Receipt::NotTracked {
                            tainted = true;
                        }
                        let Some(encoding) = hold.encoding else {
                            tainted = true;
                            continue;
                        };
                        registry.claim(
                            hold.slot,
                            HoldRecord {
                                session,
                                episode: hold.episode,
                                epoch,
                                certainty: Certainty::MayDown,
                                retained: true,
                                encoding,
                            },
                        );
                    }
                    // Refused by the guard, or never submitted: the event did not
                    // reach the system, so nothing is owned.
                    Receipt::SelfVetoed | Receipt::NotSubmitted => {}
                },
                // A repeat carries no ownership decision of its own: the episode
                // it repeats is the one the record already holds, so it neither
                // claims, releases, re-confirms nor ages anything. A receipt that
                // says a hold event carries no ownership decision is still a
                // contradiction of the reply.
                Effect::Repeat => {
                    if receipt == Receipt::NotTracked {
                        tainted = true;
                    }
                }
                Effect::Release => match receipt {
                    Receipt::Passed => registry.relinquish(hold.slot, session),
                    // A refused, unknown or unsubmitted up may have left the key
                    // down: the record stays owned and the episode is resolved by
                    // evidence from here on.
                    Receipt::Unknown
                    | Receipt::SelfVetoed
                    | Receipt::DownstreamVetoed
                    | Receipt::NotSubmitted
                    | Receipt::NotTracked => {
                        if receipt == Receipt::NotTracked {
                            tainted = true;
                        }
                        registry.retain(hold.slot, session);
                    }
                },
            }
        }
        self.faulted |= tainted;

        if status == native::INVALID_ARGUMENT {
            return Err(InputError::InvalidInput);
        }
        if status != native::OK {
            return Err(map_status(status));
        }
        if result.inserted != count {
            // A partial batch is a failure, and whatever may remain down from it
            // stays owned.
            return Err(InputError::InjectionFailed);
        }
        Ok(())
    }
}

impl Drop for InputSession {
    /// Best effort only: a drop cannot report an unconfirmed release, which is
    /// what `release_all` is for. A session whose holds cannot be resolved also
    /// keeps its guard lease, so the quarantine keeps the message thread, the
    /// descriptors, the observed key state and the code that refuses a late own
    /// event alive: a hold that could not be released is never quietly dropped
    /// and its keys are never silently reopened.
    fn drop(&mut self) {
        let _ = self.release_all();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Down,
    Up,
    Click,
}

/// A keyboard modifier the wire can require for one event.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Modifier {
    Shift,
    Control,
    Alt,
    RightShift,
    RightControl,
    RightAlt,
    Meta,
    RightMeta,
}

impl Modifier {
    fn from_control_key(key: ControlKey) -> Option<Self> {
        Some(match key {
            ControlKey::Alt | ControlKey::Option | ControlKey::Menu => Self::Alt,
            ControlKey::Shift => Self::Shift,
            ControlKey::Control => Self::Control,
            ControlKey::Meta => Self::Meta,
            ControlKey::RShift => Self::RightShift,
            ControlKey::RControl => Self::RightControl,
            ControlKey::RAlt => Self::RightAlt,
            ControlKey::RWin => Self::RightMeta,
            _ => return None,
        })
    }

    fn virtual_key(self) -> u32 {
        match self {
            Self::Shift => VK_SHIFT,
            Self::Control => VK_CONTROL,
            Self::Alt => VK_MENU,
            Self::RightShift => VK_RSHIFT,
            Self::RightControl => VK_RCONTROL,
            Self::RightAlt => VK_RMENU,
            Self::Meta => VK_LWIN,
            Self::RightMeta => VK_RWIN,
        }
    }
}

/// One modifier one event presses for itself: the canonical hold key it occupies,
/// which is what makes two aliases of one key the same modifier, and the exact
/// encoding its own down uses.
#[derive(Clone, Copy)]
struct TransientModifier {
    canonical: u32,
    encoding: Encoding,
}

impl TransientModifier {
    /// A slot that is not a modifier. Only ever read below the array's length.
    const EMPTY: Self = Self {
        canonical: 0,
        encoding: Encoding::Button(0),
    };
}

/// The canonical hold key and the encoding of one modifier's own down.
fn modifier_encoding(virtual_key: u32) -> Result<TransientModifier, InputError> {
    let (scan_code, extended) = key_scan(virtual_key)?;
    Ok(TransientModifier {
        canonical: hold_key(virtual_key, extended)?,
        encoding: Encoding::Key {
            virtual_key,
            scan_code,
            extended,
            scan_code_mode: false,
        },
    })
}

/// Adds one modifier unless it is the event's own key or one this event already
/// requires. Both tests use the canonical hold identity, so an alias of the
/// event's key is that key being pressed rather than a modifier for it, and two
/// aliases of one key never become two downs on one slot.
fn insert_modifier(
    required: &mut [TransientModifier; MAX_TRANSIENT_MODIFIERS],
    len: &mut usize,
    modifier: TransientModifier,
    own_key: u32,
) -> Result<(), InputError> {
    if modifier.canonical == own_key
        || required[..*len]
            .iter()
            .any(|existing| existing.canonical == modifier.canonical)
    {
        return Ok(());
    }
    if *len == MAX_TRANSIENT_MODIFIERS {
        return Err(InputError::InvalidInput);
    }
    required[*len] = modifier;
    *len += 1;
    Ok(())
}

/// The Win32 virtual key for one wire control key, or `None` for the keys this
/// host refuses on purpose: the secure attention sequence and the shell's lock
/// action cannot be produced by `SendInput`, the phone-only power key has no
/// Windows virtual key, and the wire's `Unknown` is not a key.
fn control_key_virtual_key(key: ControlKey) -> Option<u32> {
    Some(match key {
        ControlKey::Alt | ControlKey::Option | ControlKey::Menu => VK_MENU,
        ControlKey::RAlt => VK_RMENU,
        ControlKey::Shift => VK_SHIFT,
        ControlKey::RShift => VK_RSHIFT,
        ControlKey::Control => VK_CONTROL,
        ControlKey::RControl => VK_RCONTROL,
        ControlKey::Meta => VK_LWIN,
        ControlKey::RWin => VK_RWIN,
        ControlKey::Backspace => VK_BACK,
        ControlKey::CapsLock => VK_CAPITAL,
        ControlKey::Delete => VK_DELETE,
        ControlKey::DownArrow => VK_DOWN,
        ControlKey::End => VK_END,
        ControlKey::Escape => VK_ESCAPE,
        ControlKey::F1 => VK_F1,
        ControlKey::F2 => VK_F2,
        ControlKey::F3 => VK_F3,
        ControlKey::F4 => VK_F4,
        ControlKey::F5 => VK_F5,
        ControlKey::F6 => VK_F6,
        ControlKey::F7 => VK_F7,
        ControlKey::F8 => VK_F8,
        ControlKey::F9 => VK_F9,
        ControlKey::F10 => VK_F10,
        ControlKey::F11 => VK_F11,
        ControlKey::F12 => VK_F12,
        ControlKey::Home => VK_HOME,
        ControlKey::LeftArrow => VK_LEFT,
        ControlKey::PageDown => VK_NEXT,
        ControlKey::PageUp => VK_PRIOR,
        ControlKey::Return => VK_RETURN,
        ControlKey::RightArrow => VK_RIGHT,
        ControlKey::Space => VK_SPACE,
        ControlKey::Tab => VK_TAB,
        ControlKey::UpArrow => VK_UP,
        ControlKey::Numpad0 => VK_NUMPAD0,
        ControlKey::Numpad1 => VK_NUMPAD1,
        ControlKey::Numpad2 => VK_NUMPAD2,
        ControlKey::Numpad3 => VK_NUMPAD3,
        ControlKey::Numpad4 => VK_NUMPAD4,
        ControlKey::Numpad5 => VK_NUMPAD5,
        ControlKey::Numpad6 => VK_NUMPAD6,
        ControlKey::Numpad7 => VK_NUMPAD7,
        ControlKey::Numpad8 => VK_NUMPAD8,
        ControlKey::Numpad9 => VK_NUMPAD9,
        ControlKey::Cancel => VK_CANCEL,
        ControlKey::Clear => VK_CLEAR,
        ControlKey::Pause => VK_PAUSE,
        ControlKey::Kana => VK_KANA,
        ControlKey::Hangul => VK_HANGUL,
        ControlKey::Junja => VK_JUNJA,
        ControlKey::Final => VK_FINAL,
        ControlKey::Hanja => VK_HANJA,
        ControlKey::Kanji => VK_KANJI,
        ControlKey::Convert => VK_CONVERT,
        ControlKey::Select => VK_SELECT,
        ControlKey::Print => VK_PRINT,
        ControlKey::Execute => VK_EXECUTE,
        ControlKey::Snapshot => VK_SNAPSHOT,
        ControlKey::Insert => VK_INSERT,
        ControlKey::Help => VK_HELP,
        ControlKey::Sleep => VK_SLEEP,
        ControlKey::Separator => VK_SEPARATOR,
        ControlKey::Scroll => VK_SCROLL,
        ControlKey::NumLock => VK_NUMLOCK,
        ControlKey::Apps => VK_APPS,
        ControlKey::Multiply => VK_MULTIPLY,
        ControlKey::Add => VK_ADD,
        ControlKey::Subtract => VK_SUBTRACT,
        ControlKey::Decimal => VK_DECIMAL,
        ControlKey::Divide => VK_DIVIDE,
        ControlKey::Equals => VK_OEM_PLUS,
        ControlKey::NumpadEnter => VK_RETURN,
        ControlKey::VolumeMute => VK_VOLUME_MUTE,
        ControlKey::VolumeUp => VK_VOLUME_UP,
        ControlKey::VolumeDown => VK_VOLUME_DOWN,
        ControlKey::Unknown
        | ControlKey::Power
        | ControlKey::CtrlAltDel
        | ControlKey::LockScreen => return None,
    })
}

/// The UTF-16 units one `unicode` value injects.
fn unicode_units(value: u32) -> Result<([u16; 2], usize), InputError> {
    let character = std::char::from_u32(value).filter(|character| *character != '\0');
    let Some(character) = character else {
        // A lone surrogate, an out-of-range value or NUL is not a character.
        return Err(InputError::InvalidInput);
    };
    let mut units = [0u16; 2];
    let len = character.encode_utf16(&mut units).len();
    Ok((units, len))
}

/// Adds trackpad eighth-notches and returns the whole notches they made, keeping
/// the remainder for the next event.
fn accumulate_trackpad(pending: &mut i32, units: i32) -> Result<i32, InputError> {
    let total = pending.checked_add(units).ok_or(InputError::InvalidInput)?;
    *pending = total % TRACKPAD_UNITS_PER_NOTCH;
    Ok(total / TRACKPAD_UNITS_PER_NOTCH)
}
