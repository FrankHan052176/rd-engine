//! Flutter key events of one session, converted to the legacy RustDesk key
//! event the engine's `Viewer::send_rustdesk_key` admits.
//!
//! The key's identity comes from the code Flutter sends — the USB HID usage of
//! the physical key, or the platform key code of a raw event — never from
//! `character`: a character is payload, it is empty on most key-up events and on
//! every non-character key, and it cannot name Shift, an arrow or Fn. This is the
//! pinned official source's own conversion, with the local grab loop removed:
//!
//! * `https://github.com/rustdesk/rustdesk` revision
//!   `092a961b629d318fe290eeafac0cd214a1e9deeb` (AGPL-3.0, the revision
//!   `UPSTREAM.txt` pins). From `src/ui_session_interface.rs`:
//!   `handle_flutter_key_event`, `handle_flutter_raw_key_event` and the
//!   `_handle_*_non_flutter_simulation` converters (lines 909-1096) turn the
//!   Flutter payload into the physical key; `_handle_key_flutter_simulation`
//!   (lines 1006-1025) is the Flutter special-key arm. From `src/keyboard.rs`:
//!   `event_to_key_events` (lines 940-991) and `legacy_keyboard_mode` (lines
//!   1018-1245) turn that key into the wire's legacy `KeyEvent`, with the
//!   modifier state of `client::get_modifiers_state` and
//!   `client::legacy_modifiers` (lines 332-402), the lock-state modifiers of
//!   `parse_add_lock_modes_modifiers` (lines 871-899), the tracked modifier keys
//!   of `MODIFIERS_STATE` and `update_modifiers_state` (lines 82-96, 922-938) and
//!   the key classes of `is_numpad_rdev_key`, `is_letter_rdev_key` and
//!   `is_letter_rdev_key_ex` (lines 795-856); `src/common.rs:976-982` supplies
//!   `is_control_key`. The rdev revision the official tree pins
//!   (`23e24dd6b35452a495dae0ae6d99395e9755ab0f`) supplies the key tables.
//!
//! What differs, and why:
//!
//! * One event per call: `Ok(Some(event))` for a key event, `Ok(None)` for the
//!   payloads upstream answers no event for — a lock key's own press or release,
//!   a raw event Flutter could not give platform data for, and the auto-repeat of
//!   a modifier key that is already held — and an error only where upstream logs
//!   an unusable key and drops it. A key that cannot be named is neither lost in
//!   silence nor replaced by another key.
//! * One physical hold is one wire identity. A release repeats the event its own
//!   down carried, and so does a repeat of the key: upstream recomputes both from
//!   the key alone (`src/keyboard.rs:1018-1245`), which cannot match a down whose
//!   character came from the keyboard layout — `Shift+1` goes down as `!` and
//!   would come up as `1` — and a repeat that derived a new identity is a second
//!   key down to the peer and to the engine's writer, held under that other
//!   identity, which one release cannot undo. The wire has no key id; upstream
//!   tracks the same holds in `TO_RELEASE` (`src/keyboard.rs:946-957`, swept at
//!   732-756), and the engine's writer releases the representation its own ledger
//!   recorded. The release and the repeat therefore carry the event, and the
//!   modifier list, the hold began with.
//! * No local OS state. Upstream reads the keyboard's own state
//!   (`get_key_state`) and its grab loop's tracked state; this adapter has only
//!   the events the client sends, so that tracked state is the whole of it and it
//!   lives per session. Branches that need the grab loop are unreachable here and
//!   are not reproduced: the AltGr phantom-control filter (`IS_ALT_GR`, lines
//!   1063-1072) never applies because the identity comes from the platform code
//!   pair, where that phantom already resolves to `Key::AltGr`; `is_long_press`
//!   (lines 717-731) is reproduced below, down to its rule that only the eight
//!   tracked modifier keys can be a long press.
//! * Two peer-side special cases of `legacy_keyboard_mode` are not applied:
//!   `convert_numpad_keys` (lines 902-919) and the Windows `Ctrl+Alt+Del`
//!   interception of `Key::Delete` (lines 1076-1082). Both are decided by the
//!   peer's platform, which this interface does not carry. The lock-state
//!   modifiers below still tell the peer the client's own lock state, and a
//!   numpad key's effect under the peer's lock state is the peer's part of the
//!   contract; the client's Ctrl+Alt+Del has its own `session_ctrl_alt_del`
//!   entry.
//! * `clear` resets the pairing and the modifier state for a new connection.
//!   Upstream also sweeps held keys on teardown (`release_remote_keys`, lines
//!   737-756), which needs a list of events as its answer; this signature answers
//!   nothing.
//!
//! Nothing here sends anything: the returned event still goes through
//! `Viewer::send_rustdesk_key` with the session's current input generation, which
//! is the engine's own authorization and generation boundary, and no system
//! keyboard is read or grabbed.

use anyhow::{ensure, Result};
use base::message_proto::{key_event, ControlKey, KeyEvent, KeyboardMode};
use hbb_common::protobuf::Enum;
use rdev::Key;
use std::collections::HashMap;

/// The character Flutter uses to mark one of its own special keys, in the
/// `character` field of a key event and the `name` field of a raw one
/// (`src/ui_session_interface.rs:934, 995`).
const FLUTTER_KEY: &str = "flutter_key";

/// Per-session keyboard state: the modifier keys the client has pressed, and the
/// event each held key went down as, so every repeat and the release of that key
/// carry the one identity the hold began with.
#[derive(Default)]
pub struct KeyboardState {
    modifiers: Modifiers,
    held: HashMap<Key, KeyEvent>,
}

impl KeyboardState {
    /// One `sessionHandleFlutterKeyEvent` payload: the physical key as its USB
    /// HID usage, the character the layout produced beside it, and Flutter's
    /// lock modes. `down` is Flutter's `downOrUp`.
    ///
    /// The HID usage names the key
    /// (`src/ui_session_interface.rs:1034-1096`, `src/keyboard.rs:940-991`); the
    /// character is the payload of the keys that carry one
    /// (`src/keyboard.rs:1106-1135`) and is absent for the rest. `Ok(None)` is a
    /// payload the peer gets no key event for.
    pub fn flutter(
        &mut self,
        character: &str,
        usb_hid: i32,
        lock_modes: i32,
        down: bool,
    ) -> Result<Option<KeyEvent>> {
        if character == FLUTTER_KEY {
            return flutter_special_key(usb_hid, down).map(Some);
        }
        let key = rdev::usb_hid_key_from_code(usb_hid as u32);
        let character = (!character.is_empty()).then_some(character);
        self.translate(key, character, down, lock_modes)
    }

    /// One `sessionHandleFlutterRawKeyEvent` payload. `name` is that call's
    /// character field, which upstream uses only for the Flutter special-key
    /// marker (`src/ui_session_interface.rs:926-949`): a raw event's key is its
    /// position code, not its text.
    ///
    /// The platform code is the Windows virtual key code or the macOS/Linux key
    /// code; the position code is the Windows scancode or the macOS/Linux key
    /// code. On Windows both are needed, because the scancode decides except
    /// where the two keys differ only in the virtual key code
    /// (`src/ui_session_interface.rs:951-963`, rdev `get_win_key`); elsewhere the
    /// position code alone names the key. `Ok(None)` is a payload that is
    /// missing either code.
    pub fn raw(
        &mut self,
        name: &str,
        platform_code: i32,
        position_code: i32,
        lock_modes: i32,
        down: bool,
    ) -> Result<Option<KeyEvent>> {
        if name == FLUTTER_KEY {
            return flutter_special_key(platform_code, down).map(Some);
        }
        // Flutter sends -1 for both when it has no platform data for the event,
        // and upstream returns there without a word (line 952): no key is named,
        // so the peer gets no event.
        if platform_code < 0 || position_code < 0 {
            return Ok(None);
        }
        let key = raw_key(platform_code as u32, position_code as u32);
        self.translate(key, None, down, lock_modes)
    }

    /// Forgets everything a new connection must not inherit: which modifier keys
    /// were held, and which keys are held. Upstream calls this the start of the
    /// next session, and releases the keys it still held when the last one ends
    /// (`src/keyboard.rs:737-756`); releasing is the caller's to send, on the
    /// session that is going away.
    pub fn clear(&mut self) {
        self.modifiers = Modifiers::default();
        self.held.clear();
    }

    /// The legacy conversion of one key event
    /// (`src/keyboard.rs:940-991, 1018-1245`): the first event of a hold derives
    /// its identity here, every later event of that hold repeats it, and
    /// `Ok(None)` is a payload upstream answers no event for.
    fn translate(
        &mut self,
        key: Key,
        character: Option<&str>,
        down: bool,
        lock_modes: i32,
    ) -> Result<Option<KeyEvent>> {
        // `is_long_press` (lines 323-330, 717-731): the auto-repeat of a modifier
        // key that is already held sends nothing, and only the tracked modifier
        // keys can be one. The state is read as it was before this event.
        if down && self.modifiers.is_down(key) {
            return Ok(None);
        }

        // The tracked modifier state follows the event: upstream updates it
        // before the conversion reads it (lines 946-951, 348-370).
        self.modifiers.update(key, down);

        // One physical hold is one wire identity. The wire has no key id, so a
        // repeat re-sends the event the hold began with and the release undoes
        // that same event: a repeat that derived a fresh identity here — which is
        // what upstream's recomputation does whenever the layout, the character
        // or the modifier state changed since the down — would be a second key
        // down to the peer and to the engine's own hold ledger, and one release
        // could only undo one of them.
        if let Some(mut held) = self.held.remove(&key) {
            if !down {
                held.down = false;
                held.press = false;
                return Ok(Some(held));
            }
            let repeat = held.clone();
            self.held.insert(key, held);
            return Ok(Some(repeat));
        }

        let mut event = KeyEvent::new();
        event.mode = KeyboardMode::Legacy.into();
        match legacy_name(key) {
            LegacyName::Control(control) => event.set_control_key(control),
            // A lock key's own press or release is no wire event: its state
            // travels as the lock-mode modifiers of the keys that follow, and
            // upstream sends nothing for the key itself (lines 1102-1104).
            LegacyName::Lock => return Ok(None),
            LegacyName::Character => {
                let mut chr = character
                    // Upstream keeps a character only while it is at most two
                    // bytes, so a CJK character is left to the peer's own layout
                    // (line 1115-1127).
                    .filter(|name| name.len() <= 2)
                    .and_then(|name| name.chars().next())
                    .unwrap_or('\0');
                if chr == '·' {
                    // Special for Chinese (line 1128-1131).
                    chr = '`';
                }
                if chr == '\0' {
                    chr = base_character(key);
                }
                // Upstream logs the key and drops it (line 1183-1186); a key no
                // legacy event can name is refused here instead.
                ensure!(chr != '\0', "{key:?} has no legacy key identity");
                event.set_chr(chr as u32);
            }
        }

        let (alt, ctrl, shift, command) = self.modifiers.state();
        push_modifiers(&mut event, alt, ctrl, shift, command);
        push_lock_modes(&mut event, lock_modes, key);

        if down {
            event.down = true;
            self.held.insert(key, event.clone());
        }
        Ok(Some(event))
    }
}

/// The Flutter special keys: codes Flutter itself defines, carried in the slot
/// the physical key would use (`src/ui_session_interface.rs:1006-1025`, and
/// `flutter/lib/src/services/keyboard_key.g.dart` behind them). Upstream marks
/// them `Translate`; the engine's key gate admits the legacy mode this whole
/// bridge speaks, and the peer reads the control key itself, not the mode.
fn flutter_special_key(code: i32, down: bool) -> Result<KeyEvent> {
    let control = match code {
        0x007f => ControlKey::VolumeMute,
        0x0080 => ControlKey::VolumeUp,
        0x0081 => ControlKey::VolumeDown,
        0x0066 => ControlKey::Power,
        // Upstream returns without an event; the refusal is named here.
        _ => anyhow::bail!("unsupported Flutter special key {code:#x}"),
    };
    let mut event = KeyEvent::new();
    event.mode = KeyboardMode::Legacy.into();
    event.down = down;
    event.set_control_key(control);
    Ok(event)
}

/// The physical key one raw event names (`src/ui_session_interface.rs:951-963`).
/// On Windows the virtual key code and the scancode are read together, elsewhere
/// the position code is the platform's own key code.
#[cfg(target_os = "windows")]
fn raw_key(platform_code: u32, position_code: u32) -> Key {
    rdev::get_win_key(platform_code, position_code)
}

#[cfg(not(target_os = "windows"))]
fn raw_key(_platform_code: u32, position_code: u32) -> Key {
    #[cfg(target_os = "macos")]
    let key = rdev::macos_key_from_code(position_code as _);
    #[cfg(not(target_os = "macos"))]
    let key = rdev::linux_key_from_code(position_code as _);
    key
}

/// The legacy name of one physical key: upstream's control-key match
/// (`src/keyboard.rs:1044-1105`), plus the two cases that match does not turn
/// into a control key.
enum LegacyName {
    /// The wire's own enum names this key.
    Control(ControlKey),
    /// A lock key, whose state the follow-up keys carry as a lock modifier.
    Lock,
    /// No control key: the character path decides.
    Character,
}

fn legacy_name(key: Key) -> LegacyName {
    use ControlKey as C;
    LegacyName::Control(match key {
        Key::Alt => C::Alt,
        Key::AltGr => C::RAlt,
        Key::Backspace => C::Backspace,
        Key::ControlLeft => C::Control,
        Key::ControlRight => C::RControl,
        Key::DownArrow => C::DownArrow,
        Key::Escape => C::Escape,
        Key::F1 => C::F1,
        Key::F10 => C::F10,
        Key::F11 => C::F11,
        Key::F12 => C::F12,
        Key::F2 => C::F2,
        Key::F3 => C::F3,
        Key::F4 => C::F4,
        Key::F5 => C::F5,
        Key::F6 => C::F6,
        Key::F7 => C::F7,
        Key::F8 => C::F8,
        Key::F9 => C::F9,
        Key::LeftArrow => C::LeftArrow,
        Key::MetaLeft => C::Meta,
        Key::MetaRight => C::RWin,
        Key::Return => C::Return,
        Key::RightArrow => C::RightArrow,
        Key::ShiftLeft => C::Shift,
        Key::ShiftRight => C::RShift,
        Key::Space => C::Space,
        Key::Tab => C::Tab,
        Key::UpArrow => C::UpArrow,
        Key::Delete => C::Delete,
        Key::Apps => C::Apps,
        Key::Cancel => C::Cancel,
        Key::Clear => C::Clear,
        Key::Kana => C::Kana,
        Key::Hangul => C::Hangul,
        Key::Junja => C::Junja,
        Key::Final => C::Final,
        Key::Hanja | Key::Hanji => C::Hanja,
        Key::Lang2 => C::Convert,
        Key::Print => C::Print,
        Key::Select => C::Select,
        Key::Execute => C::Execute,
        Key::PrintScreen => C::Snapshot,
        Key::Help => C::Help,
        Key::Sleep => C::Sleep,
        Key::Separator => C::Separator,
        Key::KpReturn => C::NumpadEnter,
        Key::Kp0 => C::Numpad0,
        Key::Kp1 => C::Numpad1,
        Key::Kp2 => C::Numpad2,
        Key::Kp3 => C::Numpad3,
        Key::Kp4 => C::Numpad4,
        Key::Kp5 => C::Numpad5,
        Key::Kp6 => C::Numpad6,
        Key::Kp7 => C::Numpad7,
        Key::Kp8 => C::Numpad8,
        Key::Kp9 => C::Numpad9,
        Key::KpDivide => C::Divide,
        Key::KpMultiply => C::Multiply,
        Key::KpDecimal => C::Decimal,
        Key::KpMinus => C::Subtract,
        Key::KpPlus => C::Add,
        Key::CapsLock | Key::NumLock | Key::ScrollLock => return LegacyName::Lock,
        Key::Home => C::Home,
        Key::End => C::End,
        Key::Insert => C::Insert,
        Key::PageUp => C::PageUp,
        Key::PageDown => C::PageDown,
        Key::Pause => C::Pause,
        _ => return LegacyName::Character,
    })
}

/// The character a key's own position carries when the layout sent none — the
/// fallback that lets a key-up with no character name its key
/// (`src/keyboard.rs:1136-1188`). `'\0'` is a key with no such character.
fn base_character(key: Key) -> char {
    match key {
        Key::Num1 => '1',
        Key::Num2 => '2',
        Key::Num3 => '3',
        Key::Num4 => '4',
        Key::Num5 => '5',
        Key::Num6 => '6',
        Key::Num7 => '7',
        Key::Num8 => '8',
        Key::Num9 => '9',
        Key::Num0 => '0',
        Key::KeyA => 'a',
        Key::KeyB => 'b',
        Key::KeyC => 'c',
        Key::KeyD => 'd',
        Key::KeyE => 'e',
        Key::KeyF => 'f',
        Key::KeyG => 'g',
        Key::KeyH => 'h',
        Key::KeyI => 'i',
        Key::KeyJ => 'j',
        Key::KeyK => 'k',
        Key::KeyL => 'l',
        Key::KeyM => 'm',
        Key::KeyN => 'n',
        Key::KeyO => 'o',
        Key::KeyP => 'p',
        Key::KeyQ => 'q',
        Key::KeyR => 'r',
        Key::KeyS => 's',
        Key::KeyT => 't',
        Key::KeyU => 'u',
        Key::KeyV => 'v',
        Key::KeyW => 'w',
        Key::KeyX => 'x',
        Key::KeyY => 'y',
        Key::KeyZ => 'z',
        Key::Comma => ',',
        Key::Dot => '.',
        Key::SemiColon => ';',
        Key::Quote => '\'',
        Key::LeftBracket => '[',
        Key::RightBracket => ']',
        Key::Slash => '/',
        Key::BackSlash => '\\',
        Key::Minus => '-',
        Key::Equal => '=',
        Key::BackQuote => '`',
        _ => '\0',
    }
}

/// The eight modifier keys upstream tracks (`src/keyboard.rs:88-94`), as a slot
/// each; a key outside them is not tracked at all (`update_modifiers_state`,
/// lines 922-938).
fn modifier_slot(key: Key) -> Option<usize> {
    Some(match key {
        Key::ShiftLeft => 0,
        Key::ShiftRight => 1,
        Key::ControlLeft => 2,
        Key::ControlRight => 3,
        Key::Alt => 4,
        Key::AltGr => 5,
        Key::MetaLeft => 6,
        Key::MetaRight => 7,
        _ => return None,
    })
}

#[derive(Default)]
struct Modifiers {
    down: [bool; 8],
}

impl Modifiers {
    fn update(&mut self, key: Key, down: bool) {
        if let Some(slot) = modifier_slot(key) {
            self.down[slot] = down;
        }
    }

    fn is_down(&self, key: Key) -> bool {
        modifier_slot(key).is_some_and(|slot| self.down[slot])
    }

    /// The four states the legacy conversion reads, from the keys held
    /// (`client::get_modifiers_state`, `src/keyboard.rs:348-370`).
    fn state(&self) -> (bool, bool, bool, bool) {
        (
            self.is_down(Key::Alt) || self.is_down(Key::AltGr),
            self.is_down(Key::ControlLeft) || self.is_down(Key::ControlRight),
            self.is_down(Key::ShiftLeft) || self.is_down(Key::ShiftRight),
            self.is_down(Key::MetaLeft) || self.is_down(Key::MetaRight),
        )
    }
}

/// `client::legacy_modifiers` (`src/keyboard.rs:371-402`): the state that is
/// held, minus the modifier this event is itself.
fn push_modifiers(event: &mut KeyEvent, alt: bool, ctrl: bool, shift: bool, command: bool) {
    if alt
        && !names_control_key(event, ControlKey::Alt)
        && !names_control_key(event, ControlKey::RAlt)
    {
        event.modifiers.push(ControlKey::Alt.into());
    }
    if shift
        && !names_control_key(event, ControlKey::Shift)
        && !names_control_key(event, ControlKey::RShift)
    {
        event.modifiers.push(ControlKey::Shift.into());
    }
    if ctrl
        && !names_control_key(event, ControlKey::Control)
        && !names_control_key(event, ControlKey::RControl)
    {
        event.modifiers.push(ControlKey::Control.into());
    }
    if command
        && !names_control_key(event, ControlKey::Meta)
        && !names_control_key(event, ControlKey::RWin)
    {
        event.modifiers.push(ControlKey::Meta.into());
    }
}

/// `is_control_key` (`src/common.rs:976-982`).
fn names_control_key(event: &KeyEvent, key: ControlKey) -> bool {
    matches!(
        event.union.as_ref(),
        Some(key_event::Union::ControlKey(named)) if named.value() == key.value()
    )
}

/// The lock state the client reports, as modifiers of this key
/// (`parse_add_lock_modes_modifiers`, `src/keyboard.rs:871-888`). The bits are
/// Flutter's lock modes: Caps Lock is bit 1 and Num Lock bit 2
/// (`flutter/lib/models/input_model.dart`, `_buildLockModes`).
fn push_lock_modes(event: &mut KeyEvent, lock_modes: i32, key: Key) {
    const CAPS_LOCK: i32 = 1;
    const NUM_LOCK: i32 = 2;
    if is_letter_key(key) && lock_modes & (1 << CAPS_LOCK) != 0 {
        event.modifiers.push(ControlKey::CapsLock.into());
    }
    if is_numpad_key(key) && lock_modes & (1 << NUM_LOCK) != 0 {
        event.modifiers.push(ControlKey::NumLock.into());
    }
}

/// `is_numpad_rdev_key` (`src/keyboard.rs:795-814`).
fn is_numpad_key(key: Key) -> bool {
    matches!(
        key,
        Key::Kp0
            | Key::Kp1
            | Key::Kp2
            | Key::Kp3
            | Key::Kp4
            | Key::Kp5
            | Key::Kp6
            | Key::Kp7
            | Key::Kp8
            | Key::Kp9
            | Key::KpMinus
            | Key::KpMultiply
            | Key::KpDivide
            | Key::KpPlus
            | Key::KpDecimal
    )
}

/// `is_letter_rdev_key` plus `is_letter_rdev_key_ex` (`src/keyboard.rs:817-856`):
/// the keys whose character a Caps Lock changes.
fn is_letter_key(key: Key) -> bool {
    matches!(
        key,
        Key::KeyA
            | Key::KeyB
            | Key::KeyC
            | Key::KeyD
            | Key::KeyE
            | Key::KeyF
            | Key::KeyG
            | Key::KeyH
            | Key::KeyI
            | Key::KeyJ
            | Key::KeyK
            | Key::KeyL
            | Key::KeyM
            | Key::KeyN
            | Key::KeyO
            | Key::KeyP
            | Key::KeyQ
            | Key::KeyR
            | Key::KeyS
            | Key::KeyT
            | Key::KeyU
            | Key::KeyV
            | Key::KeyW
            | Key::KeyX
            | Key::KeyY
            | Key::KeyZ
            | Key::LeftBracket
            | Key::RightBracket
            | Key::SemiColon
            | Key::Quote
            | Key::Comma
            | Key::Dot
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // USB HID usages of the physical keys, as Flutter sends them and as rdev's
    // table (src/keycodes/usb_hid.rs) reads them.
    const KEY_A: i32 = 0x04;
    const KEY_C: i32 = 0x06;
    const DIGIT_1: i32 = 0x1E;
    const CAPS_LOCK: i32 = 0x39;
    const UP_ARROW: i32 = 0x52;
    const NUMPAD_1: i32 = 0x59;
    const CONTROL_LEFT: i32 = 0xE0;
    const SHIFT_LEFT: i32 = 0xE1;
    // A usage rdev's table does not name.
    const UNNAMED_HID: i32 = 0x0300;

    // Flutter's lock-mode bits (input_model.dart, _buildLockModes).
    const CAPS_LOCK_MODE: i32 = 1 << 1;
    const NUM_LOCK_MODE: i32 = 1 << 2;

    fn control(event: &KeyEvent) -> Option<ControlKey> {
        match event.union.as_ref() {
            Some(key_event::Union::ControlKey(key)) => key.enum_value().ok(),
            _ => None,
        }
    }

    fn chr(event: &KeyEvent) -> Option<u32> {
        match event.union.as_ref() {
            Some(key_event::Union::Chr(value)) => Some(*value),
            _ => None,
        }
    }

    fn modifiers(event: &KeyEvent) -> Vec<ControlKey> {
        event
            .modifiers
            .iter()
            .map(|key| key.enum_value().expect("a known control key"))
            .collect()
    }

    /// The one event a payload that must answer exactly one does answer.
    fn event(
        state: &mut KeyboardState,
        character: &str,
        usb_hid: i32,
        lock_modes: i32,
        down: bool,
    ) -> KeyEvent {
        state
            .flutter(character, usb_hid, lock_modes, down)
            .expect("a translated payload")
            .expect("one event")
    }

    #[test]
    fn an_arrow_key_up_matches_its_down() {
        let mut state = KeyboardState::default();
        let down = event(&mut state, "", UP_ARROW, 0, true);
        assert_eq!(down.mode, KeyboardMode::Legacy.into());
        assert_eq!(control(&down), Some(ControlKey::UpArrow));
        assert!(down.down && !down.press);
        let up = event(&mut state, "", UP_ARROW, 0, false);
        assert_eq!(control(&up), Some(ControlKey::UpArrow));
        assert!(!up.down && !up.press);
    }

    #[test]
    fn a_shifted_character_up_repeats_the_down_identity() {
        let mut state = KeyboardState::default();
        let shift = event(&mut state, "", SHIFT_LEFT, 0, true);
        assert_eq!(control(&shift), Some(ControlKey::Shift));
        assert!(
            modifiers(&shift).is_empty(),
            "an event that is the modifier does not repeat it"
        );
        let down = event(&mut state, "A", KEY_A, 0, true);
        assert_eq!(chr(&down), Some(u32::from('A')));
        assert_eq!(modifiers(&down), vec![ControlKey::Shift]);
        // The up carries no character, as Flutter's key-up events usually do.
        let up = event(&mut state, "", KEY_A, 0, false);
        assert_eq!(chr(&up), Some(u32::from('A')));
        assert!(!up.down);
    }

    #[test]
    fn a_character_up_without_a_down_still_names_its_key() {
        let mut state = KeyboardState::default();
        let up = event(&mut state, "", KEY_A, 0, false);
        assert_eq!(chr(&up), Some(u32::from('a')));
        assert!(!up.down);
    }

    #[test]
    fn a_release_keeps_the_state_its_down_was_sent_with() {
        let mut state = KeyboardState::default();
        event(&mut state, "", SHIFT_LEFT, 0, true);
        let down = event(&mut state, "!", DIGIT_1, 0, true);
        assert_eq!(chr(&down), Some(u32::from('!')));
        event(&mut state, "", SHIFT_LEFT, 0, false);
        let up = event(&mut state, "", DIGIT_1, 0, false);
        assert_eq!(
            chr(&up),
            Some(u32::from('!')),
            "the peer releases the key its down named"
        );
        assert_eq!(modifiers(&up), vec![ControlKey::Shift]);
        assert!(!up.down);
    }

    #[test]
    fn a_repeated_character_down_keeps_one_identity_for_the_up() {
        let mut state = KeyboardState::default();
        let down = event(&mut state, "a", KEY_A, 0, true);
        let repeat = event(&mut state, "a", KEY_A, 0, true);
        assert_eq!(down, repeat, "a character key's auto-repeat is a key event");
        let up = event(&mut state, "", KEY_A, 0, false);
        assert_eq!(chr(&up), Some(u32::from('a')));
        assert!(!up.down);
    }

    #[test]
    fn a_change_mid_hold_does_not_move_the_identity() {
        let mut state = KeyboardState::default();
        let down = event(&mut state, "a", KEY_A, 0, true);
        assert_eq!(chr(&down), Some(u32::from('a')));
        assert!(modifiers(&down).is_empty());
        // The modifier state, the character Flutter sends and the reported lock
        // state all change while the key is still held.
        event(&mut state, "", SHIFT_LEFT, 0, true);
        let repeat = event(&mut state, "A", KEY_A, CAPS_LOCK_MODE, true);
        assert_eq!(
            repeat, down,
            "a repeat re-sends the event the hold began with, so the peer and the \
             writer hold one identity"
        );
        event(&mut state, "", SHIFT_LEFT, 0, false);
        let released = event(&mut state, "", KEY_A, 0, false);
        let mut expected = down.clone();
        expected.down = false;
        assert_eq!(
            released, expected,
            "the release undoes exactly the event the hold began with"
        );
    }

    #[test]
    fn a_repeated_modifier_down_sends_nothing_and_the_up_still_lands() {
        let mut state = KeyboardState::default();
        let down = event(&mut state, "", SHIFT_LEFT, 0, true);
        assert_eq!(control(&down), Some(ControlKey::Shift));
        assert!(
            state
                .flutter("", SHIFT_LEFT, 0, true)
                .expect("a repeat of a held modifier")
                .is_none(),
            "upstream sends nothing for it"
        );
        let up = event(&mut state, "", SHIFT_LEFT, 0, false);
        assert_eq!(control(&up), Some(ControlKey::Shift));
        assert!(!up.down);
        // The key is not held any more, so a new press is a key event again.
        assert!(event(&mut state, "", SHIFT_LEFT, 0, true).down);
    }

    #[test]
    fn the_character_is_payload_and_three_bytes_of_it_are_not() {
        let mut state = KeyboardState::default();
        let shifted = event(&mut state, "!", DIGIT_1, 0, true);
        assert_eq!(chr(&shifted), Some(u32::from('!')));
        let composed = event(&mut state, "中", KEY_A, 0, true);
        assert_eq!(
            chr(&composed),
            Some(u32::from('a')),
            "upstream leaves a multi-byte character to the peer's own layout"
        );
    }

    #[test]
    fn an_unnamed_key_with_a_character_is_that_character_and_nothing_else_is() {
        let mut state = KeyboardState::default();
        let down = event(&mut state, "q", UNNAMED_HID, 0, true);
        assert_eq!(chr(&down), Some(u32::from('q')));
        let up = event(&mut state, "", UNNAMED_HID, 0, false);
        assert_eq!(chr(&up), Some(u32::from('q')), "its up repeats it");
        assert!(
            state.flutter("", UNNAMED_HID, 0, true).is_err(),
            "a key with neither a name nor a character is refused"
        );
        assert!(
            state.flutter("中", UNNAMED_HID, 0, true).is_err(),
            "a multi-byte character does not name a key"
        );
    }

    #[test]
    fn lock_modes_reach_letters_and_numpad_keys() {
        let mut state = KeyboardState::default();
        let letter = event(&mut state, "a", KEY_A, CAPS_LOCK_MODE, true);
        assert_eq!(modifiers(&letter), vec![ControlKey::CapsLock]);
        let arrow = event(&mut state, "", UP_ARROW, CAPS_LOCK_MODE, true);
        assert!(modifiers(&arrow).is_empty(), "an arrow is not a letter key");
        let numpad = event(&mut state, "", NUMPAD_1, NUM_LOCK_MODE, true);
        assert_eq!(modifiers(&numpad), vec![ControlKey::NumLock]);
    }

    #[test]
    fn a_lock_key_itself_is_no_key_event() {
        let mut state = KeyboardState::default();
        assert!(state
            .flutter("", CAPS_LOCK, 0, true)
            .expect("a lock key")
            .is_none());
        assert!(state
            .flutter("", CAPS_LOCK, 0, false)
            .expect("a lock key")
            .is_none());
    }

    #[test]
    fn the_tracked_modifier_state_reaches_the_keys_and_clears() {
        let mut state = KeyboardState::default();
        event(&mut state, "", CONTROL_LEFT, 0, true);
        let copy = event(&mut state, "c", KEY_C, 0, true);
        assert_eq!(modifiers(&copy), vec![ControlKey::Control]);
        event(&mut state, "", CONTROL_LEFT, 0, false);
        let plain = event(&mut state, "", UP_ARROW, 0, true);
        assert!(modifiers(&plain).is_empty(), "the control key was released");
        event(&mut state, "", CONTROL_LEFT, 0, true);
        state.clear();
        let fresh = event(&mut state, "", UP_ARROW, 0, false);
        assert!(
            modifiers(&fresh).is_empty(),
            "a new connection inherits no held modifier"
        );
    }

    #[test]
    fn a_flutter_special_key_is_a_control_key() {
        let mut state = KeyboardState::default();
        let mute = event(&mut state, "flutter_key", 0x007f, 0, true);
        assert_eq!(mute.mode, KeyboardMode::Legacy.into());
        assert_eq!(control(&mute), Some(ControlKey::VolumeMute));
        assert!(mute.down);
        let released = event(&mut state, "flutter_key", 0x007f, 0, false);
        assert!(!released.down);
        assert!(
            state.flutter("flutter_key", 0x0041, 0, true).is_err(),
            "only the codes Flutter defines are special keys"
        );
    }

    #[test]
    fn a_raw_event_without_platform_data_is_no_key_event() {
        let mut state = KeyboardState::default();
        assert!(state
            .raw("", -1, -1, 0, true)
            .expect("no platform data")
            .is_none());
        assert!(state
            .raw("", 0x41, -1, 0, true)
            .expect("half a code")
            .is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_raw_macos_position_code_names_the_key() {
        // kVK_UpArrow, the position code Flutter sends for that key on macOS.
        const MACOS_UP_ARROW: i32 = 126;
        let mut state = KeyboardState::default();
        let down = state
            .raw("", MACOS_UP_ARROW, MACOS_UP_ARROW, 0, true)
            .expect("raw arrow down")
            .expect("one event");
        assert_eq!(control(&down), Some(ControlKey::UpArrow));
        let up = state
            .raw("", MACOS_UP_ARROW, MACOS_UP_ARROW, 0, false)
            .expect("raw arrow up")
            .expect("one event");
        assert_eq!(control(&up), Some(ControlKey::UpArrow));
        assert!(!up.down);
    }
}
