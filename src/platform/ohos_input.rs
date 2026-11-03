//! HarmonyOS API 20+ dialog-authorized input injection for the host.
//!
//! This is an OHOS platform adaptation of the existing host lease/wire contract,
//! not a Unicode/IME or physical-scancode translator. Legacy control keys and
//! US-position printable ASCII are supported. Map/Translate/Auto, Unicode and
//! text sequences are refused. The OS still decides whether an event is delivered.
//!
//! All process injection and held-state changes are serialized. Only successful
//! DOWN/AXIS_BEGIN calls acquire a hold; only successful UP/AXIS_END calls retire
//! it. A failed checked release retains its obligation, including after Drop.
//! GetKeyState prevents claiming a key already reported down; it is not an atomic
//! physical-input observation guard, and cannot identify a later physical press.
use base::message_proto::{ControlKey, KeyEvent, KeyboardMode, MouseEvent, key_event};
use std::{collections::BTreeMap, ffi::c_void, sync::{
    LazyLock, Mutex, MutexGuard, atomic::{AtomicU64, Ordering},
}};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputError {
    InvalidInput,
    Unsupported,
    DesktopUnavailable,
    OutputChanged,
    InjectionFailed,
    ReclamationUnconfirmed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InjectionStatus {
    Unauthorized,
    Authorizing,
    Authorized,
    Unsupported,
    Failed(i32),
}

pub struct AuthorizationAnswer {
    /// SDK RequestInjection result verbatim, or -1 when the engine's retained/
    /// poisoned owner refused to call the SDK at all.
    pub result_code: i32,
    pub status: InjectionStatus,
    /// Explicit process request owner, never a Host run/peer/input-generation ID.
    pub request_id: Option<u64>,
}

// Values and signatures from multimodalinput/oh_input_manager.h (API 20+).
const SUCCESS: i32 = 0;
const KEY_DOWN: i32 = 1;
const KEY_UP: i32 = 2;
const MOUSE_MOVE: i32 = 1;
const BUTTON_DOWN: i32 = 2;
const BUTTON_UP: i32 = 3;
const AXIS_BEGIN: i32 = 4;
const AXIS_END: i32 = 6;
const SHIFT_LEFT: i32 = 2047;
const MAX_KEYS: usize = 5;
const MAX_WHEEL_NOTCHES: i32 = 255;

#[link(name = "ohinput")]
unsafe extern "C" {
    fn OH_Input_RequestInjection(callback: extern "C" fn(i32)) -> i32;
    fn OH_Input_QueryAuthorizedStatus(status: *mut i32) -> i32;
    fn OH_Input_CancelInjection();
    fn OH_Input_CreateKeyState() -> *mut c_void;
    fn OH_Input_DestroyKeyState(state: *mut *mut c_void);
    fn OH_Input_SetKeyCode(state: *mut c_void, code: i32);
    fn OH_Input_GetKeyState(state: *mut c_void) -> i32;
    fn OH_Input_GetKeyPressed(state: *const c_void) -> i32;
    fn OH_Input_CreateKeyEvent() -> *mut c_void;
    fn OH_Input_DestroyKeyEvent(event: *mut *mut c_void);
    fn OH_Input_SetKeyEventAction(event: *mut c_void, action: i32);
    fn OH_Input_SetKeyEventKeyCode(event: *mut c_void, code: i32);
    fn OH_Input_SetKeyEventDisplayId(event: *mut c_void, display: i32);
    fn OH_Input_InjectKeyEvent(event: *const c_void) -> i32;
    fn OH_Input_CreateMouseEvent() -> *mut c_void;
    fn OH_Input_DestroyMouseEvent(event: *mut *mut c_void);
    fn OH_Input_SetMouseEventAction(event: *mut c_void, action: i32);
    fn OH_Input_SetMouseEventDisplayId(event: *mut c_void, display: i32);
    fn OH_Input_SetMouseEventDisplayX(event: *mut c_void, x: i32);
    fn OH_Input_SetMouseEventDisplayY(event: *mut c_void, y: i32);
    fn OH_Input_SetMouseEventButton(event: *mut c_void, button: i32);
    fn OH_Input_SetMouseEventAxisType(event: *mut c_void, axis: i32);
    fn OH_Input_SetMouseEventAxisValue(event: *mut c_void, value: f32);
    fn OH_Input_InjectMouseEvent(event: *const c_void) -> i32;
}

#[link(name = "native_display_manager")]
unsafe extern "C" {
    fn OH_NativeDisplayManager_GetDefaultDisplayId(id: *mut u64) -> i32;
    fn OH_NativeDisplayManager_GetDefaultDisplayWidth(width: *mut i32) -> i32;
    fn OH_NativeDisplayManager_GetDefaultDisplayHeight(height: *mut i32) -> i32;
}

// Only an explicit request may establish a new epoch. Callback/query observations
// may invalidate an epoch, but AUTHORIZED can never revive an old one. Saturation
// is terminal rather than wrapping back to an old capability.
static AUTH_EPOCH: AtomicU64 = AtomicU64::new(0);
fn invalidate_authorization() {
    let _ = AUTH_EPOCH.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |epoch| Some(epoch.saturating_add(1)));
}

// Process-lifetime C callback: no ArkTS environment, host, peer or mutex. The SDK
// can call synchronously while RequestInjection holds HOLDS. A late restrictive
// callback can only close old admission; a late authorized callback grants none.
extern "C" fn authorization_answer(status: i32) {
    if status != 2 { invalidate_authorization(); }
}

fn query_authorization() -> (i32, InjectionStatus) {
    let mut status = -1;
    let result = unsafe { OH_Input_QueryAuthorizedStatus(&mut status) };
    let status = match (result, status) {
        (SUCCESS, 0) => InjectionStatus::Unauthorized,
        (SUCCESS, 1) => InjectionStatus::Authorizing,
        (SUCCESS, 2) => InjectionStatus::Authorized,
        (801, _) => InjectionStatus::Unsupported,
        (SUCCESS, _) => InjectionStatus::Failed(-1),
        (code, _) => InjectionStatus::Failed(code),
    };
    if status != InjectionStatus::Authorized { invalidate_authorization(); }
    (result, status)
}

/// The SDK's current dialog fact. AUTHORIZED alone does not create an engine
/// request owner and cannot authorize a Host whose original token was retired.
pub fn injection_status() -> InjectionStatus {
    authorization_status().status
}

pub fn authorization_status() -> AuthorizationAnswer {
    let Ok(mut registry) = holds() else { return owner_unavailable(); };
    query_request(&mut registry)
}

fn query_request(registry: &mut Holds) -> AuthorizationAnswer {
    let before = AUTH_EPOCH.load(Ordering::Acquire);
    let (result_code, status) = query_authorization();
    if registry.request.is_some() && status == InjectionStatus::Authorized {
        // Initial AUTHORIZING may advance epochs while the dialog is pending.
        // Pin its FIRST observed grant only. A later restrictive callback/query
        // must not let an unbound old PendingStart adopt a new epoch with this ID.
        registry.request_authorization.get_or_insert(before);
    }
    let current = AUTH_EPOCH.load(Ordering::Acquire);
    let valid = !registry.quarantined && current != u64::MAX
        && registry.request_authorization.is_none_or(|granted| granted == current);
    AuthorizationAnswer { result_code, status,
        request_id: if valid { registry.request } else { None } }
}

fn owner_unavailable() -> AuthorizationAnswer {
    AuthorizationAnswer { result_code: -1, status: InjectionStatus::Failed(-1), request_id: None }
}

pub fn request_injection() -> AuthorizationAnswer {
    // Serialize against the final run's cancellation and against injection. The
    // callback does not acquire this mutex (the SDK may call it synchronously).
    let Ok(mut registry) = holds() else {
        return owner_unavailable();
    };
    if registry.quarantined || registry.runs != 0 {
        // A pre-run request cannot supersede an authorization already borrowed
        // by a live Host. Its caller receives no token from that older owner.
        return owner_unavailable();
    }
    let Some(request_id) = registry.next_request.checked_add(1) else { return owner_unavailable(); };
    registry.next_request = request_id;
    // Even an unsuccessful/already-authorized request must not silently move a
    // pre-existing Host or peer into the request's new authorization lifetime.
    invalidate_authorization();
    registry.request = None;
    registry.request_authorization = None;
    let result_code = unsafe { OH_Input_RequestInjection(authorization_answer) };
    if matches!(result_code, SUCCESS | 3900005 | 3900007) {
        registry.request = Some(request_id);
    }
    let answer = if result_code == 801 {
        AuthorizationAnswer { result_code, status: InjectionStatus::Unsupported, request_id: None }
    } else {
        query_request(&mut registry)
    };
    AuthorizationAnswer { result_code, ..answer }
}

/// Pre-run cancellation, fenced by the exact explicit request. Stale requests
/// and requests already borrowed by a live Host cannot cancel process input.
/// CancelInjection is void: result_code below is the subsequent Query result,
/// and only status=Unauthorized confirms the fact observed after cancellation.
pub fn cancel_injection_request(request_id: u64) -> Result<AuthorizationAnswer, InputError> {
    let mut registry = holds()?;
    if registry.request != Some(request_id) { return Err(InputError::InvalidInput); }
    if registry.runs != 0 || !registry.empty() { return Err(InputError::Unsupported); }
    if registry.quarantined { return Err(InputError::ReclamationUnconfirmed); }
    Ok(cancel_locked(&mut registry))
}

fn require_authorized(registry: &Holds) -> Result<(), InputError> {
    match query_authorization().1 {
        InjectionStatus::Authorized
            if registry.request_authorization == Some(AUTH_EPOCH.load(Ordering::Acquire)) => Ok(()),
        InjectionStatus::Unsupported => Err(InputError::Unsupported),
        _ => Err(InputError::DesktopUnavailable),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetBinding {
    display: i32,
    width: i32,
    height: i32,
    authorization: u64,
    request_id: u64,
}
impl TargetBinding {
    /// Bind only the real default display at the exact published geometry. The
    /// publisher's enumeration index is deliberately not used as an SDK ID.
    pub fn bind_default(width: i32, height: i32) -> Result<Self, InputError> {
        if width <= 0 || height <= 0 { return Err(InputError::InvalidInput); }
        let mut registry = holds()?;
        if registry.quarantined { return Err(InputError::ReclamationUnconfirmed); }
        let answer = query_request(&mut registry);
        let request_id = answer.request_id
            .filter(|_| answer.status == InjectionStatus::Authorized)
            .ok_or(InputError::DesktopUnavailable)?;
        let binding = Self::current(request_id)?;
        if registry.request_authorization != Some(binding.authorization) {
            return Err(InputError::DesktopUnavailable);
        }
        if binding.width != width || binding.height != height {
            return Err(InputError::OutputChanged);
        }
        Ok(binding)
    }

    fn current(request_id: u64) -> Result<Self, InputError> {
        let (mut display, mut width, mut height) = (0, 0, 0);
        unsafe {
            if OH_NativeDisplayManager_GetDefaultDisplayId(&mut display) != SUCCESS
                || OH_NativeDisplayManager_GetDefaultDisplayWidth(&mut width) != SUCCESS
                || OH_NativeDisplayManager_GetDefaultDisplayHeight(&mut height) != SUCCESS
            { return Err(InputError::DesktopUnavailable); }
        }
        let display = i32::try_from(display).map_err(|_| InputError::Unsupported)?;
        if width <= 0 || height <= 0 { return Err(InputError::DesktopUnavailable); }
        let authorization = AUTH_EPOCH.load(Ordering::Acquire);
        if authorization == u64::MAX { return Err(InputError::ReclamationUnconfirmed); }
        Ok(Self { display, width, height, authorization, request_id })
    }

    fn verify_current(&self, registry: &Holds) -> Result<(), InputError> {
        if registry.request != Some(self.request_id) { return Err(InputError::DesktopUnavailable); }
        if Self::current(self.request_id)? != *self { return Err(InputError::OutputChanged); }
        Ok(())
    }

    fn point(&self, x: i32, y: i32) -> Result<(i32, i32), InputError> {
        if !(0..self.width).contains(&x) || !(0..self.height).contains(&y) {
            return Err(InputError::InvalidInput);
        }
        Ok((x, y))
    }
}

#[derive(Default)]
struct Holds {
    next_lease: u64,
    next_request: u64,
    request: Option<u64>,
    // The first real Authorized observation for this request. Never re-pinned
    // after revocation/query failure; retain request itself only for exact cancel.
    request_authorization: Option<u64>,
    keys: BTreeMap<i32, u64>,
    buttons: BTreeMap<i32, u64>,
    // The SDK permits only one axis sequence in progress, not one per axis.
    axis: Option<(i32, u64)>,
    runs: usize,
    // Latest epoch that a real Host run actually admitted. A retiring old run
    // must not cancel a newer explicit dialog request that has no Host yet.
    run_authorization: Option<u64>,
    quarantined: bool,
}
impl Holds {
    fn empty(&self) -> bool { self.keys.is_empty() && self.buttons.is_empty() && self.axis.is_none() }
    fn owns(&self, lease: u64) -> bool {
        self.keys.values().chain(self.buttons.values()).any(|owner| *owner == lease)
            || self.axis.is_some_and(|(_, owner)| owner == lease)
    }
}
static HOLDS: LazyLock<Mutex<Holds>> = LazyLock::new(|| Mutex::new(Holds::default()));
fn holds() -> Result<MutexGuard<'static, Holds>, InputError> {
    HOLDS.lock().map_err(|_| InputError::ReclamationUnconfirmed)
}

fn cancel_locked(registry: &mut Holds) -> AuthorizationAnswer {
    // Retire admission BEFORE touching the SDK. A late AUTHORIZED callback can
    // report OS state but never restore this request owner.
    registry.request = None;
    registry.request_authorization = None;
    invalidate_authorization();
    unsafe { OH_Input_CancelInjection(); }
    let (result_code, status) = query_authorization();
    AuthorizationAnswer { result_code, status, request_id: None }
}

fn revoke_locked(registry: &mut Holds) -> Result<(), InputError> {
    if !registry.empty() || registry.runs != 0 || registry.quarantined {
        return Err(InputError::ReclamationUnconfirmed);
    }
    // Cancel is authorization revocation, NOT a substitute for key/button UP or
    // AXIS_END. Nothing may be erased from HOLDS on account of this void call.
    match cancel_locked(registry).status {
        InjectionStatus::Unauthorized => Ok(()),
        _ => Err(InputError::InjectionFailed),
    }
}
pub(crate) fn revoke_injection() -> Result<(), InputError> {
    let mut registry = holds()?;
    revoke_locked(&mut registry)
}

/// One Host run's share of the process authorization. A run consumes this
/// only after its checked native finish. Another live run, even with no holds,
/// must not lose authorization to this run's stop.
pub(crate) struct InputRun { live: bool, authorization: u64, request_id: u64 }
impl InputRun {
    pub(crate) fn open(binding: &TargetBinding, expected_request: Option<u64>) -> Result<Self, InputError> {
        let mut registry = holds()?;
        if registry.quarantined { return Err(InputError::ReclamationUnconfirmed); }
        require_authorized(&registry)?;
        // The start probe and every later peer use this same frozen binding.
        // A request between the probe and registration must refuse the start,
        // not attach its old binding to a new authorization lifetime.
        binding.verify_current(&registry)?;
        if expected_request.is_some_and(|expected| expected != binding.request_id) {
            return Err(InputError::InvalidInput);
        }
        registry.runs = registry.runs.checked_add(1).ok_or(InputError::InjectionFailed)?;
        registry.run_authorization = Some(binding.authorization);
        Ok(Self { live: true, authorization: binding.authorization, request_id: binding.request_id })
    }
    pub(crate) fn is_current(&self) -> bool {
        let Ok(registry) = holds() else { return false; };
        !registry.quarantined && require_authorized(&registry).is_ok()
            && registry.request == Some(self.request_id)
            && self.authorization == AUTH_EPOCH.load(Ordering::Acquire)
    }
    pub(crate) fn quarantine(&self) {
        if let Ok(mut registry) = holds() { registry.quarantined = true; }
    }
    pub(crate) fn close(mut self) -> Result<(), InputError> {
        let mut registry = holds()?;
        if registry.quarantined || registry.runs == 0 {
            return Err(InputError::ReclamationUnconfirmed);
        }
        if registry.runs == 1 && !registry.empty() {
            return Err(InputError::ReclamationUnconfirmed);
        }
        registry.runs -= 1;
        // This owner was consumed, even if the SDK cannot confirm revocation.
        self.live = false;
        if registry.runs == 0 {
            let owns_current = registry.run_authorization.take() == Some(AUTH_EPOCH.load(Ordering::Acquire));
            if owns_current && let Err(error) = revoke_locked(&mut registry) {
                registry.quarantined = true;
                return Err(error);
            }
        }
        Ok(())
    }
}
impl Drop for InputRun {
    fn drop(&mut self) {
        if self.live {
            // An unjoined run cannot revoke another owner's authorization or
            // be silently removed from the process ownership count.
            self.quarantine();
        }
    }
}

pub struct InputSession {
    binding: TargetBinding,
    lease: u64,
    position: Option<(i32, i32)>,
    trackpad: [i32; 2],
    release_pending: bool,
}
impl InputSession {
    pub fn open(binding: TargetBinding) -> Result<Self, InputError> {
        let mut registry = holds()?;
        if registry.quarantined { return Err(InputError::ReclamationUnconfirmed); }
        require_authorized(&registry)?;
        binding.verify_current(&registry)?;
        registry.next_lease = registry.next_lease.checked_add(1).ok_or(InputError::InjectionFailed)?;
        Ok(Self { binding, lease: registry.next_lease, position: None, trackpad: [0; 2], release_pending: false })
    }

    fn authorized(&self, registry: &Holds) -> Result<(), InputError> {
        if registry.quarantined || self.release_pending { return Err(InputError::ReclamationUnconfirmed); }
        require_authorized(&registry)?;
        if registry.request != Some(self.binding.request_id)
            || self.binding.authorization != AUTH_EPOCH.load(Ordering::Acquire) {
            return Err(InputError::DesktopUnavailable);
        }
        Ok(())
    }

    fn ready(&self, registry: &Holds) -> Result<(), InputError> {
        self.authorized(registry)?;
        self.binding.verify_current(registry)
    }

    pub fn mouse(&mut self, event: &MouseEvent) -> Result<(), InputError> {
        let mask = u32::try_from(event.mask).map_err(|_| InputError::InvalidInput)?;
        if mask & !0xff != 0 { return Err(InputError::InvalidInput); }
        let kind = mask & 7;
        let button_bits = mask >> 3;
        if (3..=5).contains(&kind) && button_bits != 0 { return Err(InputError::InvalidInput); }
        if kind == 5 {
            return if (event.x, event.y) == (0, 0) { Ok(()) } else { Err(InputError::Unsupported) };
        }
        let mut registry = holds()?;
        match kind {
            0 => {
                let point = self.binding.point(event.x, event.y)?;
                self.ready(&registry)?;
                inject_mouse(&self.binding, point, MOUSE_MOVE, -1, None)?;
                self.position = Some(point);
                Ok(())
            }
            1 | 2 => {
                let button = match button_bits {
                    1 => 0, 2 => 2, 4 => 1, 8 => 4, 16 => 3,
                    _ => return Err(InputError::InvalidInput),
                };
                // Validate the declaration, but never warp to it on a transition.
                self.binding.point(event.x, event.y)?;
                let point = self.position.ok_or(InputError::Unsupported)?;
                if kind == 1 {
                    self.ready(&registry)?;
                    if registry.buttons.contains_key(&button) { return Err(InputError::Unsupported); }
                    inject_mouse(&self.binding, point, BUTTON_DOWN, button, None)?;
                    registry.buttons.insert(button, self.lease);
                    Ok(())
                } else {
                    self.authorized(&registry)?;
                    if registry.buttons.get(&button) != Some(&self.lease) { return Err(InputError::Unsupported); }
                    if inject_mouse(&self.binding, point, BUTTON_UP, button, None).is_err() {
                        self.release_pending = true;
                        return Err(InputError::ReclamationUnconfirmed);
                    }
                    registry.buttons.remove(&button);
                    Ok(())
                }
            }
            3 | 4 => {
                if event.x == 0 && event.y == 0 { return Err(InputError::InvalidInput); }
                let limit = MAX_WHEEL_NOTCHES * if kind == 4 { 8 } else { 1 };
                if event.x.unsigned_abs() > limit as u32 || event.y.unsigned_abs() > limit as u32 {
                    return Err(InputError::InvalidInput);
                }
                self.ready(&registry)?;
                let point = self.position.ok_or(InputError::Unsupported)?;
                if registry.axis.is_some() { return Err(InputError::Unsupported); }
                let mut deltas = [event.x, event.y];
                if kind == 4 {
                    for (axis, delta) in deltas.iter_mut().enumerate() {
                        let total = self.trackpad[axis] + *delta;
                        self.trackpad[axis] = total % 8;
                        *delta = total / 8;
                    }
                }
                for (index, delta) in deltas.into_iter().enumerate() {
                    if delta == 0 { continue; }
                    // SDK vertical=0, horizontal=1. Wire negative y is up;
                    // horizontal positive x is right. SDK positive is forward.
                    // One notch is sent as one axis unit; device calibration is
                    // still required (this is not a pixel-distance guarantee).
                    let (axis, value) = if index == 0 { (1, delta as f32) } else { (0, -(delta as f32)) };
                    inject_mouse(&self.binding, point, AXIS_BEGIN, -1, Some((axis, value)))?;
                    registry.axis = Some((axis, self.lease));
                    if inject_mouse(&self.binding, point, AXIS_END, -1, Some((axis, 0.0))).is_err() {
                        self.release_pending = true;
                        return Err(InputError::ReclamationUnconfirmed);
                    }
                    registry.axis = None;
                }
                Ok(())
            }
            _ => Err(InputError::InvalidInput),
        }
    }

    pub fn key(&mut self, event: &KeyEvent) -> Result<(), InputError> {
        if event.mode.enum_value() != Ok(KeyboardMode::Legacy) { return Err(InputError::Unsupported); }
        if event.press && event.down { return Err(InputError::InvalidInput); }
        let (code, shift) = match &event.union {
            Some(key_event::Union::ControlKey(key)) => (
                control_code(key.enum_value().map_err(|_| InputError::Unsupported)?).ok_or(InputError::Unsupported)?, false),
            Some(key_event::Union::Chr(value)) => ascii_key(*value)?,
            None => return Err(InputError::InvalidInput),
            _ => return Err(InputError::Unsupported),
        };
        let mut required = Vec::new();
        for modifier in &event.modifiers {
            let key = modifier.enum_value().map_err(|_| InputError::Unsupported)?;
            if !matches!(key, ControlKey::Alt | ControlKey::Option | ControlKey::Menu | ControlKey::RAlt
                | ControlKey::Shift | ControlKey::RShift | ControlKey::Control | ControlKey::RControl
                | ControlKey::Meta | ControlKey::RWin) { return Err(InputError::Unsupported); }
            let modifier = control_code(key).ok_or(InputError::Unsupported)?;
            if modifier != code && !required.contains(&modifier) { required.push(modifier); }
        }
        if shift && code != SHIFT_LEFT && !required.contains(&SHIFT_LEFT) { required.push(SHIFT_LEFT); }
        let mut registry = holds()?;
        if !event.down && !event.press {
            // Up does not synthesize modifiers or require the old geometry to
            // remain current, but a stale peer event cannot enter a new dialog
            // lifetime. Checked close can still release its original holds.
            self.authorized(&registry)?;
            return self.key_up(&mut registry, code);
        }
        self.ready(&registry)?;
        if registry.keys.contains_key(&code) { return Err(InputError::Unsupported); }
        let mut transient = Vec::new();
        for modifier in required {
            match registry.keys.get(&modifier) {
                Some(owner) if *owner == self.lease => {},
                Some(_) => return Err(InputError::Unsupported),
                None => { key_is_released(modifier)?; transient.push(modifier); }
            }
        }
        key_is_released(code)?;
        if registry.keys.len() + transient.len() + 1 > MAX_KEYS { return Err(InputError::Unsupported); }
        let mut pressed = Vec::new();
        let result = (|| {
            for &modifier in &transient {
                inject_key(&self.binding, modifier, KEY_DOWN)?;
                registry.keys.insert(modifier, self.lease);
                pressed.push(modifier);
            }
            inject_key(&self.binding, code, KEY_DOWN)?;
            registry.keys.insert(code, self.lease);
            if event.press { self.key_up(&mut registry, code)?; }
            Ok(())
        })();
        let mut released = true;
        for modifier in pressed.into_iter().rev() {
            released &= self.key_up(&mut registry, modifier).is_ok();
        }
        if !released { return Err(InputError::ReclamationUnconfirmed); }
        result
    }

    fn key_up(&mut self, registry: &mut Holds, code: i32) -> Result<(), InputError> {
        if registry.keys.get(&code) != Some(&self.lease) { return Err(InputError::Unsupported); }
        if inject_key(&self.binding, code, KEY_UP).is_err() {
            self.release_pending = true;
            return Err(InputError::ReclamationUnconfirmed);
        }
        registry.keys.remove(&code);
        Ok(())
    }

    pub fn release_all(&mut self) -> Result<(), InputError> {
        let mut registry = holds()?;
        // No topology/authorization precheck may hide an owed UP/END. The SDK's
        // actual result decides; even permission revocation cannot clear a hold.
        let keys: Vec<_> = registry.keys.iter().filter_map(|(&code, &owner)| (owner == self.lease).then_some(code)).collect();
        for code in keys { let _ = self.key_up(&mut registry, code); }
        let buttons: Vec<_> = registry.buttons.iter().filter_map(|(&button, &owner)| (owner == self.lease).then_some(button)).collect();
        for button in buttons {
            if let Some(point) = self.position {
                if inject_mouse(&self.binding, point, BUTTON_UP, button, None).is_ok() {
                    registry.buttons.remove(&button);
                }
            }
        }
        if let Some((axis, owner)) = registry.axis {
            if owner == self.lease {
                if let Some(point) = self.position {
                    if inject_mouse(&self.binding, point, AXIS_END, -1, Some((axis, 0.0))).is_ok() {
                        registry.axis = None;
                    }
                }
            }
        }
        if registry.owns(self.lease) {
            self.release_pending = true;
            Err(InputError::ReclamationUnconfirmed)
        } else {
            self.release_pending = false;
            self.trackpad = [0; 2];
            Ok(())
        }
    }
}
impl Drop for InputSession {
    fn drop(&mut self) {
        if self.release_all().is_err() {
            // The global records outlive this object. They are never reassigned
            // to the next peer just because its original owner was dropped.
            if let Ok(mut registry) = holds() { registry.quarantined = true; }
        }
    }
}

fn sdk_result(result: i32) -> Result<(), InputError> {
    match result {
        SUCCESS => Ok(()),
        401 => Err(InputError::InvalidInput),
        801 => Err(InputError::Unsupported),
        201 | 202 => Err(InputError::DesktopUnavailable),
        _ => Err(InputError::InjectionFailed),
    }
}

fn key_is_released(code: i32) -> Result<(), InputError> {
    unsafe {
        let mut state = OH_Input_CreateKeyState();
        if state.is_null() { return Err(InputError::InjectionFailed); }
        OH_Input_SetKeyCode(state, code);
        let result = OH_Input_GetKeyState(state);
        let pressed = OH_Input_GetKeyPressed(state);
        OH_Input_DestroyKeyState(&mut state);
        sdk_result(result)?;
        // KEY_RELEASED=1. Unknown/default is not evidence of a released key.
        if pressed != 1 { return Err(InputError::Unsupported); }
        Ok(())
    }
}

fn inject_key(binding: &TargetBinding, code: i32, action: i32) -> Result<(), InputError> {
    unsafe {
        let mut event = OH_Input_CreateKeyEvent();
        if event.is_null() { return Err(InputError::InjectionFailed); }
        OH_Input_SetKeyEventDisplayId(event, binding.display);
        OH_Input_SetKeyEventAction(event, action);
        OH_Input_SetKeyEventKeyCode(event, code);
        let result = OH_Input_InjectKeyEvent(event);
        OH_Input_DestroyKeyEvent(&mut event);
        sdk_result(result)
    }
}

fn inject_mouse(binding: &TargetBinding, point: (i32, i32), action: i32,
    button: i32, axis: Option<(i32, f32)>) -> Result<(), InputError> {
    unsafe {
        let mut event = OH_Input_CreateMouseEvent();
        if event.is_null() { return Err(InputError::InjectionFailed); }
        OH_Input_SetMouseEventDisplayId(event, binding.display);
        OH_Input_SetMouseEventDisplayX(event, point.0);
        OH_Input_SetMouseEventDisplayY(event, point.1);
        OH_Input_SetMouseEventAction(event, action);
        OH_Input_SetMouseEventButton(event, button);
        if let Some((axis, value)) = axis {
            OH_Input_SetMouseEventAxisType(event, axis);
            OH_Input_SetMouseEventAxisValue(event, value);
        }
        let result = OH_Input_InjectMouseEvent(event);
        OH_Input_DestroyMouseEvent(&mut event);
        sdk_result(result)
    }
}

// multimodalinput/oh_key_code.h: position keys, not Unicode code points. These
// mappings intentionally do not include secure-attention, screen lock or power.
fn control_code(key: ControlKey) -> Option<i32> {
    Some(match key {
        ControlKey::Alt | ControlKey::Option | ControlKey::Menu => 2045,
        ControlKey::RAlt => 2046,
        ControlKey::Shift => SHIFT_LEFT,
        ControlKey::RShift => 2048,
        ControlKey::Control => 2072,
        ControlKey::RControl => 2073,
        ControlKey::Meta => 2076,
        ControlKey::RWin => 2077,
        ControlKey::Backspace => 2055,
        ControlKey::CapsLock => 2074,
        ControlKey::Delete => 2071,
        ControlKey::DownArrow => 2013,
        ControlKey::End => 2082,
        ControlKey::Escape => 2070,
        ControlKey::F1 => 2090,
        ControlKey::F2 => 2091,
        ControlKey::F3 => 2092,
        ControlKey::F4 => 2093,
        ControlKey::F5 => 2094,
        ControlKey::F6 => 2095,
        ControlKey::F7 => 2096,
        ControlKey::F8 => 2097,
        ControlKey::F9 => 2098,
        ControlKey::F10 => 2099,
        ControlKey::F11 => 2100,
        ControlKey::F12 => 2101,
        ControlKey::Home => 2081,
        ControlKey::LeftArrow => 2014,
        ControlKey::PageDown => 2069,
        ControlKey::PageUp => 2068,
        ControlKey::Return => 2054,
        ControlKey::RightArrow => 2015,
        ControlKey::Space => 2050,
        ControlKey::Tab => 2049,
        ControlKey::UpArrow => 2012,
        ControlKey::Numpad0 => 2103,
        ControlKey::Numpad1 => 2104,
        ControlKey::Numpad2 => 2105,
        ControlKey::Numpad3 => 2106,
        ControlKey::Numpad4 => 2107,
        ControlKey::Numpad5 => 2108,
        ControlKey::Numpad6 => 2109,
        ControlKey::Numpad7 => 2110,
        ControlKey::Numpad8 => 2111,
        ControlKey::Numpad9 => 2112,
        ControlKey::Pause => 2080,
        ControlKey::Print | ControlKey::Snapshot => 2079,
        ControlKey::Insert => 2083,
        ControlKey::Separator => 2118,
        ControlKey::Scroll => 2075,
        ControlKey::NumLock => 2102,
        ControlKey::Apps => 2067,
        ControlKey::Multiply => 2114,
        ControlKey::Add => 2116,
        ControlKey::Subtract => 2115,
        ControlKey::Decimal => 2117,
        ControlKey::Divide => 2113,
        ControlKey::Equals => 2058,
        ControlKey::NumpadEnter => 2119,
        ControlKey::VolumeMute => 22,
        ControlKey::VolumeUp => 16,
        ControlKey::VolumeDown => 17,
        _ => return None,
    })
}

fn ascii_key(value: u32) -> Result<(i32, bool), InputError> {
    if !(0x20..=0x7e).contains(&value) { return Err(InputError::Unsupported); }
    let character = value as u8;
    let (code, shift) = match character {
        b'a'..=b'z' => (2017 + i32::from(character - b'a'), false),
        b'A'..=b'Z' => (2017 + i32::from(character - b'A'), true),
        b'0'..=b'9' => (2000 + i32::from(character - b'0'), false),
        b' ' => (2050, false),
        b',' | b'<' => (2043, character == b'<'),
        b'.' | b'>' => (2044, character == b'>'),
        b'`' | b'~' => (2056, character == b'~'),
        b'-' | b'_' => (2057, character == b'_'),
        b'=' | b'+' => (2058, character == b'+'),
        b'[' | b'{' => (2059, character == b'{'),
        b']' | b'}' => (2060, character == b'}'),
        b'\\' | b'|' => (2061, character == b'|'),
        b';' | b':' => (2062, character == b':'),
        b'\'' | b'"' => (2063, character == b'"'),
        b'/' | b'?' => (2064, character == b'?'),
        b'!' => (2001, true), b'@' => (2002, true), b'#' => (2003, true),
        b'$' => (2004, true), b'%' => (2005, true), b'^' => (2006, true),
        b'&' => (2007, true), b'*' => (2008, true), b'(' => (2009, true), b')' => (2000, true),
        _ => return Err(InputError::Unsupported),
    };
    Ok((code, shift))
}
