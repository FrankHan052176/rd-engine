//! Native ArkUI Surface ownership, deliberately separate from NAPI exports.
//!
//! The three wrappers in lib.rs must forward the real FrameNode/callback handles
//! on their owning UI environment thread. `attach` returns an opaque, never
//! reused componentId; the UI's node id is only a label, never a Surface id.
//! sessionBindSurface must use `borrow_surface`, not construct a lease from a
//! string. Keep SurfaceBorrow through confirmed Viewer reclamation, and call
//! watch_viewer immediately after Viewer::start (including its error handling).
//!
//! SDK signatures checked in the installed DevEco SDK's sysroot/usr/include:
//! arkui/native_node_napi.h: OH_ArkUI_GetNodeHandleFromNapiValue (API 12);
//! arkui/native_node.h: OH_ArkUI_NodeUtils_GetNodeUniqueId (API 20);
//! ace/xcomponent/native_interface_xcomponent.h: SurfaceHolder/manual lifecycle
//! (API 19), ArkUI frame callback/range functions (API 20);
//! native_window/external_window.h: reference/unreference (8), GetSurfaceId (12);
//! node_api.h, node_api_types.h, js_native_api.h: Node-API TSFN and references.
//! These bindings require API 20+, not a feature/dependency upgrade to napi-ohos
//! 1.2.0 in this workspace's lockfile. No native video data enters the TSFN.
use napi_ohos::Env;
use rd_engine::viewer::{SurfaceLease, Viewer};
use std::{
    ffi::c_void,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, Weak,
    },
};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct Retirement {
    ready: AtomicBool,
    viewer: Mutex<Weak<Viewer>>,
}

impl Retirement {
    fn new() -> Self {
        Self {
            ready: AtomicBool::new(true),
            viewer: Mutex::new(Weak::new()),
        }
    }

    fn request(&self) {
        let viewer = {
            // Same lock as watch_viewer: destruction cannot miss a viewer that
            // is being installed after a native start returned.
            let slot = lock(&self.viewer);
            self.ready.store(false, Ordering::Release);
            slot.upgrade()
        };
        if let Some(viewer) = viewer {
            viewer.request_close();
        }
    }
}

/// One actual session binding. Cloning lease() extends the native loan; neither
/// dropping this wrapper nor dropping its last clone performs UI SDK work on a
/// decoder worker. The registry retains the holder until a UI detach succeeds.
pub(super) struct SurfaceBorrow {
    pub(super) token: u64,
    pub(super) surface_id: u64,
    lease: Arc<dyn SurfaceLease>,
    retirement: Arc<Retirement>,
}

impl SurfaceBorrow {
    pub(super) fn lease(&self) -> Arc<dyn SurfaceLease> {
        self.lease.clone()
    }

    /// No JS callback is involved in native retirement. A start racing destroy
    /// is closed here even if the destruction happened before start returned.
    /// An error still requires the caller to await that Viewer's reclamation.
    pub(super) fn watch_viewer(&self, viewer: &Arc<Viewer>) -> Result<(), String> {
        let result = {
            let mut slot = lock(&self.retirement.viewer);
            if slot.upgrade().is_some_and(|old| !Arc::ptr_eq(&old, viewer)) {
                Err("this Surface loan already belongs to another Viewer".to_string())
            } else {
                *slot = Arc::downgrade(viewer);
                if self.retirement.ready.load(Ordering::Acquire) {
                    Ok(())
                } else {
                    Err("Surface retirement preceded Viewer registration".to_string())
                }
            }
        };
        if result.is_err() {
            viewer.request_close();
        }
        result
    }
}

/// # Safety
/// frame_node and event_callback must be live napi_value handles from env, used
/// on the ArkUI/UI environment thread. lib.rs owns typed NAPI argument checking.
pub(super) unsafe fn attach(
    env: Env,
    node_id: String,
    frame_node: *mut c_void,
    event_callback: *mut c_void,
) -> String {
    #[cfg(target_env = "ohos")]
    return unsafe { ohos::attach(env, node_id, frame_node, event_callback) };
    #[cfg(not(target_env = "ohos"))]
    {
        let _ = (env, node_id, frame_node, event_callback);
        unsupported()
    }
}

pub(super) fn detach(env: Env, component_id: String) -> String {
    #[cfg(target_env = "ohos")]
    return ohos::detach(env, component_id);
    #[cfg(not(target_env = "ohos"))]
    {
        let _ = (env, component_id);
        unsupported()
    }
}

pub(super) fn set_frame_rate_range(
    env: Env,
    component_id: String,
    expected: i32,
    min: i32,
    max: i32,
) -> String {
    #[cfg(target_env = "ohos")]
    return ohos::set_frame_rate_range(env, component_id, expected, min, max);
    #[cfg(not(target_env = "ohos"))]
    {
        let _ = (env, component_id, expected, min, max);
        unsupported()
    }
}

pub(super) fn borrow_surface(env: &Env, component_id: &str) -> Result<SurfaceBorrow, String> {
    #[cfg(target_env = "ohos")]
    return ohos::borrow_surface(env, component_id);
    #[cfg(not(target_env = "ohos"))]
    {
        let _ = (env, component_id);
        Err("XComponent Surface ownership requires HarmonyOS API 20+".to_string())
    }
}

#[cfg(not(target_env = "ohos"))]
fn unsupported() -> String {
    serde_json::json!({ "ok": false, "released": false,
        "error": "XComponent Surface ownership requires HarmonyOS API 20+" }).to_string()
}

#[cfg(target_env = "ohos")]
mod ohos {
    use super::*;
    use serde_json::{json, Value};
    use std::{
        ffi::c_char,
        ptr,
        sync::{atomic::{AtomicU64, AtomicUsize}, OnceLock},
    };

    // Uses the bridge's existing non-wrapping identity domain and record budget.
    // Orphaned environments/quarantined holders consume capacity, never eviction.
    fn next_id() -> Result<u64, Failure> {
        crate::allocate_native_id().map_err(Failure::local)
    }

    #[derive(Clone)]
    struct Failure {
        api: &'static str,
        result: Option<i32>,
        message: String,
    }

    impl Failure {
        fn local(message: impl Into<String>) -> Self {
            Self { api: "surface_owner", result: None, message: message.into() }
        }

        fn add_to(&self, value: &mut Value) {
            value["ok"] = json!(false);
            value["error"] = json!(self.message);
            value["api"] = json!(self.api);
            if let Some(result) = self.result {
                value["result"] = json!(result);
            }
        }
    }

    fn check(api: &'static str, result: i32) -> Result<(), Failure> {
        if result == 0 {
            Ok(())
        } else {
            Err(Failure { api, result: Some(result), message: format!("{api} returned {result}") })
        }
    }

    fn refused(error: Failure) -> String {
        let mut value = json!({ "ok": false, "released": false, "held": false });
        error.add_to(&mut value);
        value.to_string()
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Environment {
        raw: usize,
        generation: u64,
    }

    #[derive(Default)]
    struct Registry {
        environment: Option<Environment>,
        owners: Vec<Arc<Owner>>,
    }

    fn registry() -> &'static Mutex<Registry> {
        static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
        REGISTRY.get_or_init(|| Mutex::new(Registry::default()))
    }

    struct Owner {
        environment: Environment,
        component_id: String,
        node_label: String,
        unique_id: i32,
        node: usize,
        state: Mutex<State>,
        notices: Arc<Notices>,
        frames: AtomicU64,
    }

    struct State {
        environment_alive: bool,
        admitting: bool,
        operating: bool,
        callbacks_open: bool,
        callbacks_active: usize,
        frame_reference: usize,
        manual_lifecycle: bool,
        holder: usize,
        callback: usize,
        // Set before AddSurfaceCallback. Even a failed registration must be
        // positively removed before its callback object can be disposed.
        callback_removal_due: bool,
        callbacks_registered: bool,
        frame_registered: bool,
        window: usize,
        surface_id: u64,
        loan: Weak<Lease>,
        last_binding: Option<u64>,
        destroyed: bool,
        released: bool,
        width: u64,
        height: u64,
        failure: Option<Failure>,
    }

    struct Lease {
        surface_id: u64,
        retirement: Arc<Retirement>,
        _owner: Arc<Owner>,
    }

    // SAFETY: the target never changes. A real NativeWindow reference is acquired
    // before admission. The registry pins the manual-lifecycle holder and that
    // reference until the loan's Weak can no longer upgrade (not strong_count).
    // SDK destruction/unreference is UI-only and only after that terminal edge.
    // Unexpected ArkUI destruction revokes readiness and requests native Viewer
    // retirement; it does NOT discard the retained window, holder or callback.
    // A quarantined decoder retains its Arc, so it keeps this loan outstanding.
    unsafe impl SurfaceLease for Lease {
        fn surface_id(&self) -> u64 { self.surface_id }
        fn is_ready(&self) -> bool { self.retirement.ready.load(Ordering::Acquire) }
    }

    fn attach_environment(env: &Env, registry: &mut Registry) -> Result<Environment, Failure> {
        let raw = env.raw() as usize;
        if let Some(environment) = registry.environment {
            return if environment.raw == raw {
                Ok(environment)
            } else {
                Err(Failure::local("another UI environment owns XComponent admission"))
            };
        }
        let environment = Environment { raw, generation: next_id()? };
        // Same napi-ohos cleanup mechanism as app_context.rs. It fences first;
        // it never waits for a decoder, nor assumes JS disappearance is cleanup.
        env.add_env_cleanup_hook(environment, cleanup_environment)
            .map_err(|error| Failure::local(format!("cannot attach Surface cleanup: {error}")))?;
        registry.environment = Some(environment);
        Ok(environment)
    }

    fn find(env: &Env, component_id: &str) -> Result<Arc<Owner>, Failure> {
        let registry = lock(registry());
        let environment = registry.environment
            .filter(|ticket| ticket.raw == env.raw() as usize)
            .ok_or_else(|| Failure::local("UI environment does not own Surface admission"))?;
        registry.owners.iter()
            .find(|owner| owner.environment == environment && owner.component_id == component_id)
            .cloned().ok_or_else(|| Failure::local("unknown native componentId; no release is proven"))
    }

    fn snapshot(owner: &Owner) -> Value {
        snapshot_locked(owner, &lock(&owner.state))
    }

    fn snapshot_locked(owner: &Owner, state: &State) -> Value {
        let notices = lock(&owner.notices.state);
        json!({
            "ok": true, "componentId": owner.component_id, "nodeId": owner.node_label,
            "nodeUniqueId": owner.unique_id, "environmentGeneration": owner.environment.generation.to_string(),
            "surfaceId": if state.surface_id == 0 { String::new() } else { state.surface_id.to_string() },
            "bindingToken": state.last_binding.map(|token| token.to_string()),
            "ready": state.admitting && state.surface_id != 0 && !state.destroyed,
            "held": state.loan.strong_count() != 0, "released": state.released,
            "destroyed": state.destroyed, "callbacksRegistered": state.callbacks_registered,
            "frameCallbackRegistered": state.frame_registered,
            // Signal callbacks, not decoded frames or physical presentation FPS.
            "frameCallbacks": owner.frames.load(Ordering::Relaxed),
            "notificationResult": notices.last_status,
        })
    }

    fn notify(owner: &Owner, event: &str, source: &str) {
        let state = lock(&owner.state);
        let mut value = snapshot_locked(owner, &state);
        // Concurrent native callbacks can finish out of order. Serialize the
        // snapshot AND post with retirement: an older created/changed callback
        // must never overwrite a newer destroyed notice in the coalesced slot.
        value["event"] = json!(if state.destroyed {
            "destroyed"
        } else if !state.admitting {
            "retiring"
        } else {
            event
        });
        value["source"] = json!(source);
        value["width"] = json!(state.width);
        value["height"] = json!(state.height);
        if let Some(error) = &state.failure {
            error.add_to(&mut value);
        }
        // Lifecycle notifications never assert release. Only detach's explicit
        // successful cleanup path constructs a released:true result.
        value["released"] = json!(false);
        owner.notices.post(value.to_string());
    }

    fn fence(owner: &Owner, failure: Option<Failure>, destroyed: bool) {
        let loan = {
            let mut state = lock(&owner.state);
            state.admitting = false;
            state.destroyed |= destroyed;
            if let Some(failure) = failure { state.failure = Some(failure); }
            state.loan.upgrade()
        };
        if let Some(loan) = loan { loan.retirement.request(); }
    }

    /// Retain a target from the holder, never a caller-supplied Surface string.
    /// These getter/reference calls run before any loan, serialized with callback
    /// entry/retirement. Once bound, changed events only carry size metadata.
    fn capture_target(owner: &Owner) -> Result<(), Failure> {
        let mut state = lock(&owner.state);
        if !state.admitting || state.destroyed {
            return Err(Failure::local("Surface admission was revoked"));
        }
        if state.surface_id != 0 { return Ok(()); }
        let window = unsafe { ffi::OH_ArkUI_XComponent_GetNativeWindow(state.holder as _) };
        if window.is_null() { return Err(Failure::local("SurfaceHolder has no native window yet")); }
        // Pin before publishing the ID. In particular, no borrowed pointer is
        // smuggled into the decoder as if keeping a Rust String retained it.
        check("OH_NativeWindow_NativeObjectReference", unsafe {
            ffi::OH_NativeWindow_NativeObjectReference(window)
        })?;
        state.window = window as usize;
        let mut id = 0;
        check("OH_NativeWindow_GetSurfaceId", unsafe {
            ffi::OH_NativeWindow_GetSurfaceId(window, &mut id)
        })?;
        if id == 0 { return Err(Failure::local("native window returned an empty Surface id")); }
        state.surface_id = id;
        Ok(())
    }

    // An entrant can be waiting for the registry before it finds its Owner.
    // Count it before that lookup so unregister cannot free/reuse a holder while
    // such an entrant still carries the old address. Removal ends future SDK
    // delivery; a nonzero reader count defers disposal, without a UI-thread wait.
    static CALLBACK_READERS: AtomicUsize = AtomicUsize::new(0);
    struct CallbackEntry;
    impl CallbackEntry {
        fn enter() -> Self {
            CALLBACK_READERS.fetch_add(1, Ordering::SeqCst);
            Self
        }
    }
    impl Drop for CallbackEntry {
        fn drop(&mut self) { CALLBACK_READERS.fetch_sub(1, Ordering::SeqCst); }
    }

    // No SDK userdata pointer is dereferenced. The owner-specific count protects
    // SDK access already admitted before close fenced further callback work.
    struct Callback(Arc<Owner>);
    impl Drop for Callback {
        fn drop(&mut self) { lock(&self.0.state).callbacks_active -= 1; }
    }

    fn enter_callback(holder: *mut c_void) -> Option<Callback> {
        let registry = lock(registry());
        for owner in &registry.owners {
            let mut state = lock(&owner.state);
            if state.holder == holder as usize && state.callbacks_open {
                state.callbacks_active += 1;
                return Some(Callback(owner.clone()));
            }
        }
        None
    }

    unsafe extern "C" fn surface_created(holder: *mut c_void) {
        let _entry = CallbackEntry::enter();
        if let Some(callback) = enter_callback(holder) {
            match capture_target(&callback.0) {
                Ok(()) => notify(&callback.0, "created", "surface_callback"),
                Err(error) => {
                    fence(&callback.0, Some(error), false);
                    notify(&callback.0, "error", "surface_callback");
                }
            }
        }
    }

    unsafe extern "C" fn surface_changed(holder: *mut c_void, width: u64, height: u64) {
        let _entry = CallbackEntry::enter();
        if let Some(callback) = enter_callback(holder) {
            {
                let mut state = lock(&callback.0.state);
                state.width = width;
                state.height = height;
            }
            match capture_target(&callback.0) {
                Ok(()) => notify(&callback.0, "changed", "surface_callback"),
                Err(error) => {
                    fence(&callback.0, Some(error), false);
                    notify(&callback.0, "error", "surface_callback");
                }
            }
        }
    }

    unsafe extern "C" fn surface_destroyed(holder: *mut c_void) {
        let _entry = CallbackEntry::enter();
        if let Some(callback) = enter_callback(holder) {
            fence(&callback.0, None, true);
            notify(&callback.0, "destroyed", "surface_callback");
        }
    }

    unsafe extern "C" fn on_frame(node: *mut c_void, _: u64, _: u64) {
        let _entry = CallbackEntry::enter();
        // Only a signal count: no SDK call, native buffers, TSFN post or JS.
        let registry = lock(registry());
        if let Some(owner) = registry.owners.iter().find(|owner| owner.node == node as usize) {
            owner.frames.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) unsafe fn attach(
        env: Env, node_id: String, frame_node: *mut c_void, event_callback: *mut c_void,
    ) -> String {
        let prepared = (|| -> Result<Arc<Owner>, Failure> {
            if node_id.is_empty() || frame_node.is_null() || event_callback.is_null() {
                return Err(Failure::local("attach needs a node label, real FrameNode and callback"));
            }
            let mut node = ptr::null_mut();
            check("OH_ArkUI_GetNodeHandleFromNapiValue", unsafe {
                ffi::OH_ArkUI_GetNodeHandleFromNapiValue(env.raw() as _, frame_node, &mut node)
            })?;
            if node.is_null() { return Err(Failure::local("FrameNode produced no native node")); }
            let mut unique_id = -1;
            check("OH_ArkUI_NodeUtils_GetNodeUniqueId", unsafe {
                ffi::OH_ArkUI_NodeUtils_GetNodeUniqueId(node, &mut unique_id)
            })?;
            if unique_id < 0 { return Err(Failure::local("FrameNode no longer identifies a live node")); }
            let mut registry = lock(registry());
            if registry.owners.iter().any(|owner| owner.unique_id == unique_id) {
                return Err(Failure::local("this native node already has an owner (possibly retained)"));
            }
            if registry.owners.len() >= crate::MAX_SESSION_RECORDS {
                return Err(Failure::local("native Surface owner capacity is retained or exhausted"));
            }
            let environment = attach_environment(&env, &mut registry)?;
            let component_id = format!("xcomponent:{}", next_id()?);
            let owner = Arc::new(Owner {
                environment, component_id, node_label: node_id, unique_id, node: node as usize,
                state: Mutex::new(State {
                    environment_alive: true, admitting: true, operating: true,
                    callbacks_open: false, callbacks_active: 0, frame_reference: 0,
                    manual_lifecycle: false, holder: 0, callback: 0,
                    callback_removal_due: false, callbacks_registered: false, frame_registered: false,
                    window: 0, surface_id: 0, loan: Weak::new(), last_binding: None,
                    destroyed: false, released: false, width: 0, height: 0, failure: None,
                }),
                notices: Arc::new(Notices::default()), frames: AtomicU64::new(0),
            });
            registry.owners.push(owner.clone());
            Ok(owner)
        })();
        let owner = match prepared { Ok(owner) => owner, Err(error) => return refused(error) };
        let initialized = (|| -> Result<(), Failure> {
            let mut reference = ptr::null_mut();
            check("napi_create_reference(FrameNode)", unsafe {
                ffi::napi_create_reference(env.raw() as _, frame_node, 1, &mut reference)
            })?;
            lock(&owner.state).frame_reference = reference as usize;
            unsafe { owner.notices.initialize(env.raw() as _, event_callback) }?;
            check("OH_ArkUI_XComponent_SetAutoInitialize", unsafe {
                ffi::OH_ArkUI_XComponent_SetAutoInitialize(owner.node as _, false)
            })?;
            lock(&owner.state).manual_lifecycle = true;
            let holder = unsafe { ffi::OH_ArkUI_SurfaceHolder_Create(owner.node as _) };
            if holder.is_null() { return Err(Failure::local("SurfaceHolder_Create returned null")); }
            lock(&owner.state).holder = holder as usize;
            let callback = unsafe { ffi::OH_ArkUI_SurfaceCallback_Create() };
            if callback.is_null() { return Err(Failure::local("SurfaceCallback_Create returned null")); }
            lock(&owner.state).callback = callback as usize;
            unsafe {
                ffi::OH_ArkUI_SurfaceCallback_SetSurfaceCreatedEvent(callback, surface_created);
                ffi::OH_ArkUI_SurfaceCallback_SetSurfaceChangedEvent(callback, surface_changed);
                ffi::OH_ArkUI_SurfaceCallback_SetSurfaceDestroyedEvent(callback, surface_destroyed);
            }
            {
                let mut state = lock(&owner.state);
                state.callbacks_open = true;
                state.callback_removal_due = true;
            }
            check("OH_ArkUI_SurfaceHolder_AddSurfaceCallback", unsafe {
                ffi::OH_ArkUI_SurfaceHolder_AddSurfaceCallback(holder, callback)
            })?;
            lock(&owner.state).callbacks_registered = true;
            let mut initialized = false;
            check("OH_ArkUI_XComponent_IsInitialized", unsafe {
                ffi::OH_ArkUI_XComponent_IsInitialized(owner.node as _, &mut initialized)
            })?;
            if !initialized {
                check("OH_ArkUI_XComponent_Initialize", unsafe {
                    ffi::OH_ArkUI_XComponent_Initialize(owner.node as _)
                })?;
            } else if lock(&owner.state).surface_id == 0 {
                // Attach can occur after ArkUI created the Surface. The header
                // does not promise AddSurfaceCallback replays that event. Read
                // the actual initialized holder once, explicitly labelled as a
                // snapshot; do not synthesize an SDK callback or parse a JS id.
                capture_target(&owner)?;
                notify(&owner, "created", "initialized_holder_snapshot");
            }
            let state = lock(&owner.state);
            if let Some(error) = &state.failure { return Err(error.clone()); }
            if state.destroyed { return Err(Failure::local("Surface was destroyed during attach")); }
            Ok(())
        })();
        lock(&owner.state).operating = false;
        match initialized {
            Ok(()) => snapshot(&owner).to_string(),
            Err(error) => {
                fence(&owner, Some(error.clone()), false);
                // One cleanup attempt for a partially acquired owner. If it
                // cannot settle, the returned componentId remains actionable.
                let cleanup = detach_owner(&owner);
                let mut value = snapshot(&owner);
                error.add_to(&mut value);
                value["cleanup"] = cleanup;
                value.to_string()
            }
        }
    }

    pub(super) fn borrow_surface(env: &Env, component_id: &str) -> Result<SurfaceBorrow, String> {
        let owner = find(env, component_id).map_err(|error| error.message)?;
        let mut state = lock(&owner.state);
        if !state.environment_alive || !state.admitting || state.operating || state.destroyed
            || state.released || state.surface_id == 0
        {
            return Err("native Surface is not ready for a new binding".to_string());
        }
        if state.loan.upgrade().is_some() {
            return Err("native Surface is already borrowed by a session".to_string());
        }
        let token = next_id().map_err(|error| error.message)?;
        let retirement = Arc::new(Retirement::new());
        let lease = Arc::new(Lease {
            surface_id: state.surface_id, retirement: retirement.clone(), _owner: owner.clone(),
        });
        state.loan = Arc::downgrade(&lease);
        state.last_binding = Some(token);
        Ok(SurfaceBorrow { token, surface_id: state.surface_id, lease, retirement })
    }

    pub(super) fn detach(env: Env, component_id: String) -> String {
        match find(&env, &component_id) {
            Ok(owner) => detach_owner(&owner).to_string(),
            Err(error) => refused(error),
        }
    }

    fn detach_owner(owner: &Arc<Owner>) -> Value {
        fence(owner, None, false);
        let held = {
            let mut state = lock(&owner.state);
            state.callbacks_open = false;
            // Weak::upgrade == None is final for THIS loan, including all
            // external Weak pointers. strong_count == 1 would not be proof.
            let held = state.loan.upgrade().is_some() || state.callbacks_active != 0 || state.operating;
            if !held { state.operating = true; }
            held
        };
        if held {
            let mut value = snapshot(owner);
            value["ok"] = json!(false);
            value["held"] = json!(true);
            value["released"] = json!(false);
            value["error"] = json!("Surface loan or native callback/operation still owns resources");
            return value;
        }
        let result = release_native(owner);
        {
            let mut state = lock(&owner.state);
            state.operating = false;
            match &result {
                Ok(()) => state.released = true,
                Err(error) => state.failure = Some(error.clone()),
            }
        }
        if result.is_ok() {
            lock(registry()).owners.retain(|current| !Arc::ptr_eq(current, owner));
        }
        let mut value = snapshot(owner);
        if let Err(error) = result {
            error.add_to(&mut value);
            value["held"] = json!(true);
        }
        value
    }

    /// UI-only; no SDK call holding the registry mutex, no waits or worker joins.
    /// Each completed native step is recorded before any subsequent failure.
    fn release_native(owner: &Owner) -> Result<(), Failure> {
        if !lock(&owner.state).environment_alive {
            return Err(Failure::local("environment ended; native cleanup ownership remains retained"));
        }
        if lock(&owner.state).frame_registered {
            check("OH_ArkUI_XComponent_UnregisterOnFrameCallback", unsafe {
                ffi::OH_ArkUI_XComponent_UnregisterOnFrameCallback(owner.node as _)
            })?;
            lock(&owner.state).frame_registered = false;
        }
        let (holder, callback, remove_due) = {
            let state = lock(&owner.state);
            (state.holder, state.callback, state.callback_removal_due)
        };
        if remove_due {
            check("OH_ArkUI_SurfaceHolder_RemoveSurfaceCallback", unsafe {
                ffi::OH_ArkUI_SurfaceHolder_RemoveSurfaceCallback(holder as _, callback as _)
            })?;
            let mut state = lock(&owner.state);
            state.callback_removal_due = false;
            state.callbacks_registered = false;
        }
        if CALLBACK_READERS.load(Ordering::SeqCst) != 0 {
            return Err(Failure::local("native callback entry has not drained; holder remains retained"));
        }
        if lock(&owner.state).manual_lifecycle {
            let mut initialized = false;
            check("OH_ArkUI_XComponent_IsInitialized", unsafe {
                ffi::OH_ArkUI_XComponent_IsInitialized(owner.node as _, &mut initialized)
            })?;
            if initialized {
                check("OH_ArkUI_XComponent_Finalize", unsafe {
                    ffi::OH_ArkUI_XComponent_Finalize(owner.node as _)
                })?;
                check("OH_ArkUI_XComponent_IsInitialized(after Finalize)", unsafe {
                    ffi::OH_ArkUI_XComponent_IsInitialized(owner.node as _, &mut initialized)
                })?;
                if initialized { return Err(Failure::local("native Surface finalization is unconfirmed")); }
            }
            lock(&owner.state).manual_lifecycle = false;
        }
        // Retained pin is released only after no decoder loan can be revived.
        let window = lock(&owner.state).window;
        if window != 0 {
            check("OH_NativeWindow_NativeObjectUnreference", unsafe {
                ffi::OH_NativeWindow_NativeObjectUnreference(window as _)
            })?;
            lock(&owner.state).window = 0;
        }
        if holder != 0 {
            unsafe { ffi::OH_ArkUI_SurfaceHolder_Dispose(holder as _) };
            lock(&owner.state).holder = 0;
        }
        if callback != 0 {
            unsafe { ffi::OH_ArkUI_SurfaceCallback_Dispose(callback as _) };
            lock(&owner.state).callback = 0;
        }
        let reference = lock(&owner.state).frame_reference;
        if reference != 0 {
            check("napi_delete_reference(FrameNode)", unsafe {
                ffi::napi_delete_reference(owner.environment.raw as _, reference as _)
            })?;
            lock(&owner.state).frame_reference = 0;
        }
        owner.notices.close()
    }

    fn cleanup_environment(environment: Environment) {
        let owners = {
            let mut registry = lock(registry());
            if registry.environment != Some(environment) { return; }
            registry.environment = None; // Fence all new lookups before cleanup.
            registry.owners.iter().filter(|owner| owner.environment == environment)
                .cloned().collect::<Vec<_>>()
        };
        for owner in owners {
            fence(&owner, None, false);
            // The hook still runs on the environment thread. Clean only owners
            // with no loan/active callback. A held owner remains in the registry
            // even after the final JS reference/TSFN disappears with this env.
            let _ = detach_owner(&owner);
            let _ = owner.notices.close();
            lock(&owner.state).environment_alive = false;
        }
    }

    pub(super) fn set_frame_rate_range(
        env: Env, component_id: String, expected: i32, min: i32, max: i32,
    ) -> String {
        let owner = match find(&env, &component_id) {
            Ok(owner) => owner, Err(error) => return refused(error),
        };
        if min < 0 || expected <= 0 || min > expected || expected > max {
            return refused(Failure::local("frame rate must satisfy 0 <= min <= expected <= max, expected > 0"));
        }
        {
            let mut state = lock(&owner.state);
            if !state.admitting || state.operating || !state.environment_alive {
                return refused(Failure::local("native component is retiring or busy"));
            }
            state.operating = true;
        }
        let mut register_result = None;
        if !lock(&owner.state).frame_registered {
            let result = unsafe { ffi::OH_ArkUI_XComponent_RegisterOnFrameCallback(owner.node as _, on_frame) };
            register_result = Some(result);
            lock(&owner.state).frame_registered = result == 0;
        }
        let result = unsafe {
            ffi::OH_ArkUI_XComponent_SetExpectedFrameRateRange(owner.node as _, ffi::RateRange { min, max, expected })
        };
        lock(&owner.state).operating = false;
        let mut value = snapshot(&owner);
        value["ok"] = json!(result == 0 && lock(&owner.state).frame_registered);
        value["result"] = json!(result);
        value["registerResult"] = json!(register_result);
        value["expected"] = json!(expected);
        value["min"] = json!(min);
        value["max"] = json!(max);
        value.to_string()
    }

    // One coalesced lifecycle snapshot per owner, not an unbounded event stream.
    // Changed/created share an immutable target; a subsequent destroy dominates
    // them. Native retirement already happened before notifying JS, so a lost
    // callback cannot authorize reuse or abandon cleanup.
    #[derive(Default)]
    struct Notices { state: Mutex<NoticeState> }
    #[derive(Default)]
    struct NoticeState {
        handle: usize,
        queued: bool,
        latest: Option<String>,
        last_status: Option<i32>,
        close_status: Option<i32>,
        finalized: bool,
    }

    impl Notices {
        unsafe fn initialize(self: &Arc<Self>, env: *mut c_void, callback: *mut c_void) -> Result<(), Failure> {
            let mut name = ptr::null_mut();
            check("napi_create_string_utf8(Surface TSFN name)", unsafe {
                ffi::napi_create_string_utf8(env, c"rd-engine Surface lifecycle".as_ptr(), 27, &mut name)
            })?;
            // The TSFN owns this Arc until its actual native finalizer. It has no
            // strong Owner reference and cannot falsely free a native holder.
            let context = Box::into_raw(Box::new(self.clone())) as *mut c_void;
            let mut handle = ptr::null_mut();
            let result = unsafe {
                ffi::napi_create_threadsafe_function(env, callback, ptr::null_mut(), name, 1, 1,
                    context, finalize_notices, context, call_js, &mut handle)
            };
            if result != 0 {
                unsafe { drop(Box::from_raw(context as *mut Arc<Notices>)) };
                return check("napi_create_threadsafe_function", result);
            }
            lock(&self.state).handle = handle as usize;
            check("napi_unref_threadsafe_function", unsafe {
                ffi::napi_unref_threadsafe_function(env, handle)
            })
        }

        fn post(&self, event: String) {
            let mut state = lock(&self.state);
            if state.handle == 0 || state.close_status.is_some() { return; }
            state.latest = Some(event);
            if state.queued { return; }
            // Serialized against close taking this handle; nonblocking TSFN
            // delivery never invokes the JS function synchronously here.
            let result = unsafe { ffi::napi_call_threadsafe_function(state.handle as _, ptr::null_mut(), 0) };
            state.last_status = Some(result);
            state.queued = result == 0;
            // js_native_api_types.h: napi_closing = 16. Once the runtime is
            // closing the TSFN, do not call/release that handle again. Retain
            // the incomplete status until its real finalizer is observed.
            if result == 16 {
                state.handle = 0;
                state.latest = None;
                state.close_status = Some(result);
            }
        }

        fn close(&self) -> Result<(), Failure> {
            let handle = {
                let mut state = lock(&self.state);
                if state.finalized { return Ok(()); }
                if let Some(result) = state.close_status {
                    return check("napi_release_threadsafe_function", result);
                }
                let handle = state.handle;
                if handle == 0 { return Ok(()); }
                state.handle = 0; // No later post may call a released handle.
                state.latest = None;
                handle
            };
            let result = unsafe { ffi::napi_release_threadsafe_function(handle as _, 1) }; // abort
            lock(&self.state).close_status = Some(result);
            // A failed abort is not automatically replayed. The native TSFN
            // finalizer, if it later runs, provides independent completion.
            check("napi_release_threadsafe_function", result)
        }
    }

    unsafe extern "C" fn finalize_notices(_: *mut c_void, data: *mut c_void, _: *mut c_void) {
        let notices = unsafe { Box::from_raw(data as *mut Arc<Notices>) };
        let mut state = lock(&notices.state);
        state.handle = 0;
        state.latest = None;
        state.finalized = true;
    }

    unsafe extern "C" fn call_js(env: *mut c_void, callback: *mut c_void, context: *mut c_void, _: *mut c_void) {
        let notices = unsafe { &*(context as *const Arc<Notices>) };
        let event = {
            let mut state = lock(&notices.state);
            state.queued = false;
            state.latest.take()
        };
        let Some(event) = event else { return; };
        if env.is_null() || callback.is_null() { return; }
        let result = (|| -> Result<(), Failure> {
            let mut argument = ptr::null_mut();
            check("napi_create_string_utf8(Surface event)", unsafe {
                ffi::napi_create_string_utf8(env, event.as_ptr() as _, event.len(), &mut argument)
            })?;
            let mut receiver = ptr::null_mut();
            check("napi_get_undefined", unsafe { ffi::napi_get_undefined(env, &mut receiver) })?;
            let mut returned = ptr::null_mut();
            check("napi_call_function(Surface event)", unsafe {
                ffi::napi_call_function(env, receiver, callback, 1, &argument, &mut returned)
            })
        })();
        if let Err(error) = result { lock(&notices.state).last_status = error.result; }
    }

    // Opaque pointers deliberately stay within this file; no native pointer or
    // napi_ref becomes an ArkTS integer, a public token, or a SurfaceLease id.
    mod ffi {
        use super::{c_char, c_void};
        #[repr(C)]
        pub(super) struct RateRange { pub min: i32, pub max: i32, pub expected: i32 }
        #[link(name = "ace_ndk.z")]
        unsafe extern "C" {
            pub fn OH_ArkUI_GetNodeHandleFromNapiValue(env: *mut c_void, value: *mut c_void, node: *mut *mut c_void) -> i32;
            pub fn OH_ArkUI_NodeUtils_GetNodeUniqueId(node: *mut c_void, id: *mut i32) -> i32;
            pub fn OH_ArkUI_SurfaceHolder_Create(node: *mut c_void) -> *mut c_void;
            pub fn OH_ArkUI_SurfaceHolder_Dispose(holder: *mut c_void);
            pub fn OH_ArkUI_SurfaceCallback_Create() -> *mut c_void;
            pub fn OH_ArkUI_SurfaceCallback_Dispose(callback: *mut c_void);
            pub fn OH_ArkUI_SurfaceCallback_SetSurfaceCreatedEvent(callback: *mut c_void, event: unsafe extern "C" fn(*mut c_void));
            pub fn OH_ArkUI_SurfaceCallback_SetSurfaceChangedEvent(callback: *mut c_void, event: unsafe extern "C" fn(*mut c_void, u64, u64));
            pub fn OH_ArkUI_SurfaceCallback_SetSurfaceDestroyedEvent(callback: *mut c_void, event: unsafe extern "C" fn(*mut c_void));
            pub fn OH_ArkUI_SurfaceHolder_AddSurfaceCallback(holder: *mut c_void, callback: *mut c_void) -> i32;
            pub fn OH_ArkUI_SurfaceHolder_RemoveSurfaceCallback(holder: *mut c_void, callback: *mut c_void) -> i32;
            pub fn OH_ArkUI_XComponent_GetNativeWindow(holder: *mut c_void) -> *mut c_void;
            pub fn OH_ArkUI_XComponent_SetAutoInitialize(node: *mut c_void, auto: bool) -> i32;
            pub fn OH_ArkUI_XComponent_Initialize(node: *mut c_void) -> i32;
            pub fn OH_ArkUI_XComponent_Finalize(node: *mut c_void) -> i32;
            pub fn OH_ArkUI_XComponent_IsInitialized(node: *mut c_void, initialized: *mut bool) -> i32;
            pub fn OH_ArkUI_XComponent_SetExpectedFrameRateRange(node: *mut c_void, range: RateRange) -> i32;
            pub fn OH_ArkUI_XComponent_RegisterOnFrameCallback(node: *mut c_void, callback: unsafe extern "C" fn(*mut c_void, u64, u64)) -> i32;
            pub fn OH_ArkUI_XComponent_UnregisterOnFrameCallback(node: *mut c_void) -> i32;
        }
        #[link(name = "native_window")]
        unsafe extern "C" {
            pub fn OH_NativeWindow_GetSurfaceId(window: *mut c_void, surface_id: *mut u64) -> i32;
            pub fn OH_NativeWindow_NativeObjectReference(object: *mut c_void) -> i32;
            pub fn OH_NativeWindow_NativeObjectUnreference(object: *mut c_void) -> i32;
        }
        #[link(name = "ace_napi.z")]
        unsafe extern "C" {
            pub fn napi_create_reference(env: *mut c_void, value: *mut c_void, count: u32, reference: *mut *mut c_void) -> i32;
            pub fn napi_delete_reference(env: *mut c_void, reference: *mut c_void) -> i32;
            pub fn napi_create_string_utf8(env: *mut c_void, value: *const c_char, length: usize, result: *mut *mut c_void) -> i32;
            pub fn napi_get_undefined(env: *mut c_void, value: *mut *mut c_void) -> i32;
            pub fn napi_call_function(env: *mut c_void, receiver: *mut c_void, function: *mut c_void, argc: usize, argv: *const *mut c_void, result: *mut *mut c_void) -> i32;
            pub fn napi_create_threadsafe_function(env: *mut c_void, function: *mut c_void, resource: *mut c_void, name: *mut c_void, max_queue_size: usize, initial_threads: usize, finalize_data: *mut c_void, finalize: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void), context: *mut c_void, call_js: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void), result: *mut *mut c_void) -> i32;
            pub fn napi_call_threadsafe_function(function: *mut c_void, data: *mut c_void, mode: i32) -> i32;
            pub fn napi_release_threadsafe_function(function: *mut c_void, mode: i32) -> i32;
            pub fn napi_unref_threadsafe_function(env: *mut c_void, function: *mut c_void) -> i32;
        }
    }
}
