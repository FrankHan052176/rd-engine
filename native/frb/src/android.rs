//! Android runner startup adapted from RustDesk 092a961b629d318fe290eeafac0cd214a1e9deeb,
//! libs/scrap/src/android/ffi.rs:444-518 (AGPL-3.0; see UPSTREAM.txt).
//! This retains the real VM, NDK context and application-scoped TLS verifier.
//! It does not implement or replace the media/service lifecycle. Account
//! Keystore initialization remains the runner's separate, subsequent callback.

use anyhow::{anyhow, ensure, Result};
use hbb_common::config::ANDROID_RUSTLS_PLATFORM_VERIFIER_INITIALIZED;
use jni::{
    objects::{GlobalRef, JClass, JObject},
    sys::{jint, JNI_ERR, JNI_VERSION_1_6},
    JNIEnv, JavaVM,
};
use std::{
    ffi::c_void,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{atomic::Ordering, Mutex},
};

static NDK_CONTEXT_INITIALIZED: Mutex<bool> = Mutex::new(false);
static APPLICATION_CONTEXT: Mutex<Option<GlobalRef>> = Mutex::new(None);

fn init_ndk_context(vm: *mut c_void, context: *mut c_void) -> Result<()> {
    let mut initialized = NDK_CONTEXT_INITIALIZED
        .lock()
        .map_err(|_| anyhow!("Android context initialization unavailable"))?;
    // SAFETY: JNI supplies this VM and reserved context, as in the pinned
    // runner. This mutex serializes replacement of this library's NDK context.
    unsafe {
        if *initialized {
            ndk_context::release_android_context();
        }
        ndk_context::initialize_android_context(vm, context);
    }
    *initialized = true;
    Ok(())
}

#[no_mangle]
pub extern "C" fn JNI_OnLoad(vm: JavaVM, reserved: *mut c_void) -> jint {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<()> {
        let _env = vm.get_env()?;
        init_ndk_context(vm.get_java_vm_pointer().cast(), reserved)
    }));
    match result {
        Ok(Ok(())) => JNI_VERSION_1_6,
        _ => JNI_ERR,
    }
}

fn init_application(env: &mut JNIEnv<'_>, context: JObject<'_>) -> Result<()> {
    ensure!(!context.is_null(), "Android application context is missing");
    let mut retained = APPLICATION_CONTEXT
        .lock()
        .map_err(|_| anyhow!("Android application initialization unavailable"))?;
    if retained.is_some() {
        return Ok(());
    }
    let application = env.new_global_ref(context)?;
    if !ANDROID_RUSTLS_PLATFORM_VERIFIER_INITIALIZED.load(Ordering::Relaxed) {
        // Give the verifier a real JNI local reference, not a second Rust
        // owner manufactured from the retained global reference's raw handle.
        let local = env.new_local_ref(application.as_obj())?;
        hbb_common::rustls_platform_verifier::android::init_hosted(env, local)?;
        ANDROID_RUSTLS_PLATFORM_VERIFIER_INITIALIZED.store(true, Ordering::Relaxed);
    }
    *retained = Some(application);
    Ok(())
}

#[no_mangle]
pub extern "system" fn Java_ffi_FFI_onAppStart(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    context: JObject<'_>,
) {
    let result = catch_unwind(AssertUnwindSafe(|| init_application(&mut env, context)));
    if !matches!(result, Ok(Ok(()))) {
        // No raw Java/Rust exception details become account diagnostics. A
        // failed startup is observable to the real Application caller; never
        // report initialization success or unwind across the JNI boundary.
        let _ = env.exception_clear();
        let _ = env.throw_new(
            "java/lang/IllegalStateException",
            "Native application initialization failed",
        );
    }
}
