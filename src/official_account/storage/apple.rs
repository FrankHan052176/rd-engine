//! Apple master-key backing for the official account store.
//!
//! This is missing platform integration, not a RustDesk source transplant. The
//! API contracts come from Security.framework's SecItem/SecKeychain headers,
//! LocalAuthentication.framework's LAContext header, and security-framework
//! 3.7.0 / security-framework-sys 2.17.0. See Apple's TN3137 (On Mac Keychains).
//!
//! macOS deliberately uses the current user's default file-based keychain and
//! its default calling-application ACL. This supports the pinned client's 10.14
//! deployment target without new entitlements. The OS may ask the real user to
//! authorize access; we never approve it, change an ACL, alter process-global UI
//! policy, or retry a denial. Per-query LAContext flags do not suppress legacy
//! keychain UI. This is NOT a fallback from the data-protection keychain.
//!
//! iOS uses its normal application-scoped data-protection keychain, with a fresh
//! noninteractive LAContext and WhenUnlockedThisDeviceOnly protection. No access
//! group is supplied or added. Neither implementation synchronizes keys. The
//! pinned iOS client's minimum is 13.0; interactionNotAllowed requires only 11.0.
//!
//! The common owner supplies a non-secret application/profile digest, generates
//! the random secretbox key, and holds its cross-process lock during election.
//! `root` is unused: the key never has a plaintext filesystem representation.

use std::{io, path::Path, ptr, sync::Arc};

use core_foundation::{
    base::{CFType, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFMutableDictionary,
    string::CFString,
};
use hbb_common::sodiumoxide::crypto::secretbox;
use security_framework_sys::{
    base::{errSecDuplicateItem, errSecItemNotFound, errSecSuccess},
    item::{
        kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecValueData,
    },
    keychain_item::SecItemAdd,
};

#[cfg(target_os = "macos")]
use self::macos as platform;
#[cfg(target_os = "ios")]
use self::ios as platform;

// The service is a private item identity, not a device UUID or account credential.
// The account attribute is the common owner's stable application/profile digest.
const SERVICE: &str = "org.rustdesk.rd-engine.official-account.master-key.v1";

type KeyQuery = CFMutableDictionary<CFString, CFType>;

pub(super) fn load_key(_root: &Path, namespace: &str) -> io::Result<Option<secretbox::Key>> {
    validate_namespace(namespace)?;
    platform::load(namespace)
}

pub(super) fn create_key(
    _root: &Path,
    namespace: &str,
    key: &secretbox::Key,
) -> io::Result<bool> {
    validate_namespace(namespace)?;
    platform::create(namespace, key)
}

fn validate_namespace(namespace: &str) -> io::Result<()> {
    // In the macOS Find API, an empty account would omit the account predicate.
    // Also avoid narrowing a string length at that API's UInt32 boundary.
    if namespace.is_empty() || u32::try_from(namespace.len()).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Apple Keychain profile namespace",
        ));
    }
    Ok(())
}

fn key_query(namespace: &str) -> KeyQuery {
    // SAFETY: These are framework-owned CFString constants available on both
    // pinned deployment targets. The dictionary retains all keys and values.
    unsafe {
        KeyQuery::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrService),
                CFString::from_static_string(SERVICE).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccount),
                CFString::from(namespace).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFBoolean::false_value().into_CFType(),
            ),
        ])
    }
}

fn add_key(mut query: KeyQuery, key: &secretbox::Key) -> io::Result<bool> {
    // CFData owns this Arc, rather than copying a temporary Vec. Its deallocator
    // drops the secretbox::Key, whose Drop uses sodium_memzero. Copies internal
    // to Security.framework are outside this Rust owner's erasure guarantee.
    let data = CFData::from_arc(Arc::new(key.clone()));
    // SAFETY: The dictionary retains the live CFData until SecItemAdd finishes.
    unsafe {
        query.add(
            &CFString::wrap_under_get_rule(kSecValueData),
            &data.as_CFType(),
        );
    }
    // SecItemAdd is intentional: the high-level set_generic_password helper
    // calls SecItemUpdate on a duplicate and would replace the elected key.
    // SAFETY: query contains the documented generic-password attributes. No
    // return value is requested, so passing a null result pointer is permitted.
    let status = unsafe { SecItemAdd(query.as_concrete_TypeRef(), ptr::null_mut()) };
    match status {
        errSecSuccess => Ok(true),
        errSecDuplicateItem => Ok(false),
        _ => Err(status_error("add master key", status)),
    }
}

fn status_error(operation: &'static str, status: i32) -> io::Error {
    // OSStatus is not an errno. Preserve its number without attaching a query,
    // application path, key bytes, or a potentially secret-bearing description.
    io::Error::other(format!("Apple Keychain {operation} failed (OSStatus {status})"))
}

fn invalid_key() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Apple Keychain master key")
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{ffi::c_void, slice};

    use hbb_common::sodiumoxide::utils::memzero;
    use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
    use security_framework_sys::{
        base::SecKeychainRef,
        item::kSecUseKeychain,
        keychain::SecKeychainFindGenericPassword,
        keychain_item::SecKeychainItemFreeContent,
    };

    use super::*;

    // Public Security.framework API, absent from security-framework-sys 2.17.0.
    // SecKeychain.h: SecKeychainStatus is UInt32; available since macOS 10.2.
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecKeychainGetStatus(keychain: SecKeychainRef, status: *mut u32) -> i32;
    }

    fn user_keychain() -> io::Result<SecKeychain> {
        let keychain = SecKeychain::default_for_domain(SecPreferencesDomain::User)
            .map_err(|error| status_error("open user keychain", error.code()))?;
        let mut state = 0;
        // SAFETY: keychain is live and state points to a writable SecKeychainStatus.
        let status = unsafe { SecKeychainGetStatus(keychain.as_concrete_TypeRef(), &mut state) };
        if status != errSecSuccess {
            return Err(status_error("read keychain state", status));
        }
        // kSecUnlockStateStatus from SecKeychain.h. In particular, a locked
        // keychain must not masquerade as an absent master key. This preflight
        // is not a no-UI guarantee: an ACL check or subsequent lock can prompt.
        if state & 1 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the user Keychain is locked",
            ));
        }
        Ok(keychain)
    }

    pub(super) fn load(namespace: &str) -> io::Result<Option<secretbox::Key>> {
        let keychain = user_keychain()?;
        let mut password = PasswordBuffer { data: ptr::null_mut(), len: 0 };
        // Use the maintained low-level Find API for this explicitly selected
        // file keychain. Unlike the SecItem legacy search shim, it propagates
        // lookup errors directly and returns an owned, erasable byte buffer.
        // SAFETY: Both names are live UTF-8 byte strings; namespace length was
        // checked by load_key. The keychain and out-parameters live through the
        // call. A null itemRef requests no extra item reference.
        let status = unsafe {
            SecKeychainFindGenericPassword(
                keychain.as_CFTypeRef(),
                SERVICE.len() as u32,
                SERVICE.as_ptr().cast(),
                namespace.len() as u32,
                namespace.as_ptr().cast(),
                &mut password.len,
                &mut password.data,
                ptr::null_mut(),
            )
        };
        match status {
            errSecItemNotFound => return Ok(None),
            errSecSuccess => {},
            _ => return Err(status_error("load master key", status)),
        }
        if password.data.is_null() || password.len as usize != secretbox::KEYBYTES {
            return Err(invalid_key());
        }
        // SAFETY: A successful Find returned this owned allocation, and its
        // checked length is exactly the secretbox key size, not an unbounded read.
        let bytes = unsafe { slice::from_raw_parts(password.data.cast(), secretbox::KEYBYTES) };
        secretbox::Key::from_slice(bytes).map(Some).ok_or_else(invalid_key)
    }

    pub(super) fn create(namespace: &str, key: &secretbox::Key) -> io::Result<bool> {
        let keychain = user_keychain()?;
        let mut query = key_query(namespace);
        // kSecUseKeychain explicitly selects the file-based implementation and
        // exactly the same user-default keychain used by load. Omit kSecAttrAccess
        // to retain Apple's default application ACL; never install allow-any ACLs.
        // SAFETY: The dictionary retains the live keychain reference.
        unsafe {
            query.add(
                &CFString::wrap_under_get_rule(kSecUseKeychain),
                &keychain.as_CFType(),
            );
        }
        add_key(query, key)
    }

    struct PasswordBuffer {
        data: *mut c_void,
        len: u32,
    }

    impl Drop for PasswordBuffer {
        fn drop(&mut self) {
            if !self.data.is_null() {
                // SAFETY: Find transfers this mutable allocation to the caller;
                // it is freed exactly once with the matching Keychain API. u32
                // fits the slice-size bound on the supported 64-bit macOS targets.
                unsafe {
                    memzero(slice::from_raw_parts_mut(self.data.cast(), self.len as usize));
                    SecKeychainItemFreeContent(ptr::null_mut(), self.data);
                }
            }
        }
    }
}

#[cfg(target_os = "ios")]
mod ios {
    use objc2::{
        extern_class, extern_methods,
        rc::{autoreleasepool, Retained},
        runtime::NSObject,
    };
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework_sys::{
        item::{kSecAttrAccessControl, kSecReturnData, kSecUseAuthenticationContext},
        keychain_item::SecItemCopyMatching,
    };

    use super::*;

    #[link(name = "LocalAuthentication", kind = "framework")]
    unsafe extern "C" {}

    // Narrow bindings for the public LAContext methods not exposed by
    // security-framework. objc2 supplies Objective-C BOOL/ownership handling.
    extern_class!(
        #[unsafe(super(NSObject))]
        struct LAContext;
    );

    impl LAContext {
        extern_methods!(
            #[unsafe(method(new))]
            #[unsafe(method_family = new)]
            fn new() -> Option<Retained<Self>>;

            #[unsafe(method(setInteractionNotAllowed:))]
            #[unsafe(method_family = none)]
            fn set_interaction_not_allowed(&self, value: bool);
        );
    }

    fn noninteractive_query(namespace: &str) -> io::Result<KeyQuery> {
        let context = LAContext::new()
            .ok_or_else(|| io::Error::other("could not create Keychain authentication context"))?;
        context.set_interaction_not_allowed(true);
        let mut query = key_query(namespace);
        // SAFETY: kSecUseAuthenticationContext explicitly accepts LAContext as
        // a retained Objective-C object in a CFDictionary. Both the temporary
        // CFType and the dictionary retain it; the context survives the OS call.
        unsafe {
            let value = CFType::wrap_under_get_rule(Retained::as_ptr(&context).cast());
            query.add(
                &CFString::wrap_under_get_rule(kSecUseAuthenticationContext),
                &value,
            );
        }
        // Do not use kSecUseAuthenticationUISkip: skipping an inaccessible item
        // would incorrectly turn an authentication failure into a missing key.
        Ok(query)
    }

    pub(super) fn load(namespace: &str) -> io::Result<Option<secretbox::Key>> {
        autoreleasepool(|_| {
            let mut query = noninteractive_query(namespace)?;
            // SAFETY: Request exactly one CFData (SecItem's default match limit).
            unsafe {
                query.add(
                    &CFString::wrap_under_get_rule(kSecReturnData),
                    &CFBoolean::true_value().as_CFType(),
                );
            }
            let mut raw = ptr::null();
            // SAFETY: The query and writable output reference live through the call.
            let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut raw) };
            // Own any result even on an unexpected error, so it is released on
            // every path. Its type and length are checked before reading bytes.
            let result = if raw.is_null() {
                None
            } else {
                Some(unsafe { CFType::wrap_under_create_rule(raw) })
            };
            match status {
                errSecItemNotFound => return Ok(None),
                errSecSuccess => {},
                _ => return Err(status_error("load master key", status)),
            }
            let data = result.and_then(|value| value.downcast_into::<CFData>())
                .ok_or_else(invalid_key)?;
            if data.len() != secretbox::KEYBYTES as isize {
                return Err(invalid_key());
            }
            // No intermediate Vec or unbounded copy. The returned key owns and
            // erases its bytes. Security's immutable CFData is released promptly,
            // but cannot safely be overwritten by casting away its immutability.
            secretbox::Key::from_slice(data.bytes()).map(Some).ok_or_else(invalid_key)
        })
    }

    pub(super) fn create(namespace: &str, key: &secretbox::Key) -> io::Result<bool> {
        autoreleasepool(|_| {
            let mut query = noninteractive_query(namespace)?;
            let access = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                0,
            ).map_err(|error| status_error("configure key protection", error.code()))?;
            // No user-presence/biometry/password flags or access-group override.
            // SAFETY: This is the documented SecAccessControl value type.
            unsafe {
                query.add(
                    &CFString::wrap_under_get_rule(kSecAttrAccessControl),
                    &access.as_CFType(),
                );
            }
            add_key(query, key)
        })
    }
}
