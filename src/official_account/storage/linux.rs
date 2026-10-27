//! Linux account master keys backed by the user's Secret Service.
//!
//! This is a new platform integration, not transplanted RustDesk persistence.
//! Secret Service protocol/session cryptography belongs to secret-service 5.2.0
//! (upstream 1fe4fbe405b152bc969deb5de417847e1e4e4c7b). The recorded vendor patch
//! adds only blocking, prompt-free item creation. Do not substitute its ordinary
//! `create_item` here: even an unlocked collection may require authorization.
//!
//! The caller holds the common account-directory file lock across election and
//! record I/O. `namespace` already binds the application/purpose and profile path;
//! `root` is not another secret file. Calls run on the existing blocking worker.

use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::path::Path;
use std::time::Duration;

use hbb_common::sodiumoxide::{crypto::secretbox, utils::memcmp};
use secret_service::blocking::{Collection, Item, SecretService};
use secret_service::{EncryptionType, Error as SecretError};
use zbus::DBusError;
use zeroize::Zeroizing;

const SERVICE: &str = "rd-engine.official-account.v1";
const ACCOUNT: &str = "master-key";
const LABEL: &str = "RustDesk engine private account master key";
const CONTENT_TYPE: &str = "application/octet-stream";
const METHOD_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn load_key(_root: &Path, namespace: &str) -> io::Result<Option<secretbox::Key>> {
    validate_namespace(namespace)?;
    let service = connect()?;
    match find_item(&service, namespace)? {
        Some(item) => read_key(&item, namespace).map(Some),
        None => {
            // An unavailable/locked default collection is not an empty key store.
            // Never provision a collection or fall back to the ephemeral session one.
            persistent_collection(&service)?;
            Ok(None)
        }
    }
}

pub(super) fn create_key(
    _root: &Path,
    namespace: &str,
    key: &secretbox::Key,
) -> io::Result<bool> {
    validate_namespace(namespace)?;
    let service = connect()?;
    if let Some(item) = find_item(&service, namespace)? {
        // An existing malformed/locked item must not masquerade as a usable winner.
        // The temporary Key is wiped by sodiumoxide's secret-key Drop implementation.
        read_key(&item, namespace)?;
        return Ok(false);
    }

    let collection = persistent_collection(&service)?;
    let created = collection
        .create_item_no_prompt(
            LABEL,
            attributes(namespace),
            key.as_ref(),
            false,
            CONTENT_TYPE,
        )
        .map_err(secret_error)?;

    // replace=false prevents overwrites, but Secret Service has no atomic
    // create-if-absent constraint on attributes. The caller's file lock elects
    // among our processes; reject external duplicate writers rather than choose
    // one or delete somebody else's item. Do not retry an uncertain create.
    let acknowledged = find_item(&service, namespace)?.ok_or_else(|| {
        io::Error::other("Secret Service did not acknowledge a discoverable account master key")
    })?;
    if acknowledged.item_path != created.item_path {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Secret Service account master-key creation has conflicting ownership",
        ));
    }
    let stored = read_key(&acknowledged, namespace)?;
    if !memcmp(stored.as_ref(), key.as_ref()) {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Secret Service did not preserve the supplied account master key",
        ));
    }

    // This is a provider-acknowledged, read-back creation in the persistent
    // collection. The protocol has no separate fsync/durability-attestation API.
    Ok(true)
}

fn validate_namespace(namespace: &str) -> io::Result<()> {
    if namespace.len() != 64
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "account master-key namespace must be a lowercase SHA-256 digest",
        ));
    }
    Ok(())
}

fn attributes(namespace: &str) -> HashMap<&str, &str> {
    HashMap::from([
        ("service", SERVICE),
        ("account", ACCOUNT),
        ("profile", namespace),
    ])
}

fn connect<'a>() -> io::Result<SecretService<'a>> {
    let connection = zbus::blocking::connection::Builder::session()
        .map_err(zbus_error)?
        .method_timeout(METHOD_TIMEOUT)
        .build()
        .map_err(zbus_error)?;
    // The maintained blocking async-io backend owns its I/O. No nested Tokio
    // runtime/block_on, external helper, manual activation, or Plain fallback.
    SecretService::connect_with_existing(EncryptionType::Dh, connection).map_err(secret_error)
}

fn find_item<'a>(
    service: &'a SecretService<'a>,
    namespace: &str,
) -> io::Result<Option<Item<'a>>> {
    // Search the entire service, including locked matches. Searching only the
    // current default collection could orphan a key after an alias change.
    let mut items = service
        .search_items(attributes(namespace))
        .map_err(secret_error)?;
    match (items.unlocked.len(), items.locked.len()) {
        (0, 0) => Ok(None),
        (1, 0) => Ok(items.unlocked.pop()),
        (0, 1) => Err(locked_error()),
        _ => Err(io::Error::new(
            ErrorKind::InvalidData,
            "Secret Service contains ambiguous account master-key items",
        )),
    }
}

fn persistent_collection<'a>(service: &'a SecretService<'a>) -> io::Result<Collection<'a>> {
    let collection = service.get_default_collection().map_err(secret_error)?;
    if collection.is_locked().map_err(secret_error)? {
        return Err(locked_error());
    }
    match service.get_collection_by_alias("session") {
        Ok(session) if session.collection_path == collection.collection_path => {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "Secret Service default collection is session-only",
            ));
        }
        Ok(_) | Err(SecretError::NoResult) => {}
        Err(error) => return Err(secret_error(error)),
    }
    Ok(collection)
}

fn read_key(item: &Item<'_>, namespace: &str) -> io::Result<secretbox::Key> {
    if item.is_locked().map_err(secret_error)? {
        return Err(locked_error());
    }
    let actual = item.get_attributes().map_err(secret_error)?;
    for (name, expected) in attributes(namespace) {
        if actual.get(name).map(String::as_str) != Some(expected) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Secret Service account master-key attributes changed",
            ));
        }
    }
    if item.get_secret_content_type().map_err(secret_error)? != CONTENT_TYPE {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Secret Service account master key has an invalid content type",
        ));
    }
    let bytes = Zeroizing::new(item.get_secret().map_err(secret_error)?);
    secretbox::Key::from_slice(bytes.as_slice()).ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            "Secret Service account master key must contain exactly 32 bytes",
        )
    })
}

fn locked_error() -> io::Error {
    io::Error::new(
        ErrorKind::PermissionDenied,
        "Secret Service account key or collection is locked; unlocking is disabled",
    )
}

// Never retain/format the provider's error strings or reply messages: arbitrary
// service diagnostics can contain secret material. In particular, a missing bus
// socket/object is an error, never io::ErrorKind::NotFound/Ok(None).
fn secret_error(error: SecretError) -> io::Error {
    match error {
        SecretError::Locked => locked_error(),
        SecretError::Prompt => io::Error::new(
            ErrorKind::PermissionDenied,
            "Secret Service requires authorization; prompting is disabled",
        ),
        SecretError::Unavailable | SecretError::PromptDisconnected => io::Error::new(
            ErrorKind::NotConnected,
            "Secret Service or its user-session connection is unavailable",
        ),
        SecretError::NoResult => io::Error::new(
            ErrorKind::NotConnected,
            "Secret Service has no available default collection",
        ),
        SecretError::Crypto(_) | SecretError::Zvariant(_) => io::Error::new(
            ErrorKind::InvalidData,
            "Secret Service returned malformed account key data",
        ),
        SecretError::Zbus(error) => zbus_error(error),
        SecretError::ZbusFdo(error) => fdo_error(error),
        _ => io::Error::other("Secret Service account key operation failed"),
    }
}

fn zbus_error(error: zbus::Error) -> io::Error {
    match error {
        zbus::Error::MethodError(name, _, _) => remote_error(name.as_str()),
        zbus::Error::FDO(error) => fdo_error(*error),
        zbus::Error::InputOutput(error) => {
            let kind = match error.kind() {
                ErrorKind::NotFound => ErrorKind::NotConnected,
                kind => kind,
            };
            io::Error::new(kind, "Secret Service user-session transport failed")
        }
        zbus::Error::Address(_) => io::Error::new(
            ErrorKind::InvalidInput,
            "Secret Service user-session bus address is invalid",
        ),
        zbus::Error::Handshake(_) => io::Error::new(
            ErrorKind::PermissionDenied,
            "Secret Service user-session authentication failed",
        ),
        zbus::Error::InterfaceNotFound | zbus::Error::Unsupported => io::Error::new(
            ErrorKind::Unsupported,
            "Secret Service interface is unavailable",
        ),
        zbus::Error::Variant(_)
        | zbus::Error::InvalidField
        | zbus::Error::ExcessData
        | zbus::Error::IncorrectEndian
        | zbus::Error::InvalidReply
        | zbus::Error::MissingField => io::Error::new(
            ErrorKind::InvalidData,
            "Secret Service returned an invalid message",
        ),
        _ => io::Error::other("Secret Service user-session operation failed"),
    }
}

fn fdo_error(error: zbus::fdo::Error) -> io::Error {
    match error {
        zbus::fdo::Error::ZBus(error) => zbus_error(error),
        error => remote_error(error.name().as_str()),
    }
}

fn remote_error(name: &str) -> io::Error {
    let (kind, message) = match name {
        "org.freedesktop.Secret.Error.IsLocked" => return locked_error(),
        "org.freedesktop.DBus.Error.AccessDenied"
        | "org.freedesktop.DBus.Error.AuthFailed"
        | "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired" => (
            ErrorKind::PermissionDenied,
            "Secret Service denied account master-key access",
        ),
        "org.freedesktop.DBus.Error.ServiceUnknown"
        | "org.freedesktop.DBus.Error.NameHasNoOwner"
        | "org.freedesktop.DBus.Error.NoServer"
        | "org.freedesktop.DBus.Error.Disconnected"
        | "org.freedesktop.Secret.Error.NoSession" => (
            ErrorKind::NotConnected,
            "Secret Service or its user-session connection is unavailable",
        ),
        "org.freedesktop.DBus.Error.NoReply"
        | "org.freedesktop.DBus.Error.Timeout"
        | "org.freedesktop.DBus.Error.TimedOut" => (
            ErrorKind::TimedOut,
            "Secret Service account master-key operation timed out",
        ),
        "org.freedesktop.Secret.Error.NoSuchObject"
        | "org.freedesktop.DBus.Error.UnknownObject" => (
            ErrorKind::Interrupted,
            "Secret Service account key object disappeared during the operation",
        ),
        "org.freedesktop.DBus.Error.NotSupported"
        | "org.freedesktop.DBus.Error.UnknownMethod"
        | "org.freedesktop.DBus.Error.UnknownInterface" => (
            ErrorKind::Unsupported,
            "Secret Service does not support the required account key operation",
        ),
        _ => (
            ErrorKind::Other,
            "Secret Service rejected the account master-key operation",
        ),
    };
    io::Error::new(kind, message)
}
