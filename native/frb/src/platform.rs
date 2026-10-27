//! The two platform operations the official client asks its native library for.
//!
//! Reused in their minimal necessary form from the pinned upstream
//! `src/platform/windows.rs` (092a961b629d318fe290eeafac0cd214a1e9deeb,
//! AGPL-3.0-only):
//!
//! * `create_shortcut` (`windows.rs:2257`) writes the `--connect <id>` desktop
//!   shortcut the client's peer menu offers (`common/widgets/peer_card.dart:686`).
//! * `is_installed` (`windows.rs:1926`) with the install-path probe it reads:
//!   `get_valid_subkey` (`windows.rs:1314`), `get_install_info_with_subkey`
//!   (`windows.rs:1452`), `get_default_install_path` (`windows.rs:1390`) and
//!   `get_reg_of` (`windows.rs:1936`).
//! * the validator an id passes before it becomes a file name, a script body or
//!   an argument list: `is_valid_untrusted_peer_id` (`src/common.rs:2809`).
//!
//! Nothing else from the official platform layer is copied. This library is a
//! viewer, not the application: no service, installer, updater, elevation,
//! registry write or system setting is reachable from here, and `create_shortcut`
//! is the only entry that writes anything at all.
//!
//! The Windows branch needs one dependency the rest of the bridge does not:
//! `winreg`, declared for Windows targets only. That is the crate upstream pins
//! (`Cargo.toml:147`, 0.11), and it refuses to build off Windows, so it cannot be
//! an unconditional dependency here.

use anyhow::bail;
#[cfg(target_os = "windows")]
use anyhow::Context;
#[cfg(target_os = "windows")]
use std::io::Write;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
use crate::client_compat::APP_NAME;

// ---------------------------------------------------------------------------
// Untrusted peer ids
// ---------------------------------------------------------------------------

/// Upstream `src/common.rs:2802`: the server's own peer-id length limit.
#[cfg(target_os = "windows")]
const MAX_UNTRUSTED_PEER_ID_LEN: usize = 253;

/// Upstream `src/common.rs:2803`: characters that must never reach a file name,
/// a script body or an argument list from an id the peer chose.
#[cfg(target_os = "windows")]
const UNTRUSTED_PEER_ID_FORBIDDEN_CHARS: &[char] = &['"', '<', '>', '/', '\\', '|', '?', '*'];

/// Upstream `src/common.rs:2809` `is_valid_untrusted_peer_id`, unchanged: an id
/// is usable only when it is non-empty, within the server's limit, and free of
/// control characters, whitespace and the characters above. `:` is deliberately
/// allowed - the server issues ids that contain one.
///
/// Windows-only here because the shortcut script is the only place in this
/// library where an id becomes a file name and an argument list; ids that reach
/// the engine are validated by the engine.
#[cfg(target_os = "windows")]
fn is_valid_untrusted_peer_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_UNTRUSTED_PEER_ID_LEN
        && !id.chars().any(|ch| {
            ch.is_control() || ch.is_whitespace() || UNTRUSTED_PEER_ID_FORBIDDEN_CHARS.contains(&ch)
        })
}

// ---------------------------------------------------------------------------
// Desktop shortcut
// ---------------------------------------------------------------------------

/// Create the peer's desktop connection shortcut, upstream
/// `src/platform/windows.rs:2257`.
///
/// Windows only, as upstream is: its Flutter FFI entry is `#[cfg(windows)]`
/// (`src/ui_interface.rs:772`) and the client offers the menu item only on
/// Windows (`peer_card.dart:992`). Everywhere else this refuses by name instead
/// of writing a shortcut that does not exist on that platform.
///
/// The shortcut targets `std::env::current_exe()`, which is the client process
/// that loaded this library - the same process-relative target upstream uses,
/// because upstream's copy of this function lives in the client binary itself.
#[cfg(target_os = "windows")]
pub fn create_shortcut(id: &str) -> anyhow::Result<()> {
    if !is_valid_untrusted_peer_id(id) {
        bail!("Invalid peer id for shortcut");
    }
    let exe = std::env::current_exe().context("current exe")?;
    // Upstream reads this with `to_str().unwrap_or("")` and would then write a
    // shortcut with an empty target; a path that cannot round-trip through the
    // script is reported instead of saved broken.
    let exe = exe
        .to_str()
        .filter(|p| !p.is_empty())
        .context("current exe path is not valid UTF-8")?;

    // `:` cannot appear in a Windows file name. Upstream renames it for the
    // shortcut file only (`windows.rs:2265`, rustdesk#13735); the id itself still
    // reaches the client unchanged.
    let link_name = id.replace(':', "_");
    let script_path = write_vbs(&shortcut_script(exe, id, &link_name))?;
    let output = std::process::Command::new("cscript")
        .arg(&script_path)
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    // The script holds no secret and cscript has read it by now.
    let _ = std::fs::remove_file(&script_path);
    let output = output.context("run cscript")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut detail = stderr.trim().to_owned();
        if detail.is_empty() {
            detail = stdout.trim().to_owned();
        }
        if detail.is_empty() {
            detail = "no output".to_owned();
        }
        bail!(
            "cscript could not create the desktop shortcut for {id} ({}): {detail}",
            output.status
        );
    }
    Ok(())
}

/// Upstream has no non-Windows entry point for this and the client never calls
/// it there, so the honest answer is a named refusal rather than a reported
/// success.
#[cfg(not(target_os = "windows"))]
pub fn create_shortcut(_id: &str) -> anyhow::Result<()> {
    hbb_common::log::error!(
        "main_create_shortcut: unsupported on {}",
        std::env::consts::OS
    );
    bail!("unsupported: main_create_shortcut")
}

/// Upstream `src/platform/windows.rs:2267-2282`, with the icon line the official
/// code interpolates left out: `get_shortcut_icon_location` yields a path only
/// for a custom client (`windows.rs:2240` `get_custom_icon` behind
/// `src/common.rs:2429` `is_custom_client`), and this library serves the official
/// name, for which it is the empty string.
///
/// Three differences from upstream, all so that a failure cannot pass as success:
/// the script refuses to save a link when the shell resolved no desktop folder,
/// it checks that the link it just saved exists, and it exits non-zero with a
/// message otherwise, while the caller waits for that exit status. The client
/// shows "Successful" for this call without awaiting it (`peer_card.dart:686-700`),
/// so a silent no-op is indistinguishable from a created shortcut to the user.
#[cfg(target_os = "windows")]
fn shortcut_script(exe: &str, id: &str, link_name: &str) -> String {
    format!(
        "
Set oWS = WScript.CreateObject(\"WScript.Shell\")
strDesktop = oWS.SpecialFolders(\"Desktop\")
If Len(strDesktop) = 0 Then
    WScript.StdErr.WriteLine \"No desktop folder to write the shortcut to\"
    WScript.Quit 1
End If
Set objFSO = CreateObject(\"Scripting.FileSystemObject\")
sLinkFile = objFSO.BuildPath(strDesktop, \"{link_name}.lnk\")
Set oLink = oWS.CreateShortcut(sLinkFile)
    oLink.TargetPath = \"{exe}\"
    oLink.Arguments = \"--connect {id}\"
oLink.Save
If Not objFSO.FileExists(sLinkFile) Then
    WScript.StdErr.WriteLine \"Shortcut was not created: \" & sLinkFile
    WScript.Quit 1
End If
"
    )
}

/// Upstream `src/platform/windows.rs:1865` `write_vbs`, minus its
/// shell-metacharacter fallback: the path is handed to `cscript` as an argument
/// and never through `cmd.exe`, so a `&`, `@` or `^` in the temp path cannot
/// reach a shell. The body is written UTF-16LE with a BOM, the encoding the
/// scripting host needs to read a path or id that is not ASCII. The byte layout is
/// upstream's; the little-endian conversion is written as a plain byte map
/// instead of upstream's in-place `align_to`, which would need `unsafe`.
#[cfg(target_os = "windows")]
fn write_vbs(script: &str) -> anyhow::Result<std::path::PathBuf> {
    const UTF16LE_BOM: &[u8] = &[0xFF, 0xFE];
    let mut path = std::env::temp_dir();
    // FRB calls may run concurrently; never overwrite another request's script.
    path.push(format!(
        "{APP_NAME}_connect_shortcut_{}.vbs",
        uuid::Uuid::new_v4()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("create {}", path.display()))?;
    let script = script.replace("\r\n", "\n").replace('\n', "\r\n");
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let written = file
        .write_all(UTF16LE_BOM)
        .and_then(|()| file.write_all(&utf16))
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&path);
        return Err(error).context("write shortcut script");
    }
    Ok(path)
}

/// `CREATE_NO_WINDOW` from `winbase.h`: the short-lived scripting host must not
/// flash a console in front of the client. Upstream takes the constant from the
/// `windows` crate; the value is fixed by the Win32 ABI, so it is spelled here
/// rather than adding that crate to a bridge that needs nothing else from it.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

// ---------------------------------------------------------------------------
// Installation state
// ---------------------------------------------------------------------------

/// Is the RustDesk client installed on this machine, upstream
/// `src/platform/windows.rs:1926`: the install key's `InstallLocation`, else the
/// default install path, then the client exe that path names.
///
/// This reads HKLM and the file system only. It never starts, stops or installs
/// anything, and an unreadable key or a missing exe is simply "not installed",
/// which is upstream's answer as well.
#[cfg(target_os = "windows")]
pub fn is_installed() -> bool {
    std::fs::metadata(installed_exe()).is_ok()
}

/// Everything outside Windows answers this artifact's own boundary, and the
/// answer is false: this build ships no installer, no service, no daemon and no
/// updater, so there is no installed deployment of it to report, and the official
/// client's consumers of this query are all about the installed deployment
/// (the install card and update card on the home page, `desktop_home_page.dart:435`
/// and `:461`; the settings that an installed build locks behind the service,
/// `desktop_setting_page.dart:981` and `:1748`).
///
/// It is a query, not an operation: refusing it as unsupported made the official
/// pages that read it while building throw. This is the same answer the official
/// client gives when it runs unpackaged, and it is the state of this build on
/// every non-Windows target.
#[cfg(not(target_os = "windows"))]
pub fn is_installed() -> bool {
    false
}

/// Upstream `src/platform/windows.rs:1452` `get_install_info_with_subkey`'s path
/// and exe, the only two of its four values this query needs.
#[cfg(target_os = "windows")]
fn installed_exe() -> String {
    let mut path = reg_value(&valid_install_subkey(), "InstallLocation");
    if path.is_empty() {
        path = default_install_path();
    }
    let path = path.trim_end_matches('\\');
    format!("{path}\\{APP_NAME}.exe")
}

/// Upstream `src/platform/windows.rs:1314` `get_valid_subkey`: the first install
/// key that carries an `InstallLocation`, in the official order, ending on the
/// plain uninstall key.
#[cfg(target_os = "windows")]
fn valid_install_subkey() -> String {
    let subkey = format!("{HKLM_PREFIX}Software\\{APP_NAME}\\InstallState\\{APP_NAME}");
    if !reg_value(&subkey, "InstallLocation").is_empty() {
        return subkey;
    }
    for subkey in [
        uninstall_subkey(IS1, false),
        uninstall_subkey(IS1, true),
        uninstall_subkey(APP_NAME, true),
    ] {
        if !reg_value(&subkey, "InstallLocation").is_empty() {
            return subkey;
        }
    }
    uninstall_subkey(APP_NAME, false)
}

/// Upstream `src/platform/windows.rs:1303` `get_subkey`.
#[cfg(target_os = "windows")]
fn uninstall_subkey(name: &str, wow: bool) -> String {
    let subkey = format!(
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{name}"
    );
    if wow {
        subkey.replace("Microsoft", "Wow6432Node\\Microsoft")
    } else {
        subkey
    }
}

/// Upstream `src/platform/windows.rs:1390` `get_default_install_path`.
#[cfg(target_os = "windows")]
fn default_install_path() -> String {
    let mut pf = "C:\\Program Files".to_owned();
    if let Ok(x) = std::env::var("ProgramFiles") {
        if std::path::Path::new(&x).exists() {
            pf = x;
        }
    }
    #[cfg(target_pointer_width = "32")]
    {
        let tmp = pf.replace("Program Files", "Program Files (x86)");
        if std::path::Path::new(&tmp).exists() {
            pf = tmp;
        }
    }
    format!("{pf}\\{APP_NAME}")
}

/// Upstream `src/platform/windows.rs:1936` `get_reg_of`, reduced to the value:
/// a key that cannot be opened, or a value that is not there or is not a string,
/// reads as empty, which is how the callers above spell "no install location
/// recorded".
#[cfg(target_os = "windows")]
fn reg_value(subkey: &str, name: &str) -> String {
    let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(subkey.replace(HKLM_PREFIX, "")) {
        if let Ok(value) = key.get_value(name) {
            return value;
        }
    }
    Default::default()
}

/// Upstream `src/platform/windows.rs:128`.
#[cfg(target_os = "windows")]
const HKLM_PREFIX: &str = "HKEY_LOCAL_MACHINE\\";

/// Upstream `src/platform/windows.rs:1301`: the Inno Setup uninstall key.
#[cfg(target_os = "windows")]
const IS1: &str = "{54E86BC2-6C85-41F3-A9EB-1A94AC9B1F93}_is1";
