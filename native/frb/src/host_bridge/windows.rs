//! Windows transport adapter for the pinned RustDesk IPC/auth contract.
//! Source: rustdesk 092a961b629d318fe290eeafac0cd214a1e9deeb src/ipc/auth.rs
//! (canonical executable / OS peer PID / session checks), AGPL-3.0-only.
//! Unlike upstream's service exceptions, this portable endpoint accepts ONLY the
//! same user AND logon AND terminal session AND packaged executable, both ways.
//! Framing reuses the pinned hbb_common BytesCodec; no upstream application IPC
//! commands, SYSTEM exception, impersonation, or general configuration RPC.
use anyhow::{ensure, Context, Result};
use hbb_common::{bytes::{Bytes, BytesMut}, bytes_codec::BytesCodec, sha2::{Digest, Sha256}, tokio_util::codec::{Decoder, Encoder}};
use serde::{de::DeserializeOwned, Serialize};
use std::{ffi::OsString, io::{self, Write}, mem::{size_of, zeroed}, os::windows::ffi::OsStringExt, path::{Path, PathBuf}, ptr::{null, null_mut}, time::{Duration, Instant}};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, LocalFree, HANDLE, INVALID_HANDLE_VALUE, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, WAIT_OBJECT_0, WAIT_TIMEOUT, GENERIC_READ, GENERIC_WRITE},
    Security::{Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW}, GetTokenInformation, TokenGroups, TokenSessionId, TokenStatistics, TokenUser, PSID, SECURITY_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER},
    Storage::FileSystem::{CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT},
    System::{IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED}, Pipes::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_READMODE_BYTE, PIPE_WAIT}, SystemInformation::GetTickCount64, Threading::{CreateEventW, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE}},
};

// Includes the core's bounded options (256 * 4096 bytes, JSON escaping included).
pub(super) const MAX_FRAME: usize = 8 * 1024 * 1024;
const TOKEN_LIMIT: usize = 64 * 1024;

pub(super) fn uptime_ms() -> u64 { unsafe { GetTickCount64() } }

struct LimitedFrame(Vec<u8>);
impl Write for LimitedFrame {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_FRAME.saturating_sub(self.0.len()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "IPC frame exceeds limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

struct Handle(HANDLE);
// Each handle is moved, never shared with concurrent operations. Windows process,
// event and pipe handles are not thread-affine.
unsafe impl Send for Handle {}
impl Handle {
    fn checked(value: HANDLE) -> Result<Self> {
        ensure!(!value.is_null() && value != INVALID_HANDLE_VALUE, "Windows handle: {}", std::io::Error::last_os_error());
        Ok(Self(value))
    }
}
impl Drop for Handle { fn drop(&mut self) { unsafe { CloseHandle(self.0); } } }

#[derive(Clone)]
pub(super) struct Identity {
    user: String,
    logon: String,
    authentication: (u32, i32),
    session: u32,
    pub exe: PathBuf,
}

fn token_data(token: HANDLE, class: i32) -> Result<Vec<u64>> {
    let mut needed = 0;
    unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut needed); }
    ensure!((1..=TOKEN_LIMIT).contains(&(needed as usize)), "invalid token information size");
    // Aligned for both native pointers and TOKEN_STATISTICS' i64 on Win32/64.
    let mut data = vec![0u64; (needed as usize + size_of::<u64>() - 1) / size_of::<u64>()];
    ensure!(unsafe { GetTokenInformation(token, class, data.as_mut_ptr().cast(), needed, &mut needed) } != 0, "cannot read Windows token");
    Ok(data)
}
// ConvertSidToStringSidW has already validated the binary SID. This checks
// only that its text is safe to insert as an SDDL trustee, not SID validity.
fn sid_text_has_safe_syntax(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-1-") else { return false; };
    let mut fields = rest.split('-');
    let Some(authority) = fields.next() else { return false; };
    let decimal = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    let authority_valid = if let Some(hex) = authority.strip_prefix("0x") {
        (1..=12).contains(&hex.len()) && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    } else {
        decimal(authority)
    };
    authority_valid && fields.all(decimal)
}

fn sid_string(sid: PSID) -> Result<String> {
    let mut raw = null_mut();
    ensure!(unsafe { ConvertSidToStringSidW(sid, &mut raw) } != 0, "cannot read Windows SID");
    let result = unsafe {
        let mut length = 0;
        while length < 256 && *raw.add(length) != 0 { length += 1; }
        if length == 256 { Err(anyhow::anyhow!("invalid SID length")) }
        else { String::from_utf16(std::slice::from_raw_parts(raw, length)).map_err(Into::into) }
    };
    unsafe { LocalFree(raw.cast()); }
    let result = result?;
    ensure!(sid_text_has_safe_syntax(&result), "invalid SID syntax");
    Ok(result)
}
fn normalized(path: &Path) -> String {
    let path = path.to_string_lossy().replace('/', "\\");
    path.strip_prefix(r"\\?\").unwrap_or(&path).to_ascii_lowercase()
}
impl Identity {
    fn of_process(process: HANDLE) -> Result<Self> {
        let mut token = null_mut();
        ensure!(unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } != 0, "cannot open peer token");
        let token = Handle::checked(token)?;
        let user_data = token_data(token.0, TokenUser)?;
        ensure!(user_data.len() * size_of::<u64>() >= size_of::<TOKEN_USER>(), "short user token");
        let user = sid_string(unsafe { (&*user_data.as_ptr().cast::<TOKEN_USER>()).User.Sid })?;
        let groups_data = token_data(token.0, TokenGroups)?;
        ensure!(groups_data.len() * size_of::<u64>() >= size_of::<TOKEN_GROUPS>(), "short groups token");
        let groups = unsafe { &*groups_data.as_ptr().cast::<TOKEN_GROUPS>() };
        let count = groups.GroupCount as usize;
        let group_offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
        let group_bytes = count.checked_mul(size_of::<windows_sys::Win32::Security::SID_AND_ATTRIBUTES>()).and_then(|size| group_offset.checked_add(size)).context("token groups overflow")?;
        ensure!(group_bytes <= groups_data.len() * size_of::<u64>(), "invalid groups token");
        let entries = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), count) };
        let group = entries.iter().find(|g| g.Attributes & 0xc0000000 == 0xc0000000).context("process has no interactive logon SID")?;
        let logon = sid_string(group.Sid)?;
        let stats_data = token_data(token.0, TokenStatistics)?;
        ensure!(stats_data.len() * size_of::<u64>() >= size_of::<TOKEN_STATISTICS>(), "short statistics token");
        let stats = unsafe { &*stats_data.as_ptr().cast::<TOKEN_STATISTICS>() };
        let session_data = token_data(token.0, TokenSessionId)?;
        let session = unsafe { *session_data.as_ptr().cast::<u32>() };
        let mut path = vec![0u16; 32768];
        let mut length = path.len() as u32;
        ensure!(unsafe { QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut length) } != 0, "cannot resolve peer executable");
        path.truncate(length as usize);
        let exe = std::fs::canonicalize(PathBuf::from(OsString::from_wide(&path))).context("cannot canonicalize packaged executable")?;
        Ok(Self { user, logon, authentication: (stats.AuthenticationId.LowPart, stats.AuthenticationId.HighPart), session, exe })
    }
    pub fn current() -> Result<Self> {
        let process = open_process(std::process::id())?;
        Self::of_process(process.0)
    }
    fn endpoint(&self) -> Vec<u16> {
        let digest = Sha256::digest(format!("{}\0{}\0{}\0{}", normalized(&self.exe), self.user, self.logon, self.session).as_bytes());
        let hash: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        format!(r"\\.\pipe\rd-engine-host-v1-{hash}").encode_utf16().chain(Some(0)).collect()
    }
    fn permits(&self, peer: &Self) -> bool {
        self.user == peer.user && self.logon == peer.logon && self.authentication == peer.authentication && self.session == peer.session && normalized(&self.exe) == normalized(&peer.exe)
    }
}
fn open_process(pid: u32) -> Result<Handle> {
    ensure!(pid != 0, "missing OS peer PID");
    Handle::checked(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, 0, pid) })
}

pub(super) struct Peer { process: Handle }
impl Peer {
    pub fn alive(&self) -> Result<()> {
        ensure!(unsafe { WaitForSingleObject(self.process.0, 0) } == WAIT_TIMEOUT, "authenticated IPC process exited");
        Ok(())
    }
}

pub(super) struct Pipe { handle: Handle, codec: BytesCodec, input: BytesMut }
impl Pipe {
    fn new(handle: Handle) -> Self {
        let mut codec = BytesCodec::new();
        codec.set_max_packet_length(MAX_FRAME);
        Self { handle, codec, input: BytesMut::new() }
    }
    pub fn reserve(identity: &Identity) -> Result<Self> {
        // Protected DACL, no inherited ACEs, no world/administrator/SYSTEM bypass.
        // One held first-instance pipe excludes an alternate owner for its lifetime.
        let sddl: Vec<u16> = format!("D:P(A;;GA;;;{})", identity.logon).encode_utf16().chain(Some(0)).collect();
        let mut descriptor = null_mut();
        ensure!(unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut descriptor, null_mut()) } != 0, "cannot construct host pipe DACL");
        let security = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: descriptor, bInheritHandle: 0 };
        let handle = unsafe { CreateNamedPipeW(identity.endpoint().as_ptr(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 3000, &security) };
        let error = std::io::Error::last_os_error();
        unsafe { LocalFree(descriptor); }
        ensure!(handle != INVALID_HANDLE_VALUE, "cannot reserve unique host endpoint: {error}");
        Ok(Self::new(Handle::checked(handle)?))
    }
    pub fn connect(identity: &Identity) -> Result<Self> {
        // SQOS identification prevents even a malicious endpoint impersonating CM.
        let handle = unsafe { CreateFileW(identity.endpoint().as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, null(), OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, null_mut()) };
        Ok(Self::new(Handle::checked(handle).context("host endpoint unavailable")?))
    }
    pub fn authenticate(&self, identity: &Identity, server_side: bool) -> Result<Peer> {
        let mut pid = 0;
        let ok = unsafe { if server_side { GetNamedPipeClientProcessId(self.handle.0, &mut pid) } else { GetNamedPipeServerProcessId(self.handle.0, &mut pid) } };
        ensure!(ok != 0, "cannot resolve OS pipe peer PID");
        let process = open_process(pid)?;
        let peer = Identity::of_process(process.0)?;
        ensure!(identity.permits(&peer), "IPC peer user/logon/session/executable rejected");
        let result = Peer { process };
        result.alive()?;
        Ok(result)
    }
    fn operation(&self, deadline: Instant, start: impl FnOnce(*mut OVERLAPPED) -> i32, connecting: bool) -> Result<usize> {
        ensure!(Instant::now() < deadline, "IPC operation expired");
        let event = Handle::checked(unsafe { CreateEventW(null(), 1, 0, null()) })?;
        let mut overlapped: OVERLAPPED = unsafe { zeroed() };
        overlapped.hEvent = event.0;
        let immediate = start(&mut overlapped);
        if immediate == 0 {
            let error = unsafe { GetLastError() };
            if connecting && error == ERROR_PIPE_CONNECTED { return Ok(0); }
            ensure!(error == ERROR_IO_PENDING, "IPC native operation failed: {}", std::io::Error::from_raw_os_error(error as i32));
        }
        let millis = deadline.saturating_duration_since(Instant::now()).as_millis().min(u32::MAX as u128 - 1) as u32;
        let waited = unsafe { WaitForSingleObject(event.0, millis) };
        let mut transferred = 0;
        if waited != WAIT_OBJECT_0 {
            let error = if waited == WAIT_TIMEOUT { io::Error::new(io::ErrorKind::TimedOut, "IPC operation timed out; outcome not assumed") } else { io::Error::last_os_error() };
            // OVERLAPPED and its buffer may not be released until cancellation is
            // actually acknowledged, including a completion racing the deadline.
            unsafe { CancelIoEx(self.handle.0, &overlapped); GetOverlappedResult(self.handle.0, &overlapped, &mut transferred, 1); }
            return Err(error.into());
        }
        ensure!(unsafe { GetOverlappedResult(self.handle.0, &overlapped, &mut transferred, 0) } != 0, "IPC completion failed: {}", std::io::Error::last_os_error());
        Ok(transferred as usize)
    }
    pub fn accept(&mut self) -> Result<bool> {
        match self.operation(Instant::now() + Duration::from_millis(500), |overlapped| unsafe { ConnectNamedPipe(self.handle.0, overlapped) }, true) {
            Ok(_) => Ok(true),
            Err(error) if error.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::TimedOut) => Ok(false),
            Err(error) => Err(error),
        }
    }
    pub fn disconnect(&mut self) -> Result<()> {
        if unsafe { DisconnectNamedPipe(self.handle.0) } == 0 {
            let error = unsafe { GetLastError() };
            ensure!(error == ERROR_PIPE_NOT_CONNECTED, "IPC disconnect failed: {}", io::Error::from_raw_os_error(error as i32));
        }
        self.input.clear();
        self.codec = BytesCodec::new();
        self.codec.set_max_packet_length(MAX_FRAME);
        Ok(())
    }
    pub fn send<T: Serialize>(&mut self, value: &T, deadline: Instant) -> Result<()> {
        let mut data = LimitedFrame(Vec::with_capacity(4096));
        serde_json::to_writer(&mut data, value).context("IPC serialization failed or exceeded limit")?;
        ensure!(!data.0.is_empty(), "empty IPC frame");
        let mut frame = BytesMut::with_capacity(data.0.len() + 4);
        self.codec.encode(Bytes::from(data.0), &mut frame)?;
        let mut offset = 0;
        while offset < frame.len() {
            let part = &frame[offset..];
            let n = self.operation(deadline, |overlapped| unsafe { WriteFile(self.handle.0, part.as_ptr(), part.len() as u32, null_mut(), overlapped) }, false)?;
            ensure!(n > 0, "IPC write made no progress");
            offset += n;
        }
        Ok(())
    }
    pub fn receive<T: DeserializeOwned>(&mut self, deadline: Instant, limit: usize) -> Result<T> {
        ensure!(limit > 0 && limit <= MAX_FRAME, "invalid IPC frame limit");
        self.codec.set_max_packet_length(limit);
        loop {
            if let Some(frame) = self.codec.decode(&mut self.input)? {
                // Do not echo malformed payloads (even a hostile client may send secrets).
                return serde_json::from_slice(&frame).map_err(|_| anyhow::anyhow!("invalid or unsupported IPC message"));
            }
            let mut data = [0u8; 8192];
            let n = self.operation(deadline, |overlapped| unsafe { ReadFile(self.handle.0, data.as_mut_ptr(), data.len() as u32, null_mut(), overlapped) }, false)?;
            ensure!(n > 0 && self.input.len() + n <= limit + 4, "IPC closed or frame exceeds limit");
            self.input.extend_from_slice(&data[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sid_text_has_safe_syntax;

    #[test]
    fn accepts_windows_user_and_logon_sid_text() {
        assert!(sid_text_has_safe_syntax("S-1-5-21-111-222-333-1001"));
        assert!(sid_text_has_safe_syntax("S-1-5-5-0-12345"));
        // Larger identifier authorities are written in hexadecimal by Windows.
        assert!(sid_text_has_safe_syntax("S-1-0x28651FE848-12-72-9-110"));
        assert!(sid_text_has_safe_syntax("S-1-5")); // Valid authority-only SID.
    }

    #[test]
    fn rejects_malformed_or_sddl_injecting_sid_text() {
        for value in ["S-2-5-7", "S-1-", "S-1-5-", "S-1-5--7", "S-1-0x-7", "S-1-5-0x10", "S-1-5-7)(A;;GA;;;WD)"] {
            assert!(!sid_text_has_safe_syntax(value), "accepted {value:?}");
        }
    }
}
