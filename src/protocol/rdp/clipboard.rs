//! Text-only CLIPRDR backend. IronRDP owns channel negotiation, framing and
//! string encoding. This backend owns only delayed local text and user events.

use std::collections::VecDeque;
use std::fmt;

use ironrdp_cliprdr::backend::CliprdrBackend;
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags,
    FileContentsRequest, FileContentsResponse, FormatDataRequest, FormatDataResponse,
    LockDataId, OwnedFormatDataResponse,
};
use ironrdp_core::IntoOwned as _;
use zeroize::Zeroizing;

use super::RdpError;

pub(super) enum Action {
    Advertise,
    RequestUnicode,
    Respond(OwnedFormatDataResponse),
    RejectFile(u32),
    Text(String),
    Error(&'static str),
}

#[derive(Default)]
pub(super) struct TextClipboard {
    pub(super) actions: VecDeque<Action>,
    ready: bool,
    text: Option<Zeroizing<String>>,
    remote_unicode: bool,
    request_pending: bool,
    remote_changed: bool,
}

impl fmt::Debug for TextClipboard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TextClipboard").field("ready", &self.ready).finish_non_exhaustive()
    }
}

ironrdp_core::impl_as_any!(TextClipboard);

impl TextClipboard {
    pub(super) fn set_text(&mut self, text: &str) -> Result<(), RdpError> {
        if !self.ready {
            return Err(RdpError::Clipboard("channel not ready"));
        }
        self.text = Some(Zeroizing::new(text.to_owned()));
        self.actions.push_back(Action::Advertise);
        Ok(())
    }

    pub(super) fn formats(&self) -> Vec<ClipboardFormat> {
        if self.text.is_some() {
            vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]
        } else {
            Vec::new()
        }
    }

    fn request_remote(&mut self) {
        if self.remote_unicode && !self.request_pending {
            self.request_pending = true;
            self.remote_changed = false;
            self.actions.push_back(Action::RequestUnicode);
        }
    }
}

impl CliprdrBackend for TextClipboard {
    fn temporary_directory(&self) -> &str {
        // Empty is intentional: no filesystem or file redirection is offered.
        ""
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }

    fn on_ready(&mut self) {
        self.ready = true;
        self.request_remote();
    }

    fn on_request_format_list(&mut self) {
        self.actions.push_back(Action::Advertise);
    }

    fn on_format_list_response(&mut self, ok: bool) {
        if !ok {
            self.actions.push_back(Action::Error("remote rejected clipboard formats"));
        }
    }

    fn on_process_negotiated_capabilities(&mut self, _capabilities: ClipboardGeneralCapabilityFlags) {
        // Unicode text has no optional capability; Cliprdr selects short/long
        // format names itself. File and locking capabilities are never offered.
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        self.remote_unicode = available_formats.iter()
            .any(|format| format.id == ClipboardFormatId::CF_UNICODETEXT);
        self.remote_changed = self.request_pending;
        if self.ready {
            self.request_remote();
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        let response = match (&self.text, request.format) {
            (Some(text), ClipboardFormatId::CF_UNICODETEXT) => {
                FormatDataResponse::new_unicode_string(text)
            }
            _ => FormatDataResponse::new_error(),
        };
        self.actions.push_back(Action::Respond(response.into_owned()));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if !self.request_pending {
            self.actions.push_back(Action::Error("unsolicited clipboard data"));
            return;
        }
        self.request_pending = false;
        if self.remote_changed {
            // Do not publish an older copy after a new format list arrived.
            // Serializing requests also preserves CLIPRDR's single response
            // correlation slot when the remote clipboard changes quickly.
            self.request_remote();
            return;
        }
        if response.is_error() {
            self.actions.push_back(Action::Error("remote clipboard data unavailable"));
            return;
        }
        match response.to_unicode_string() {
            Ok(text) => self.actions.push_back(Action::Text(text)),
            Err(_) => self.actions.push_back(Action::Error("invalid Unicode clipboard data")),
        }
    }

    fn on_file_contents_request(&mut self, request: FileContentsRequest) {
        self.actions.push_back(Action::RejectFile(request.stream_id));
    }

    fn on_file_contents_response(&mut self, _response: FileContentsResponse<'_>) {
        self.actions.push_back(Action::Error("unsolicited file clipboard data"));
    }

    fn on_lock(&mut self, _data_id: LockDataId) {
        self.actions.push_back(Action::Error("file clipboard locking was not negotiated"));
    }

    fn on_unlock(&mut self, _data_id: LockDataId) {
        self.actions.push_back(Action::Error("file clipboard locking was not negotiated"));
    }
}
