//! RustDesk cursor messages retained for snapshot consumers, not frame input.
//! Bitmaps are optional untrusted peer data. A bounded FIFO remembers recent
//! IDs; a miss or invalid image clears the selection without ending the session.

use super::{State, lock};
use crate::{protocol::Protocol, session::SessionMode};
use base::message_proto::{CursorData, CursorPosition};
use std::{
    collections::VecDeque,
    io::Read,
    sync::{Arc, atomic::Ordering},
};

const MAX_CURSOR_EDGE: i32 = 512;
const MAX_CURSOR_RGBA_BYTES: usize = 512 * 512 * 4;
const MAX_CURSOR_COMPRESSED_BYTES: usize = 2 * MAX_CURSOR_RGBA_BYTES;
const MAX_CURSOR_IMAGES: usize = 256;
const MAX_CURSOR_CACHE_BYTES: usize = 16 * MAX_CURSOR_RGBA_BYTES;

/// A validated, decompressed peer bitmap. Snapshot clones share these bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct CursorImage {
    pub id: u64,
    pub hotx: i32,
    pub hoty: i32,
    pub width: i32,
    pub height: i32,
    pub rgba: Vec<u8>,
}

impl CursorImage {
    fn decode(data: CursorData) -> Option<Self> {
        if !(1..=MAX_CURSOR_EDGE).contains(&data.width)
            || !(1..=MAX_CURSOR_EDGE).contains(&data.height)
            || !(0..data.width).contains(&data.hotx)
            || !(0..data.height).contains(&data.hoty)
            || data.colors.len() > MAX_CURSOR_COMPRESSED_BYTES
        {
            return None;
        }
        let length = (data.width as usize)
            .checked_mul(data.height as usize)?
            .checked_mul(4)?;
        // Same streaming zstd mechanism as clipboard: bound both output and
        // decoder window, not just the length checked after decompression. The
        // official bulk compressor pledges its source size, so an accepted
        // bitmap never needs a window larger than its entire RGBA payload.
        let mut decoder = zstd::Decoder::new(&data.colors[..]).ok()?;
        let window_log = (usize::BITS - (length - 1).leading_zeros()).max(10);
        decoder.window_log_max(window_log).ok()?;
        let mut rgba = Vec::with_capacity(length + 1);
        decoder.take((length + 1) as u64).read_to_end(&mut rgba).ok()?;
        if rgba.len() != length {
            return None;
        }
        Some(Self {
            id: data.id,
            hotx: data.hotx,
            hoty: data.hoty,
            width: data.width,
            height: data.height,
            rgba,
        })
    }
}

/// Latest peer selection and global position. Revisions change only when the
/// corresponding observable value changes; no per-move event queue is retained.
#[derive(Debug, Clone, Default)]
pub struct CursorSnapshot {
    pub revision: u64,
    pub id: Option<u64>,
    pub image: Option<Arc<CursorImage>>,
    /// This selection arrived as CursorId, or its bitmap was refused/missing.
    pub from_id: bool,
    pub position_revision: u64,
    pub position: Option<(i32, i32)>,
}

#[derive(Default)]
pub(super) struct CursorState {
    snapshot: CursorSnapshot,
    images: VecDeque<Arc<CursorImage>>,
    bytes: usize,
}

impl CursorState {
    pub(super) fn snapshot(&self) -> CursorSnapshot {
        self.snapshot.clone()
    }

    fn data(&mut self, id: u64, image: Option<CursorImage>) {
        let previous = self.images.iter().position(|known| known.id == id);
        if let (Some(index), Some(image)) = (previous, image.as_ref()) {
            if self.images[index].as_ref() == image {
                self.select(id, Some(Arc::clone(&self.images[index])), false);
                return;
            }
        }
        if let Some(previous) = previous.and_then(|index| self.images.remove(index)) {
            self.bytes -= previous.rgba.len();
        }
        let Some(image) = image else {
            // Invalidate an old image for this ID too: a bad same-ID update
            // must not leave its previous bitmap masquerading as current data.
            self.select(id, None, true);
            return;
        };
        while self.bytes + image.rgba.len() > MAX_CURSOR_CACHE_BYTES
            || self.images.len() >= MAX_CURSOR_IMAGES
        {
            if let Some(oldest) = self.images.pop_front() {
                self.bytes -= oldest.rgba.len();
            }
        }
        let image = Arc::new(image);
        self.bytes += image.rgba.len();
        self.images.push_back(Arc::clone(&image));
        self.select(id, Some(image), false);
    }

    fn id(&mut self, id: u64) {
        let image = self.images.iter().find(|image| image.id == id).cloned();
        self.select(id, image, true);
    }

    fn select(&mut self, id: u64, image: Option<Arc<CursorImage>>, from_id: bool) {
        let same_image = match (&self.snapshot.image, &image) {
            (Some(known), Some(image)) => Arc::ptr_eq(known, image),
            (None, None) => true,
            _ => false,
        };
        if self.snapshot.id == Some(id) && same_image {
            return;
        }
        self.snapshot.revision = self.snapshot.revision.saturating_add(1);
        self.snapshot.id = Some(id);
        self.snapshot.image = image;
        self.snapshot.from_id = from_id;
    }

    fn position(&mut self, position: CursorPosition) {
        let position = (position.x, position.y);
        if self.snapshot.position != Some(position) {
            self.snapshot.position_revision = self.snapshot.position_revision.saturating_add(1);
            self.snapshot.position = Some(position);
        }
    }
}

impl State {
    pub(super) fn cursor_active(&self) -> bool {
        self.protocol == Protocol::RustDesk
            && self.mode == SessionMode::Desktop
            && self.authenticated.load(Ordering::Acquire)
            && !self.cancel.is_cancelled()
    }

    pub(super) fn cursor_data(&self, data: CursorData) {
        if !self.cursor_active() {
            return;
        }
        // No lock is held during decompression. A close racing it withdraws
        // authentication/cancels first; publication rechecks under Inner.
        let id = data.id;
        let image = CursorImage::decode(data);
        let mut inner = lock(&self.inner);
        if self.cursor_active() && !inner.snapshot.closed {
            inner.cursor.data(id, image);
        }
    }

    pub(super) fn cursor_id(&self, id: u64) {
        let mut inner = lock(&self.inner);
        if self.cursor_active() && !inner.snapshot.closed {
            inner.cursor.id(id);
        }
    }

    pub(super) fn cursor_position(&self, position: CursorPosition) {
        let mut inner = lock(&self.inner);
        if self.cursor_active() && !inner.snapshot.closed {
            inner.cursor.position(position);
        }
    }
}
