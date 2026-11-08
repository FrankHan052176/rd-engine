//! RustDesk cursor messages retained for snapshot consumers, not frame input.
//! Bitmaps are optional untrusted peer data. A bounded FIFO remembers recent
//! IDs; a miss or invalid image clears the selection without ending the session.

use super::{MOUSE_DOWN, MOUSE_MOVE, MOUSE_UP, State, ViewerInput, lock};
use crate::{protocol::Protocol, session::SessionMode};
use base::message_proto::{CursorData, CursorPosition};
use std::{
    collections::VecDeque,
    io::Read,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
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
    fn decode(data: &CursorData) -> Option<Self> {
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
        let image = CursorImage::decode(&data);
        // A shared display's viewer is offered only what this viewer accepted.
        let accepted = image.is_some().then_some(data);
        let mut inner = lock(&self.inner);
        if self.cursor_active() && !inner.snapshot.closed {
            inner.cursor.data(id, image);
            self.forward_cursor.data(id, accepted);
        }
    }

    pub(super) fn cursor_id(&self, id: u64) {
        let mut inner = lock(&self.inner);
        if self.cursor_active() && !inner.snapshot.closed {
            inner.cursor.id(id);
            self.forward_cursor.id(id);
        }
    }

    pub(super) fn cursor_position(&self, position: CursorPosition) {
        // Lock order everywhere: pointer, then inner, then the share feed.
        let mut pointer = lock(&self.pointer);
        let mut inner = lock(&self.inner);
        if self.cursor_active() && !inner.snapshot.closed {
            // A sample taken before the peer applied B's last write must not
            // pull the one pointer back behind it.
            if pointer.emitted.is_some_and(|at| at.elapsed() < ECHO_GRACE) {
                return;
            }
            pointer.position = Some((position.x, position.y));
            self.forward_cursor.position(position.x, position.y);
            inner.cursor.position(position);
        }
    }
}

/// How long after B's own pointer write a position sample from the peer is not
/// believed: it may have been taken before the peer applied that write.
const ECHO_GRACE: Duration = Duration::from_millis(250);
const MOUSE_WHEEL: u32 = 3;
const MOUSE_TRACKPAD: u32 = 4;
const MOUSE_RELATIVE: u32 = 5;

/// One display's desktop-global rectangle: x, y, width, height.
pub(super) type Area = (i32, i32, i32, i32);

/// Who holds a button on the peer. B's own input, whether it travelled the
/// shared-pointer path or not, is one owner; each admitted share viewer (C) is
/// another, so one side letting go never lets go of the other's hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Owner {
    Local,
    Remote(u64),
}

/// How a queued event reaches the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Origin {
    /// Already in wire terms: the event is emitted as it was queued.
    Plain,
    /// A pointer intent (relative move, button at the pointer, wheel) that the
    /// writer resolves against the one pointer when the event is taken.
    Shared(Owner),
}

impl Origin {
    pub(super) fn owner(self) -> Owner {
        match self {
            Self::Plain => Owner::Local,
            Self::Shared(owner) => owner,
        }
    }
}

/// B's one desktop-global pointer, and which share viewer may currently drive it.
///
/// The position is what the one ordered writer last put on the wire, corrected
/// by a position the peer itself reported. It is a single value, so B's own
/// input and a share viewer's accumulate on the same pointer.
#[derive(Default)]
pub(super) struct Pointer {
    pub(super) position: Option<(i32, i32)>,
    emitted: Option<Instant>,
    /// The admitted share viewer allowed to drive the pointer, if any.
    pub(super) remote: Option<u64>,
    remotes: u64,
}

impl State {
    pub(super) fn pointer_position(&self) -> Option<(i32, i32)> {
        lock(&self.pointer).position
    }

    /// The desktop B's pointer may roam: the display B is watching together
    /// with every display the peer reports, not only a shared one.
    fn pointer_bounds(&self) -> Vec<Area> {
        let mut areas = Vec::new();
        if let Some(geometry) = lock(&self.inner).geometry {
            areas.push((geometry.x, geometry.y, geometry.width, geometry.height));
        }
        areas.extend(
            lock(&self.peer_displays)
                .iter()
                .map(|display| (display.x, display.y, display.width, display.height)),
        );
        areas.retain(|area| area.2 > 0 && area.3 > 0);
        areas
    }

    /// Whether `owner` may still drive the pointer or keep a hold.
    pub(super) fn owner_live(&self, owner: Owner) -> bool {
        match owner {
            Owner::Local => true,
            Owner::Remote(id) => lock(&self.pointer).remote == Some(id),
        }
    }

    /// Makes one admitted share viewer the pointer's remote owner, replacing a
    /// previous one: what that one still held is released by the writer.
    pub(super) fn begin_remote(&self) -> u64 {
        let id = {
            let mut pointer = lock(&self.pointer);
            pointer.remotes += 1;
            pointer.remote = Some(pointer.remotes);
            pointer.remotes
        };
        self.input.changed.notify_one();
        id
    }

    /// Ends one share viewer's claim; the writer releases what only it held.
    pub(super) fn end_remote(&self, id: u64) {
        {
            let mut pointer = lock(&self.pointer);
            if pointer.remote == Some(id) {
                pointer.remote = None;
            }
        }
        self.input.changed.notify_one();
    }

    /// Resolves one pointer intent into the wire event the writer emits, or
    /// `None` when there is nothing it may emit.
    ///
    /// A relative move accumulates on the one pointer and leaves as an absolute
    /// position inside the peer's real desktop; a button acts where that pointer
    /// is and never at a coordinate the sender supplied.
    pub(super) fn pointer_intent(&self, kind: u32, button: u32, x: i32, y: i32) -> Option<ViewerInput> {
        match kind {
            MOUSE_RELATIVE => {
                let bounds = self.pointer_bounds();
                // Without a real peer sample or a prior admitted write there
                // is no current position. Never fabricate a centre and warp.
                let from = self.pointer_position()?;
                let to = (from.0.saturating_add(x), from.1.saturating_add(y));
                let (x, y) = constrain(from, to, &bounds)?;
                Some(ViewerInput::Mouse { kind: MOUSE_MOVE, button: 0, x, y })
            }
            MOUSE_DOWN | MOUSE_UP => {
                let (x, y) = self.pointer_position()?;
                Some(ViewerInput::Mouse { kind, button, x, y })
            }
            MOUSE_WHEEL | MOUSE_TRACKPAD => Some(ViewerInput::Mouse { kind, button: 0, x, y }),
            _ => None,
        }
    }

    /// Records a pointer position the writer has put on the wire.
    ///
    /// The peer does not echo the position of the connection that is driving
    /// it, so this is what the share viewers are told. `follow` also publishes
    /// it to this viewer's own snapshot: it is B's authoritative position, not
    /// an acknowledgement from the peer.
    pub(super) fn pointer_emitted(&self, x: i32, y: i32, follow: bool) {
        let mut pointer = lock(&self.pointer);
        pointer.position = Some((x, y));
        // Only B's shared writer predicts the authoritative position. A plain
        // C button carries (0, 0) as a wire placeholder; it must never suppress
        // the actual position B sends back to C.
        pointer.emitted = follow.then(Instant::now);
        self.forward_cursor.position(x, y);
        if follow {
            let mut inner = lock(&self.inner);
            if self.cursor_active() && !inner.snapshot.closed {
                inner.cursor.position(CursorPosition { x, y, ..Default::default() });
            }
        }
    }
}

fn inside(area: &Area, (x, y): (i32, i32)) -> bool {
    let (x, y) = (i64::from(x), i64::from(y));
    (i64::from(area.0)..i64::from(area.0) + i64::from(area.2)).contains(&x)
        && (i64::from(area.1)..i64::from(area.1) + i64::from(area.3)).contains(&y)
}

/// The nearest point of `area` to `to`.
fn clamp(area: &Area, to: (i32, i32)) -> (i32, i32) {
    (
        to.0.clamp(area.0, area.0.saturating_add(area.2 - 1)),
        to.1.clamp(area.1, area.1.saturating_add(area.3 - 1)),
    )
}

/// Moves a pointer from `from` towards `to` inside the union of `areas`.
///
/// A move that stays on a display, or lands on another one, is taken as it is.
/// One that would leave every display stops at the edge of the display the
/// pointer is on (so it slides along that edge), and never jumps across a gap to
/// whichever display happens to be nearest. `None` means no display is known to
/// move on.
pub(super) fn constrain(from: (i32, i32), to: (i32, i32), areas: &[Area]) -> Option<(i32, i32)> {
    if areas.iter().any(|area| inside(area, to)) {
        return Some(to);
    }
    if let Some(home) = areas.iter().find(|area| inside(area, from)) {
        return Some(clamp(home, to));
    }
    // Not on any display (stale position): the nearest point of the desktop.
    areas.iter().map(|area| clamp(area, to)).min_by_key(|point| {
        let (dx, dy) = (i64::from(point.0) - i64::from(to.0), i64::from(point.1) - i64::from(to.1));
        dx * dx + dy * dy
    })
}
