//! CPU frame loan for the pinned official client's get-size/get-pointer/next protocol.
//! A published allocation is immutable until nextRgba. Close is NOT a release.
use rd_engine::protocol::rect::Rect;
use std::sync::{Mutex, MutexGuard};

#[derive(Default)]
pub(crate) struct FrameStore {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    pending: Vec<u8>,
    width: i32,
    height: i32,
    dirty: bool,
    front: Vec<u8>,
    outstanding: bool,
    borrowed: bool,
    closed: bool,
    generation: u64,
}

impl FrameStore {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// Invalidate callbacks from the old viewer without touching an outstanding loan.
    pub(crate) fn restart(&self) -> u64 {
        let mut state = self.lock();
        state.generation = state.generation.wrapping_add(1);
        state.pending.clear();
        state.width = 0;
        state.height = 0;
        state.dirty = false;
        state.generation
    }

    pub(crate) fn present(
        &self,
        generation: u64,
        width: i32,
        height: i32,
        stride: usize,
        bytes: &[u8],
        damage: Rect,
    ) -> bool {
        if width <= 0
            || height <= 0
            || damage.width <= 0
            || damage.height <= 0
            || damage.x < 0
            || damage.y < 0
        {
            return false;
        }
        let Some(row_bytes) = (width as usize).checked_mul(4) else {
            return false;
        };
        let Some(frame_bytes) = row_bytes.checked_mul(height as usize) else {
            return false;
        };
        let Some(source_bytes) = stride.checked_mul(height as usize) else {
            return false;
        };
        let right = i64::from(damage.x) + i64::from(damage.width);
        let bottom = i64::from(damage.y) + i64::from(damage.height);
        if stride < row_bytes
            || bytes.len() < source_bytes
            || right > i64::from(width)
            || bottom > i64::from(height)
        {
            return false;
        }
        let mut state = self.lock();
        if state.closed || generation != state.generation {
            return false;
        }
        if state.width != width || state.height != height {
            state.pending.resize(frame_bytes, 0);
            state.pending.fill(0);
            state.width = width;
            state.height = height;
        }
        let start_column = damage.x as usize * 4;
        let copy_bytes = damage.width as usize * 4;
        for row in damage.y as usize..bottom as usize {
            let source_start = row * stride + start_column;
            let target_start = row * row_bytes + start_column;
            let source = &bytes[source_start..source_start + copy_bytes];
            let target = &mut state.pending[target_start..target_start + copy_bytes];
            // Pinned model.dart decodes RGBA on Windows/Linux and BGRA on macOS/iOS.
            if cfg!(any(target_os = "windows", target_os = "linux")) {
                for (pixel, output) in source.chunks_exact(4).zip(target.chunks_exact_mut(4)) {
                    output.copy_from_slice(&[pixel[2], pixel[1], pixel[0], pixel[3]]);
                }
            } else {
                target.copy_from_slice(source);
            }
        }
        state.dirty = true;
        true
    }

    /// At most one event is in flight. Producer callbacks touch only pending.
    pub(crate) fn publish(&self) -> Option<(i32, i32)> {
        let mut state = self.lock();
        if state.closed || state.outstanding || !state.dirty {
            return None;
        }
        let State { pending, front, .. } = &mut *state;
        front.resize(pending.len(), 0);
        front.copy_from_slice(pending);
        state.dirty = false;
        state.outstanding = true;
        Some((state.width, state.height))
    }

    /// The size read reserves the allocation before the separate pointer call.
    pub(crate) fn size(&self) -> usize {
        let mut state = self.lock();
        if state.closed || !state.outstanding {
            return 0;
        }
        state.borrowed = true;
        state.front.len()
    }

    pub(crate) fn pointer(&self) -> *const u8 {
        let state = self.lock();
        if state.borrowed {
            state.front.as_ptr()
        } else {
            std::ptr::null()
        }
    }

    /// Only the actual consumer acknowledgement releases an acquired pointer.
    /// Return true when a closed owner may leave the retained-owner registry.
    pub(crate) fn release(&self) -> bool {
        let mut state = self.lock();
        state.borrowed = false;
        state.outstanding = false;
        if state.closed {
            state.front.clear();
        }
        state.closed
    }

    /// Return true if no external pointer can still exist. Otherwise retain the
    /// owner until nextRgba; a consumer that never acknowledges is quarantined.
    pub(crate) fn close(&self) -> bool {
        let mut state = self.lock();
        state.closed = true;
        state.generation = state.generation.wrapping_add(1);
        state.pending = Vec::new();
        state.dirty = false;
        !state.borrowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquired_bytes_survive_resize_restart_and_close_until_acknowledged() {
        let store = FrameStore::default();
        let generation = store.restart();
        let pixels = [1, 2, 3, 255, 4, 5, 6, 255];
        let expected = if cfg!(any(target_os = "windows", target_os = "linux")) {
            [3, 2, 1, 255, 6, 5, 4, 255]
        } else {
            pixels
        };
        assert!(store.present(generation, 2, 1, 8, &pixels, Rect::new(0, 0, 2, 1)));
        assert_eq!(store.publish(), Some((2, 1)));
        let size = store.size();
        let pointer = store.pointer();
        assert!(store.present(generation, 3, 1, 12, &[77; 12], Rect::new(0, 0, 3, 1)));
        assert_eq!(store.publish(), None);
        let restarted = store.restart();
        assert!(!store.present(generation, 2, 1, 8, &pixels, Rect::new(0, 0, 2, 1)));
        assert!(store.present(restarted, 1, 1, 4, &[88; 4], Rect::new(0, 0, 1, 1)));
        // The consumer owns this loan until release, even after producer restart.
        assert_eq!(
            unsafe { std::slice::from_raw_parts(pointer, size) },
            expected
        );
        assert!(!store.close());
        assert_eq!(store.pointer(), pointer);
        // Close must retain the allocation while the asynchronous decode uses it.
        assert_eq!(
            unsafe { std::slice::from_raw_parts(pointer, size) },
            expected
        );
        assert!(store.release());
        assert!(store.pointer().is_null());
        assert!(!store.present(restarted, 1, 1, 4, &[99; 4], Rect::new(0, 0, 1, 1)));
    }

    #[test]
    fn padded_damage_preserves_other_pixels_and_rejects_out_of_bounds_updates() {
        let store = FrameStore::default();
        let generation = store.restart();
        let pixels = [1, 2, 3, 255, 4, 5, 6, 255, 7, 8, 9, 255, 10, 11, 12, 255];
        assert!(store.present(generation, 2, 2, 8, &pixels, Rect::new(0, 0, 2, 2)));
        assert_eq!(store.publish(), Some((2, 2)));
        assert_eq!(store.size(), 16);
        assert!(!store.release());
        let mut padded = [99; 24];
        padded[16..20].copy_from_slice(&[20, 21, 22, 255]);
        assert!(store.present(generation, 2, 2, 12, &padded, Rect::new(1, 1, 1, 1)));
        assert!(!store.present(
            generation,
            2,
            2,
            12,
            &padded,
            Rect::new(i32::MAX, 1, i32::MAX, 1)
        ));
        assert_eq!(store.publish(), Some((2, 2)));
        assert_eq!(store.size(), 16);
        let expected = if cfg!(any(target_os = "windows", target_os = "linux")) {
            [3, 2, 1, 255, 6, 5, 4, 255, 9, 8, 7, 255, 22, 21, 20, 255]
        } else {
            [1, 2, 3, 255, 4, 5, 6, 255, 7, 8, 9, 255, 20, 21, 22, 255]
        };
        // size reserves these bytes; no acknowledgement has released them yet.
        assert_eq!(
            unsafe { std::slice::from_raw_parts(store.pointer(), 16) },
            expected
        );
        assert!(!store.release());
        assert!(store.close());
    }
}
