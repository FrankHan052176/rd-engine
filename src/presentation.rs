//! Local Surface presentation controls. Decode and transport never wait here.
//!
//! `set_size` follows the pinned Flutter renderer's expected-image geometry
//! check, not a remote resolution request or a CPU scaling path. Only the HAR
//! lease installs this owner; other presentation backends keep their contracts.
use std::{collections::BTreeMap, sync::{Mutex, MutexGuard}};
use tokio::sync::Notify;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Output {
    pub generation: u64,
    pub display: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub generation: u64,
    pub paused: bool,
    /// Successful native submission after the last rearm; not physical scanout.
    pub ready: Option<Output>,
}

struct State {
    snapshot: Snapshot,
    display: i32,
    sizes: BTreeMap<i32, (i32, i32)>,
}

pub struct LocalPresentation {
    state: Mutex<State>,
    changed: Notify,
}

impl Default for LocalPresentation {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                snapshot: Snapshot { generation: 1, paused: false, ready: None },
                display: 0,
                sizes: BTreeMap::new(),
            }),
            changed: Notify::new(),
        }
    }
}

impl LocalPresentation {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn advance(state: &mut State) -> Result<u64, &'static str> {
        let next = state.snapshot.generation.checked_add(1)
            .ok_or("presentation generation exhausted")?;
        state.snapshot.generation = next;
        state.snapshot.ready = None;
        Ok(next)
    }

    pub fn snapshot(&self) -> Snapshot {
        self.lock().snapshot
    }

    /// Called by the ordered feeder only after the previous decoder was closed.
    /// A peer display switch, not a local size request, changes this identity.
    pub fn bind_display(&self, display: i32) -> Result<(), &'static str> {
        let mut state = self.lock();
        if state.display != display {
            Self::advance(&mut state)?;
            state.display = display;
        }
        Ok(())
    }

    pub fn set_size(&self, display: i32, width: i32, height: i32) -> Result<u64, &'static str> {
        if display < 0 || !(1..=crate::surface::MAX_DIMENSION).contains(&width)
            || !(1..=crate::surface::MAX_DIMENSION).contains(&height)
            || (width as u64) * (height as u64) * 4 > crate::surface::MAX_FRAMEBUFFER_BYTES as u64
        {
            return Err("invalid or over-budget local renderer geometry");
        }
        // The bridge validates display membership against the real peer first.
        let mut state = self.lock();
        let generation = Self::advance(&mut state)?;
        state.sizes.insert(display, (width, height));
        drop(state);
        self.changed.notify_one();
        Ok(generation)
    }

    pub fn set_paused(&self, paused: bool) -> Result<u64, &'static str> {
        let mut state = self.lock();
        if state.snapshot.paused == paused {
            return Ok(state.snapshot.generation);
        }
        let generation = Self::advance(&mut state)?;
        state.snapshot.paused = paused;
        drop(state);
        // A stored permit wakes the existing rectangle pump even when the
        // display is static. It does not spawn a worker or request a peer frame.
        self.changed.notify_one();
        Ok(generation)
    }

    pub fn rearm(&self) -> Result<u64, &'static str> {
        // No wake: waiting must not redisplay an old framebuffer as a new image.
        Self::advance(&mut self.lock())
    }

    pub async fn changed(&self) {
        self.changed.notified().await;
    }

    /// Taken immediately before a real output submission. No lock crosses SDK
    /// calls; an already admitted submission may complete after pause returns.
    pub fn begin_output(&self, width: i32, height: i32) -> Option<Output> {
        let state = self.lock();
        if state.snapshot.paused || width <= 0 || height <= 0
            || state.sizes.get(&state.display).is_some_and(|size| *size != (width, height))
        {
            return None;
        }
        Some(Output { generation: state.snapshot.generation, display: state.display, width, height })
    }

    /// A successful SDK handoff, not an old counter or an attempted render.
    /// An output admitted before rearm/pause cannot satisfy the new generation.
    pub fn submitted(&self, output: Output) {
        let mut state = self.lock();
        if output.generation == state.snapshot.generation && !state.snapshot.paused {
            state.snapshot.ready = Some(output);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_is_a_local_output_gate_and_waiting_requires_new_submission() {
        let owner = LocalPresentation::default();
        let old = owner.begin_output(640, 480).unwrap();
        owner.submitted(old);
        assert!(owner.snapshot().ready.is_some());
        owner.set_size(1, 800, 600).unwrap();
        // Requesting another display never changes the feeder's source.
        assert_eq!(owner.begin_output(640, 480).unwrap().display, 0);
        owner.bind_display(1).unwrap();
        assert!(owner.begin_output(640, 480).is_none());
        let output = owner.begin_output(800, 600).unwrap();
        owner.rearm().unwrap();
        owner.submitted(output);
        assert!(owner.snapshot().ready.is_none());
        let output = owner.begin_output(800, 600).unwrap();
        owner.submitted(output);
        assert_eq!(owner.snapshot().ready, Some(output));
        assert!(owner.set_size(1, 0, 600).is_err());
        assert!(owner.set_size(1, 16384, 16384).is_err());
        assert_eq!(owner.snapshot().ready, Some(output));
    }
}
