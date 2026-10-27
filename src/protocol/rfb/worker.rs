use super::{RfbError, native::{Connected, Frame, Native}, session::RfbOptions};
use mio::{Events, Interest, Poll, Token, Waker};
use std::{
    io::ErrorKind,
    net::{Shutdown, TcpStream},
    sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc},
    thread::{self, JoinHandle},
};
use tokio::sync::oneshot;

pub(super) enum Input {
    Pointer { x: u16, y: u16, buttons: u8 },
    Key { key: u32, down: bool },
    Clipboard(String),
}
enum Command {
    Receive(oneshot::Sender<Result<Frame, RfbError>>),
    Input(Input, oneshot::Sender<Result<(), RfbError>>),
    Stop,
}

pub(super) struct Worker {
    commands: mpsc::Sender<Command>,
    wake: Arc<Waker>,
    stopping: Arc<AtomicBool>,
    socket: TcpStream,
    thread: Option<JoinHandle<()>>,
    cancelled: bool,
}
impl Worker {
    pub fn start(stream: TcpStream, mut options: RfbOptions) -> Result<(Self, oneshot::Receiver<Result<Connected, RfbError>>), RfbError> {
        let socket = stream.try_clone()?;
        let mut monitor = mio::net::TcpStream::from_std(stream.try_clone()?);
        let poll = Poll::new()?;
        poll.registry().register(&mut monitor, Token(0), Interest::READABLE)?;
        let wake = Arc::new(Waker::new(poll.registry(), Token(1))?);
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stopping = stopping.clone();
        let (commands, receiver) = mpsc::channel();
        let (ready, connected) = oneshot::channel();
        let thread = thread::Builder::new().name("rd-vnc".into()).spawn(move || {
            let password = std::mem::take(&mut options.password);
            let native = Native::new(stream, password, options.shared);
            let mut native = match native {
                Ok(native) => native,
                Err(error) => { let _ = ready.send(Err(error)); return; }
            };
            match native.connect() {
                Ok(info) => { if ready.send(Ok(info)).is_err() { return; } }
                Err(error) => { let _ = ready.send(Err(error)); return; }
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run(&mut native, poll, monitor, receiver, &worker_stopping);
            }));
            if let Err(panic) = result {
                // A completed frame can still be in the session's receiver.
                // Do not free its pixels during an unexpected worker unwind.
                while !worker_stopping.load(Ordering::Acquire) { thread::park(); }
                std::panic::resume_unwind(panic);
            }
            // Native drops on this thread, after every C operation and callback.
        })?;
        Ok((Self { commands, wake, stopping, socket, thread: Some(thread), cancelled: false }, connected))
    }
    fn enqueue(&self, command: Command) -> Result<(), RfbError> {
        self.ensure_open()?;
        self.commands.send(command).map_err(|_| RfbError::Closed)?;
        self.wake.wake().map_err(|_| RfbError::Transport)
    }
    pub fn receive(&self) -> Result<oneshot::Receiver<Result<Frame, RfbError>>, RfbError> {
        let (sender, receiver) = oneshot::channel();
        self.enqueue(Command::Receive(sender))?;
        Ok(receiver)
    }
    pub async fn input(&mut self, input: Input) -> Result<(), RfbError> {
        let (sender, receiver) = oneshot::channel();
        // If this future is cancelled after enqueue, stop and join the native
        // worker before returning its borrow. No queued input can outlive the
        // caller's input-policy/revocation guard. A successful result is sent
        // only after the library has completed the actual socket write.
        let mut guard = CancelInput { worker: self, armed: true };
        guard.worker.enqueue(Command::Input(input, sender))?;
        let result = receiver.await.map_err(|_| RfbError::Closed)?;
        guard.armed = false;
        result
    }
    pub fn ensure_open(&self) -> Result<(), RfbError> {
        if self.cancelled { return Err(RfbError::Cancelled); }
        if self.thread.is_none() { return Err(RfbError::Closed); }
        Ok(())
    }
    pub fn stop(&mut self) -> Result<(), RfbError> {
        let Some(thread) = self.thread.take() else { return Ok(()); };
        self.stopping.store(true, Ordering::Release);
        let _ = self.commands.send(Command::Stop);
        // A duplicate socket refers to the same connection but has independent
        // descriptor lifetime: no cross-thread close/reused-descriptor race.
        let shutdown = self.socket.shutdown(Shutdown::Both);
        let _ = self.wake.wake();
        thread.thread().unpark();
        let joined = thread.join();
        if joined.is_err() { return Err(RfbError::Protocol("VNC worker panicked")); }
        match shutdown {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotConnected => Ok(()),
            Err(_) => Err(RfbError::Transport),
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) { let _ = self.stop(); }
}
struct CancelInput<'a> { worker: &'a mut Worker, armed: bool }
impl Drop for CancelInput<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.worker.cancelled = true;
            let _ = self.worker.stop();
        }
    }
}

fn apply_input(native: &mut Native, input: Input) -> Result<(), RfbError> {
    match input {
        Input::Pointer { x, y, buttons } => native.pointer(x, y, buttons),
        Input::Key { key, down } => native.key(key, down),
        Input::Clipboard(text) => native.clipboard(&text),
    }
}
fn run(native: &mut Native, mut poll: Poll, monitor: mio::net::TcpStream,
       commands: mpsc::Receiver<Command>, stopping: &AtomicBool) {
    let mut pending: Option<oneshot::Sender<Result<Frame, RfbError>>> = None;
    let mut failure: Option<RfbError> = None;
    let mut events = Events::with_capacity(2);
    loop {
        if stopping.load(Ordering::Acquire) { return; }
        loop {
            match commands.try_recv() {
                Ok(Command::Stop) => return,
                Ok(Command::Receive(reply)) => {
                    if let Some(error) = &failure { let _ = reply.send(Err(error.clone())); }
                    else if pending.is_some() { let _ = reply.send(Err(RfbError::Protocol("concurrent VNC receives"))); }
                    else { pending = Some(reply); }
                }
                Ok(Command::Input(input, reply)) => {
                    if stopping.load(Ordering::Acquire) { return; }
                    let result = match &failure {
                        Some(error) => Err(error.clone()),
                        None => apply_input(native, input),
                    };
                    if let Err(error) = &result {
                        if !matches!(error, RfbError::Geometry) { failure = Some(error.clone()); }
                    }
                    let _ = reply.send(result);
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }
        if stopping.load(Ordering::Acquire) { return; }
        if let Some(error) = &failure {
            if let Some(reply) = pending.take() { let _ = reply.send(Err(error.clone())); }
            // A cancelled pump may still own a completed frame view. Keep its
            // native allocation alive even after transport/input failure.
            while let Ok(command) = commands.recv() {
                match command {
                    Command::Receive(reply) => { let _ = reply.send(Err(error.clone())); }
                    Command::Input(_, reply) => { let _ = reply.send(Err(error.clone())); }
                    Command::Stop => return,
                }
            }
            return;
        }
        if pending.is_some() {
            let readable = if native.buffered() { true } else {
                match monitor.peek(&mut [0u8; 1]) {
                    Ok(_) => true, // EOF is handled by upstream, preserving Closed.
                    Err(error) if error.kind() == ErrorKind::WouldBlock => false,
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => { failure = Some(RfbError::Transport); false }
                }
            };
            if failure.is_some() || readable {
                let result = match &failure {
                    Some(error) => Err(error.clone()),
                    None => native.receive(),
                };
                if let Err(error) = &result { failure = Some(error.clone()); }
                if let Some(reply) = pending.take() { let _ = reply.send(result); }
                // Do not receive again until pump has synchronously consumed the
                // borrowed framebuffer view and submitted a new Receive command.
                continue;
            }
        }
        // No timer, spin, per-frame task, or frame queue. Wake for input/pump/stop
        // independently of socket readability; upstream handles buffered bytes.
        if let Err(error) = poll.poll(&mut events, None) {
            if error.kind() != ErrorKind::Interrupted { failure = Some(RfbError::Transport); }
        }
    }
}
