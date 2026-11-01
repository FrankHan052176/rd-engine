    use super::{
        CLIPBOARD_QUEUE, COMMANDS, ClipboardMessage, DIRECT_ACCESS_PORT, Facts, GateView, Inner,
        InputGate, MAX_HELD_INPUTS, PasswordGate, Protocol, QueuedInput, RustDeskHeld,
        SecondFactorGate, State, Viewer, ViewerError, ViewerInput, ViewerInputPolicy, ViewerSnapshot,
        WireReader, WireWriter, direct_address, lock, take_clipboard, take_input,
    };
    use crate::transport;
    use base::message_proto::{ControlKey, KeyEvent, Message, message};
    use hbb_common::tcp::FramedStream;
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::{Arc, Mutex, atomic::AtomicBool},
        time::Duration,
    };
    use tokio::sync::{Notify, mpsc};
    use tokio_util::sync::CancellationToken;

    /// How long a step that expects one message on the test wire waits for it.
    const RECEIVE_LIMIT: Duration = Duration::from_secs(5);

    /// A viewer that is authorized on a wire. The peer's grant is the gate's
    /// own fact and is published there, not here.
    fn facts(protocol: Protocol, proven: bool) -> Facts {
        Facts {
            protocol,
            authenticated: true,
            proven,
            closed: false,
        }
    }

    /// What a gate publishes, for a decision a test makes without a viewer.
    fn view(policy: ViewerInputPolicy, keyboard: bool) -> GateView {
        GateView {
            policy,
            keyboard,
            generation: 1,
            owed: 0,
            retired: 0,
            unreleased: 0,
        }
    }

    /// What the viewer still owes, read the way a caller reads it: a policy
    /// change that changes nothing.
    fn owed(gate: &InputGate, facts: &Facts) -> u64 {
        gate.set(gate.policy(), facts).releases_owed
    }

    /// A gate the peer has granted the keyboard on, which is where every viewer
    /// that can send input starts.
    fn granted(policy: ViewerInputPolicy) -> InputGate {
        let gate = InputGate::new(policy);
        gate.grant(true);
        gate
    }

    /// A viewer's input state with no session behind it: only the facts an
    /// admission decision reads are set, so one writer step can be driven at a
    /// time.
    fn writer_state() -> Arc<State> {
        Arc::new(State {
            inner: Mutex::new(Inner {
                conn_token: None,
                snapshot: ViewerSnapshot::default(),
                geometry: None,
                decoder: None,
                observed_peer_close_reason: None,
            }),
            cancel: CancellationToken::new(),
            done: Notify::new(),
            result: Mutex::new(None),
            protocol: Protocol::RustDesk,
            mode: crate::session::SessionMode::Desktop,
            transfer: Mutex::new(None),
            authenticated: AtomicBool::new(true),
            rdp_input_flags: super::AtomicU16::new(0),
            peer_proven: AtomicBool::new(true),
            input: InputGate::new(ViewerInputPolicy::interactive()),
            // The clipboard mailbox and its fence, with the peer's grant and the
            // local option left to each test: nothing is admitted until a test
            // opens the AND the way a session does.
            clipboard: crate::clipboard::ClipboardState::new(),
            peer_clipboard: AtomicBool::new(false),
            peer_file: AtomicBool::new(false),
            cliprdr: Mutex::new(None),
            clipboard_out: Mutex::new(None),
            clipboard_in: super::ClipboardDecoder::default(),
            resources_unconfirmed: AtomicBool::new(false),
            control: Mutex::new(None),
            second_factor: Mutex::new(SecondFactorGate::default()),
            password: Mutex::new(PasswordGate::default()),
            session_options: Mutex::new(crate::session_options::SessionOptions::default()),
            advertised_decoding: Mutex::new(None),
        })
    }

    /// One parsed record from the peer's end of a test wire.
    async fn receive(wire: &mut FramedStream) -> Message {
        use hbb_common::protobuf::Message as _;
        let bytes = wire.next().await.unwrap().unwrap();
        Message::parse_from_bytes(&bytes).unwrap()
    }

    /// One peer `LoginResponse.error` on a test wire.
    async fn refuse(wire: &mut FramedStream, text: &str) {
        let mut response = base::message_proto::LoginResponse::new();
        response.set_error(text.into());
        let mut message = Message::new();
        message.set_login_response(response);
        wire.send(&message).await.unwrap();
    }

    /// One queued event, stamped the way the enqueue boundary stamps it: with
    /// the generation the gate is at now.
    fn queued(state: &State, event: ViewerInput) -> QueuedInput {
        QueuedInput {
            event,
            generation: state.input.read().generation,
        }
    }

    /// The enqueue boundary of one viewer, with no session behind it: the real
    /// `Viewer` methods over the state a writer step is driven with, so a test
    /// asserts both what a caller is answered and what was actually queued.
    fn writer_viewer() -> (Arc<Viewer>, mpsc::Receiver<QueuedInput>) {
        let state = writer_state();
        state.input.grant(true);
        let (mouse, queue) = mpsc::channel(COMMANDS);
        (Arc::new(Viewer { state, mouse }), queue)
    }

    /// One written wire and its peer, with every half of the client's own
    /// transport kept alive.
    ///
    /// That is not tidiness: a reader and a writer split from one stream share
    /// one cancellation token, so dropping the half a test does not read would
    /// cancel the half it drives, and the first write would fail as a closed
    /// transport.
    struct Wire {
        writer: WireWriter,
        peer: WireReader,
        _client_reader: WireReader,
        _peer_writer: WireWriter,
    }

    /// One writer and the peer's end of one in-memory wire.
    ///
    /// The peer reads through the transport's own receiver, so a test asserts
    /// what the peer received rather than what a call returned.
    fn writer_wire() -> Wire {
        let address: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (local, peer) = tokio::io::duplex(4096);
        let (client_reader, writer) = transport::split(FramedStream::from(local, address));
        let (peer_reader, peer_writer) = transport::split(FramedStream::from(peer, address));
        Wire {
            writer,
            peer: peer_reader,
            _client_reader: client_reader,
            _peer_writer: peer_writer,
        }
    }

    /// The next message the peer received on that wire.
    ///
    /// The wait is bounded, so a writer that emitted nothing where this step
    /// expects an event fails the test instead of hanging it.
    async fn received(peer: &mut WireReader) -> Message {
        tokio::time::timeout(RECEIVE_LIMIT, peer.recv())
            .await
            .expect("the writer emitted the message this step expects")
            .expect("the peer's end stays open")
            .expect("the writer emitted a well-formed message")
    }

    /// The key state one message the peer received carries.
    fn key_state(message: Message) -> bool {
        match message.union {
            Some(message::Union::KeyEvent(event)) => event.down,
            other => panic!("expected a key event, got {other:?}"),
        }
    }

    /// The pointer state one message the peer received carries: the buttons it
    /// holds and where it put the pointer.
    fn pointer(message: Message) -> (u32, i32, i32) {
        match message.union {
            Some(message::Union::MouseEvent(event)) => (event.mask as u32, event.x, event.y),
            other => panic!("expected a mouse event, got {other:?}"),
        }
    }

    #[test]
    fn rdp_legacy_shortcuts_emit_scancodes_and_do_not_release_an_existing_modifier() {
        use super::{RdpHeld, FastPathInputEvent as E, KeyboardFlags as F, rdp_legacy};
        let mut control = control_key_event(true);
        let held = rdp_legacy(&control, &RdpHeld::default()).unwrap().held;
        let mut shortcut = KeyEvent::new();
        shortcut.set_chr(u32::from(b'a'));
        shortcut.press = true;
        shortcut.modifiers.push(ControlKey::Control.into());
        let batch = rdp_legacy(&shortcut, &held).unwrap();
        assert_eq!(&batch.events[..batch.len], &[
            E::KeyboardEvent(F::empty(), 0x1e),
            E::KeyboardEvent(F::RELEASE, 0x1e),
        ]);
        // The modifier belongs to the earlier down, not to the shortcut tap.
        control.down = false;
        let release = rdp_legacy(&control, &batch.held).unwrap();
        assert_eq!(&release.events[..release.len], &[E::KeyboardEvent(F::RELEASE, 0x1d)]);
        let complete = rdp_legacy(&shortcut, &RdpHeld::default()).unwrap();
        assert_eq!(&complete.events[..complete.len], &[
            E::KeyboardEvent(F::empty(), 0x1d), E::KeyboardEvent(F::empty(), 0x1e),
            E::KeyboardEvent(F::RELEASE, 0x1e), E::KeyboardEvent(F::RELEASE, 0x1d),
        ]);
    }

    #[test]
    fn rdp_uppercase_shortcuts_and_changed_modifier_ups_preserve_the_downs_key() {
        use super::{RdpHeld, FastPathInputEvent as E, KeyboardFlags as F, rdp_legacy};
        let mut key = KeyEvent::new();
        key.set_chr(u32::from(b'A'));
        key.down = true;
        key.modifiers.push(ControlKey::Control.into());
        let down = rdp_legacy(&key, &RdpHeld::default()).unwrap();
        assert_eq!(&down.events[..down.len], &[
            E::KeyboardEvent(F::empty(), 0x1d), E::KeyboardEvent(F::empty(), 0x2a),
            E::KeyboardEvent(F::empty(), 0x1e), E::KeyboardEvent(F::RELEASE, 0x2a),
            E::KeyboardEvent(F::RELEASE, 0x1d),
        ]);
        key.down = false;
        key.modifiers.clear();
        let up = rdp_legacy(&key, &down.held).unwrap();
        assert_eq!(&up.events[..up.len], &[E::KeyboardEvent(F::RELEASE, 0x1e)]);
    }

    #[test]
    fn rdp_text_is_unicode_and_batches_stop_at_the_upstream_event_limit() {
        use super::{RdpHeld, FastPathInputEvent as E, KeyboardFlags as F, rdp_legacy};
        let mut key = KeyEvent::new();
        key.set_seq("中".into());
        let batch = rdp_legacy(&key, &RdpHeld::default()).unwrap();
        assert_eq!(&batch.events[..batch.len], &[
            E::UnicodeKeyboardEvent(F::empty(), 0x4e2d),
            E::UnicodeKeyboardEvent(F::RELEASE, 0x4e2d),
        ]);
        key.set_seq("a".repeat(127));
        let batch = rdp_legacy(&key, &RdpHeld::default()).unwrap();
        assert_eq!(batch.len, 254);
        key.set_seq("a".repeat(128));
        assert!(matches!(rdp_legacy(&key, &RdpHeld::default()), Err(ViewerError::InputNotAllowed)));
    }

    #[test]
    fn rdp_relative_pointer_survives_the_upstream_fastpath_encoder() {
        use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent};
        let mut batch = super::rdp_mouse(5, 0, -17, 23, (10, 20)).unwrap();
        let key = FastPathInputEvent::KeyboardEvent(super::KeyboardFlags::empty(), 0x1e);
        batch.push(key).unwrap();
        let input = FastPathInput::new(batch.events[..batch.len].to_vec()).unwrap();
        let bytes = ironrdp_core::encode_vec(&input).unwrap();
        let decoded: FastPathInput = ironrdp_core::decode(&bytes).unwrap();
        assert_eq!(decoded.input_events(), &[
            FastPathInputEvent::MouseEventRel(super::MouseRelPdu {
                flags: super::PointerRelFlags::MOVE, x_delta: -17, y_delta: 23,
            }),
            key,
        ]);
    }

    #[test]
    fn rdp_revocation_after_relative_motion_releases_without_warping_the_pointer() {
        let down = super::rdp_batch(&super::RdpHeld::default(), &QueuedInput {
            event: ViewerInput::Mouse { kind: 1, button: 1, x: 10, y: 20 }, generation: 3,
        }).unwrap();
        let moved = super::rdp_batch(&down.held, &QueuedInput {
            event: ViewerInput::Mouse { kind: 5, button: 0, x: -7, y: 9 }, generation: 3,
        }).unwrap();
        assert_eq!(moved.held.release_event(0), super::FastPathInputEvent::MouseEventRel(super::MouseRelPdu {
            flags: super::PointerRelFlags::BUTTON1, x_delta: 0, y_delta: 0,
        }));
    }

    #[test]
    fn rdp_wheel_units_preserve_both_axes_without_overflow_or_truncation() {
        use super::{FastPathInputEvent, PointerFlags};
        let batch = super::rdp_mouse(3, 0, 3, -3, (10, 20)).unwrap();
        let mut horizontal = 0;
        let mut vertical = 0;
        for event in &batch.events[..batch.len] {
            let FastPathInputEvent::MouseEvent(event) = event else { panic!("wheel event"); };
            assert!((-256..=255).contains(&event.number_of_wheel_rotation_units));
            if event.flags.contains(PointerFlags::HORIZONTAL_WHEEL) {
                horizontal += i32::from(event.number_of_wheel_rotation_units);
            } else {
                assert!(event.flags.contains(PointerFlags::VERTICAL_WHEEL));
                vertical += i32::from(event.number_of_wheel_rotation_units);
            }
        }
        assert_eq!((horizontal, vertical), (360, 360));
        assert!(matches!(super::rdp_mouse(3, 0, i32::MAX, 0, (0, 0)), Err(ViewerError::InvalidMouse)));
    }

    /// A peer that carries scan codes but not Unicode still releases the key
    /// its own shortcut went down as: the up is derived as Unicode, the ledger
    /// holds the scan code, and the enqueue check admits a representation the
    /// peer has rather than the one this event alone names.
    #[test]
    fn rdp_scan_code_shortcut_releases_when_only_scan_codes_are_carried() {
        use super::{
            FastPathInputEvent as E, KeyboardFlags as F, RdpHeld, RdpInputFlags, rdp_legacy,
            rdp_legacy_admission,
        };
        let mut state = writer_state();
        Arc::get_mut(&mut state).unwrap().protocol = Protocol::Rdp;
        let scan_codes = RdpInputFlags::FASTPATH_INPUT | RdpInputFlags::SCANCODES;
        state.rdp_input_flags.store(scan_codes.bits(), super::Ordering::Release);

        let mut down = KeyEvent::new();
        down.set_chr(u32::from(b'a'));
        down.down = true;
        down.modifiers.push(ControlKey::Control.into());
        assert!(rdp_legacy_admission(&state, &down).is_ok());
        let held = rdp_legacy(&down, &RdpHeld::default()).unwrap().held;

        let mut up = KeyEvent::new();
        up.set_chr(u32::from(b'a'));
        assert!(
            rdp_legacy_admission(&state, &up).is_ok(),
            "the up of a scan-code hold is admitted even though it derives as Unicode"
        );
        let released = rdp_legacy(&up, &held).unwrap();
        assert_eq!(
            &released.events[..released.len],
            &[E::KeyboardEvent(F::RELEASE, 0x1e)],
            "the wire carries the release of the scan code the peer actually holds"
        );
        assert_eq!(released.held.len, 0, "the released hold leaves the ledger");

        // New input the peer cannot carry is still refused before it is queued,
        // and a peer with neither representation refuses even a release.
        let mut text = KeyEvent::new();
        text.set_seq("text".into());
        assert!(matches!(
            rdp_legacy_admission(&state, &text),
            Err(ViewerError::InputNotAllowed)
        ));
        state.rdp_input_flags.store(RdpInputFlags::FASTPATH_INPUT.bits(), super::Ordering::Release);
        assert!(matches!(
            rdp_legacy_admission(&state, &up),
            Err(ViewerError::InputNotAllowed)
        ));
        assert!(matches!(
            rdp_legacy_admission(&state, &control_key_event(false)),
            Err(ViewerError::InputNotAllowed)
        ));
    }

    #[test]
    fn rdp_refuses_unsupported_input_and_stale_generations_at_enqueue() {
        let mut state = writer_state();
        Arc::get_mut(&mut state).unwrap().protocol = Protocol::Rdp;
        state.input.grant(true);
        let (mouse, _queue) = mpsc::channel(COMMANDS);
        let viewer = Viewer { state, mouse };
        let generation = viewer.input_generation();
        // Authentication alone cannot prove the server's optional input modes.
        assert!(matches!(viewer.send_key(0xffe3, true, generation), Err(ViewerError::InputNotAllowed)));
        let flags = super::RdpInputFlags::FASTPATH_INPUT | super::RdpInputFlags::SCANCODES;
        viewer.state.rdp_input_flags.store(flags.bits(), super::Ordering::Release);
        assert!(matches!(viewer.send_mouse(5, 0, 1, -1, generation), Err(ViewerError::InputNotAllowed)));
        let mut unicode = KeyEvent::new();
        unicode.set_seq("text".into());
        assert!(matches!(viewer.send_rustdesk_key(unicode, generation), Err(ViewerError::InputNotAllowed)));
        viewer.state.rdp_input_flags.store((flags | super::RdpInputFlags::MOUSE_RELATIVE).bits(), super::Ordering::Release);
        assert_eq!(viewer.send_mouse(5, 0, 1, -1, generation).unwrap(), generation);
        // A new input the peer cannot carry is refused: with scan codes only,
        // this character has no physical key to press.
        let mut key = KeyEvent::new();
        key.set_chr('中' as u32);
        key.down = true;
        key.modifiers.push(ControlKey::Control.into());
        assert!(matches!(viewer.send_rustdesk_key(key, generation), Err(ViewerError::InputNotAllowed)));
        assert!(matches!(viewer.send_key(0x1008ff12, true, generation), Err(ViewerError::InputNotAllowed)));
        viewer.set_input_policy(ViewerInputPolicy::read_only());
        let current = viewer.set_input_policy(ViewerInputPolicy::interactive()).input_generation;
        assert!(matches!(viewer.send_key(0xffe3, false, generation), Err(ViewerError::StaleInputGeneration)));
        assert!(matches!(viewer.send_rustdesk_key(control_key_event(false), generation), Err(ViewerError::StaleInputGeneration)));
        assert_eq!(viewer.send_key(0xffe3, true, current).unwrap(), current);
    }

    #[test]
    fn rdp_cannot_adopt_a_retired_hold_when_regrant_races_the_release_pass() {
        let gate = granted(ViewerInputPolicy::interactive());
        let facts = facts(Protocol::Rdp, false);
        let old = gate.read().generation;
        assert!(gate.own_many(old, 1, &facts));
        // The writer could have read its release-pass gate just before this.
        gate.set(ViewerInputPolicy::read_only(), &facts);
        let new = gate.set(ViewerInputPolicy::interactive(), &facts).input_generation;
        assert!(!gate.own_many(new, 0, &facts), "same-key repeat cannot adopt an old hold");
        gate.released(old);
        assert!(gate.own_many(new, 1, &facts));
        assert!(!gate.own_many(old, 0, &facts));
    }

    #[test]
    fn direct_address_uses_the_standard_port_for_bare_ips() {
        assert_eq!(
            direct_address("192.168.108.155"),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 108, 155)),
                DIRECT_ACCESS_PORT,
            )),
        );
        assert_eq!(
            direct_address("::1"),
            Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                DIRECT_ACCESS_PORT
            )),
        );
    }

    #[test]
    fn direct_address_preserves_explicit_ports_and_rejects_non_addresses() {
        assert_eq!(
            direct_address("192.168.108.155:24444"),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 108, 155)),
                24444,
            )),
        );
        assert_eq!(direct_address("192.168.108.155:0"), None);
        assert_eq!(direct_address("peer-id"), None);
    }

    /// One key event on the original wire, down or up, for the same key.
    fn control_key(down: bool) -> ViewerInput {
        ViewerInput::RustDeskKey {
            event: control_key_event(down),
        }
    }

    /// The same key event as the wire message it is.
    fn control_key_event(down: bool) -> KeyEvent {
        let mut event = KeyEvent::new();
        event.set_control_key(ControlKey::Control);
        event.down = down;
        event
    }

    #[test]
    fn an_unproven_rustdesk_peer_admits_nothing_until_this_viewer_accepts_it() {
        let gate = granted(ViewerInputPolicy::interactive());
        let facts = facts(Protocol::RustDesk, false);
        let start = gate.read();
        assert!(
            !facts.admits(start),
            "a wire the handshake did not encrypt and verify admits nothing on its own"
        );
        assert!(
            !gate.own(start.generation, true, &facts),
            "the writer drops what the gate refuses"
        );

        // The operator's answer is this session's own state. It opens input for
        // this viewer, and it says nothing about a later one.
        let accepted = gate.set(
            ViewerInputPolicy {
                view_only: false,
                unverified_accepted: true,
            },
            &facts,
        );
        assert!(accepted.policy.unverified_accepted);
        assert!(
            !accepted.revoked,
            "an acceptance that opens input revokes nothing"
        );
        assert!(
            !gate.own(start.generation, true, &facts),
            "the event queued under the previous policy is still dropped"
        );
        let current = gate.read();
        assert!(
            current.generation > start.generation,
            "a policy change advances the generation"
        );
        assert_eq!(
            accepted.input_generation, current.generation,
            "the answer names the generation the change published"
        );
        assert!(
            gate.own(current.generation, true, &facts),
            "an event admitted under this session's acceptance is emitted"
        );
    }

    #[test]
    fn view_only_admits_no_input_on_either_wire() {
        let read_only = ViewerInputPolicy::read_only();
        assert!(
            !facts(Protocol::Vnc, false).admits(view(read_only, true)),
            "RFB input is refused too"
        );
        assert!(
            !facts(Protocol::RustDesk, true).admits(view(read_only, true)),
            "a peer the handshake proved does not outrank the read-only switch"
        );
        let gate = granted(read_only);
        let current = gate.read();
        assert_eq!(current.policy, read_only);
        assert!(
            !gate.own(current.generation, true, &facts(Protocol::Vnc, false)),
            "a viewer started read-only emits nothing"
        );
    }

    #[test]
    fn rfb_input_is_admitted_without_peer_evidence() {
        // RFB carries no identity evidence, and this viewer does not invent a
        // question for it: an authenticated session with the peer's grant admits
        // input exactly as it did before the policy existed.
        assert!(
            facts(Protocol::Vnc, false).admits(view(ViewerInputPolicy::interactive(), true)),
            "VNC input is not gated on evidence its wire cannot carry"
        );
    }

    #[test]
    fn a_hold_the_writer_could_not_remember_is_refused_rather_than_emitted() {
        let gate = granted(ViewerInputPolicy::interactive());
        let facts = facts(Protocol::Vnc, false);
        let generation = gate.read().generation;
        for _ in 0..MAX_HELD_INPUTS {
            assert!(gate.own(generation, true, &facts));
        }
        assert!(
            !gate.own(generation, true, &facts),
            "the ledger's bound refuses one hold too many"
        );
        gate.released(generation);
        assert!(
            gate.own(generation, true, &facts),
            "a released hold is available again"
        );
    }

    #[test]
    fn only_what_the_writer_emitted_becomes_a_hold_it_can_release() {
        let gate = granted(ViewerInputPolicy::interactive());
        let facts = facts(Protocol::Vnc, false);
        let generation = gate.read().generation;
        let mut held = RustDeskHeld::default();

        // Admitted and queued is not yet held: the writer takes the hold before
        // the wire, and records it as one it owns.
        assert!(held.adds(&control_key(true)));
        assert!(gate.own(generation, held.adds(&control_key(true)), &facts));
        assert_eq!(owed(&gate, &facts), 1, "the gate owns the hold it admitted");
        assert_eq!(held.record(&control_key(true), generation), None);

        // The peer's key is one key, so a repeat of the same down is one hold.
        assert!(!held.adds(&control_key(true)));
        assert_eq!(held.record(&control_key(true), generation), None);
        assert_eq!(owed(&gate, &facts), 1);

        // Its release is what drops the hold, and it drops it once — reporting
        // the stamp the hold carried, so the gate can tell a hold the operator
        // let go from one a change retired.
        assert_eq!(
            held.record(&control_key(false), generation),
            Some(generation)
        );
        gate.released(generation);
        assert_eq!(owed(&gate, &facts), 0);
        assert_eq!(
            held.record(&control_key(false), generation),
            None,
            "a release for a key this writer never held releases nothing"
        );

        // A button is the same: the down holds it, the up that follows releases
        // it, and an up with no hold releases nothing.
        let down = ViewerInput::Mouse {
            kind: 1,
            button: 0x01,
            x: 4,
            y: 3,
        };
        let up = ViewerInput::Mouse {
            kind: 2,
            button: 0x01,
            x: 4,
            y: 3,
        };
        assert!(held.adds(&down));
        assert!(gate.own(generation, held.adds(&down), &facts));
        assert_eq!(held.record(&down, generation), None);
        assert_eq!(owed(&gate, &facts), 1);
        assert!(!held.adds(&down), "a button already held takes nothing");
        assert_eq!(held.record(&up, generation), Some(generation));
        gate.released(generation);
        assert_eq!(owed(&gate, &facts), 0);
        assert_eq!(held.record(&up, generation), None);
    }

    #[test]
    fn a_writer_that_stopped_reports_its_holds_as_unreleased_not_as_released() {
        let gate = granted(ViewerInputPolicy::interactive());
        let facts = facts(Protocol::Vnc, false);
        let generation = gate.read().generation;
        assert!(gate.own(generation, true, &facts));

        let revoked = gate.set(ViewerInputPolicy::read_only(), &facts);
        assert!(revoked.revoked, "read-only revokes the admission it had");
        assert_eq!(revoked.releases_owed, 1, "the release is still owed");
        assert_eq!(
            revoked.releases_retired, 1,
            "the change retired the hold, so its release is now pending"
        );
        assert!(
            !revoked.released(),
            "an owed release is not a completed one"
        );

        // The writer stopped before it made that release.
        gate.stopped();
        let after = gate.set(gate.policy(), &facts);
        assert_eq!(after.releases_owed, 0);
        assert_eq!(
            after.releases_retired, 0,
            "a writer that stopped has no release on its way"
        );
        assert_eq!(
            after.releases_unreleased, 1,
            "a release whose writer stopped is reported as unconfirmed, never as a completed one"
        );
        assert!(!after.released());
    }

    #[test]
    fn only_a_hold_a_change_retired_is_reported_as_a_release_on_its_way() {
        let gate = granted(ViewerInputPolicy::interactive());
        let facts = facts(Protocol::Vnc, false);
        let generation = gate.read().generation;
        assert!(gate.own(generation, true, &facts));

        // A key the operator is holding is not a release the engine owes: the
        // policy in force still admits it.
        let holding = gate.set(gate.policy(), &facts);
        assert_eq!(holding.releases_owed, 1, "the writer owns the hold");
        assert_eq!(
            holding.releases_retired, 0,
            "nothing was retired, so no release is pending"
        );

        // The change that stops admitting it is what makes the release pending.
        let revoked = gate.set(ViewerInputPolicy::read_only(), &facts);
        assert_eq!(revoked.releases_owed, 1);
        assert_eq!(revoked.releases_retired, 1);

        // Releasing the hold the change retired settles the pending release,
        // and the hold's own stamp is what says so.
        gate.released(generation);
        let settled = gate.set(gate.policy(), &facts);
        assert_eq!(settled.releases_owed, 0);
        assert_eq!(settled.releases_retired, 0);
    }

    #[test]
    fn a_peer_grant_change_moves_the_generation_in_both_directions() {
        let gate = InputGate::new(ViewerInputPolicy::interactive());
        let facts = facts(Protocol::RustDesk, true);
        let withheld = gate.read();
        assert!(
            !facts.admits(withheld),
            "nothing is admitted before the peer grants the keyboard"
        );

        gate.grant(true);
        let given = gate.read();
        assert!(facts.admits(given), "the peer's grant admits input");
        assert!(
            !gate.own(withheld.generation, true, &facts),
            "input queued before the grant is not admitted by it"
        );
        gate.grant(true);
        assert_eq!(
            gate.read().generation,
            given.generation,
            "a grant already in force changes nothing"
        );

        // Withdrawn and granted again: input is admitted, and the generation
        // says so, because what was queued or emitted under the old grant is
        // still invalid.
        gate.grant(false);
        let withdrawn = gate.read();
        assert!(!facts.admits(withdrawn));
        gate.grant(true);
        let regranted = gate.read();
        assert!(facts.admits(regranted), "input is admitted again");
        assert!(
            regranted.generation > withdrawn.generation,
            "the grant that follows a withdrawal is a change of its own"
        );
        assert!(
            !gate.own(withdrawn.generation, true, &facts),
            "an event queued across the withdrawal is not replayed by the grant that followed it"
        );
    }

    /// A peer that withdraws and re-grants the keyboard while this writer is
    /// between events must not leave the key it emitted standing.
    ///
    /// The writer's own path is driven directly here, with a real wire on the
    /// other end and no select loop to schedule: the order asserted is the
    /// writer's own, and not a product of when a wake-up happened to be polled.
    #[tokio::test]
    async fn a_peer_grant_change_releases_old_holds_before_fresh_same_key_input() {
        let state = writer_state();
        state.input.grant(true);
        let mut wire = writer_wire();
        let mut held = RustDeskHeld::default();

        // The peer granted the keyboard, and this writer emitted a key down it
        // now holds.
        take_input(
            &state,
            &mut wire.writer,
            &mut held,
            queued(&state, control_key(true)),
        )
        .await
        .expect("the writer takes the event the grant admits");
        assert!(
            key_state(received(&mut wire.peer).await),
            "the down reached the peer"
        );

        // The peer withdraws the grant and grants it again, and a fresh down for
        // the same key is queued under the grant in force now.
        state.input.grant(false);
        state.input.grant(true);
        take_input(
            &state,
            &mut wire.writer,
            &mut held,
            queued(&state, control_key(true)),
        )
        .await
        .expect("the writer takes the event the new grant admits");

        // In order: the hold the withdrawal ended is released, and only then is
        // the fresh down emitted. An old hold adopted by the event that follows
        // it would leave the peer's key down with no release behind it.
        assert!(
            !key_state(received(&mut wire.peer).await),
            "the hold from before the change is released first"
        );
        assert!(
            key_state(received(&mut wire.peer).await),
            "and the fresh down follows the release"
        );
    }

    /// Input queued under a grant the peer withdrew is never replayed by the
    /// grant that follows it.
    #[tokio::test]
    async fn input_queued_across_a_peer_grant_change_is_not_replayed() {
        let state = writer_state();
        state.input.grant(true);
        let mut wire = writer_wire();
        let mut held = RustDeskHeld::default();

        // Queued while the peer granted the keyboard, and reached by the writer
        // only after the grant was withdrawn and given again.
        let stale = queued(
            &state,
            ViewerInput::Mouse {
                kind: 0,
                button: 0,
                x: 3,
                y: 4,
            },
        );
        state.input.grant(false);
        state.input.grant(true);
        take_input(&state, &mut wire.writer, &mut held, stale)
            .await
            .expect("a dropped event is not a writer failure");

        let fresh = queued(
            &state,
            ViewerInput::Mouse {
                kind: 0,
                button: 0,
                x: 5,
                y: 6,
            },
        );
        take_input(&state, &mut wire.writer, &mut held, fresh)
            .await
            .expect("the writer takes the event the new grant admits");

        // The first thing the peer receives is the event queued under the grant
        // in force, so the one queued across the change never reached it.
        let (_, x, y) = pointer(received(&mut wire.peer).await);
        assert_eq!(
            (x, y),
            (5, 6),
            "the event queued under the withdrawn grant was not replayed"
        );
    }

    /// The clipboard is the session's own: a payload queued under a generation
    /// this viewer has left is not written, and the peer's own update lands in
    /// the mailbox stamped with the generation it arrived under.
    ///
    /// Both directions are driven over one real state, and the send half asserts
    /// what the peer received rather than what a call answered.
    #[tokio::test]
    async fn clipboard_delivery_follows_the_generation_it_was_accepted_under() {
        let state = writer_state();
        state.input.grant(true);
        // The local `disable-clipboard` option a login states, and the peer's own
        // grant: the fence this viewer uses is the AND of the two.
        *lock(&state.session_options) = crate::session_options::SessionOptions::default()
            .request(crate::session_options::SessionOptionChange::ClipboardEnabled(true))
            .expect("clipboard can be asked for");
        state.peer_clipboard.store(true, super::Ordering::Release);
        state.refresh_clipboard();
        let (clipboard_tx, mut clipboard_rx) = mpsc::channel(CLIPBOARD_QUEUE);
        *lock(&state.clipboard_out) = Some(clipboard_tx);
        let viewer = Arc::new(Viewer {
            state: state.clone(),
            mouse: mpsc::channel(COMMANDS).0,
        });
        let mut wire = writer_wire();

        // Queued while every fact holds, and the peer withdraws before the writer
        // reaches it.
        let withdrawn = viewer
            .clipboard_send(crate::clipboard::ClipboardPayload::text("withdrawn"))
            .expect("the live fence admits this payload");
        state.peer_clipboard.store(false, super::Ordering::Release);
        assert!(
            state.refresh_clipboard() > withdrawn,
            "a withdrawal moves the fence"
        );
        let queued = clipboard_rx.recv().await.expect("the payload was queued");
        take_clipboard(&state, &mut wire.writer, queued)
            .await
            .expect("a dropped payload is not a writer failure");
        assert!(
            tokio::time::timeout(Duration::from_millis(200), wire.peer.recv())
                .await
                .is_err(),
            "the payload queued under the withdrawn grant was not written"
        );

        // The peer grants it again: a payload queued now belongs to the new
        // generation, and that one is written.
        state.peer_clipboard.store(true, super::Ordering::Release);
        assert!(
            state.refresh_clipboard() > withdrawn,
            "a fresh grant moves the fence too"
        );
        let live = viewer
            .clipboard_send(crate::clipboard::ClipboardPayload::text("kept"))
            .expect("the live fence admits this payload");
        assert!(
            live > withdrawn,
            "the receipt names the generation in force, not the one before"
        );
        let queued = clipboard_rx.recv().await.expect("the payload was queued");
        take_clipboard(&state, &mut wire.writer, queued)
            .await
            .expect("the writer takes a payload the fence admits");
        match received(&mut wire.peer).await.union {
            Some(message::Union::Clipboard(clipboard)) => {
                assert_eq!(clipboard.content.as_ref(), b"kept".as_slice());
                assert!(
                    !clipboard.compress,
                    "a payload that saves nothing is not compressed"
                );
            }
            other => panic!("expected one clipboard, got {other:?}"),
        }

        // The other direction on the same state: the peer's message goes through
        // the decode step and lands in the mailbox under the generation in force.
        super::clipboard_decode_once(
            &state,
            live,
            ClipboardMessage::Single(base::message_proto::Clipboard {
                compress: false,
                content: b"from peer".to_vec().into(),
                format: base::message_proto::ClipboardFormat::Text.into(),
                ..Default::default()
            }),
        )
        .await
        .expect("one decode step");
        assert!(viewer.snapshot().clipboard_pending);
        let metadata = viewer.clipboard_take_metadata().expect("a hand-out");
        assert!(!viewer.snapshot().clipboard_pending);
        assert_eq!(metadata.revision, live);
        assert_eq!(metadata.text.as_deref(), Some("from peer"));
    }

    /// The enqueue boundary answers with the generation it stamped, and the
    /// answer is a receipt a caller can act on: the event queued behind it
    /// carries exactly that generation.
    #[test]
    fn a_queued_event_is_answered_with_the_generation_that_stamps_it() {
        let (viewer, mut queue) = writer_viewer();
        let admitted = viewer.snapshot().input_generation;
        assert!(
            admitted > 0,
            "a started viewer reports the generation its admission belongs to"
        );

        let receipt = viewer
            .send_mouse(3, 0, 0, 1, admitted)
            .expect("the generation in force is admitted");
        assert_eq!(
            receipt, admitted,
            "the answer is the stamp the queued event carries"
        );
        let keyed = viewer
            .send_rustdesk_key(control_key_event(true), receipt)
            .expect("the event named with that receipt's generation is admitted");
        assert_eq!(
            keyed, receipt,
            "a receipt is a generation a caller may name"
        );

        let pointer = queue.try_recv().expect("the pointer event was queued");
        assert_eq!(pointer.generation, admitted);
        let key = queue.try_recv().expect("the key event was queued");
        assert_eq!(key.generation, admitted);
    }

    /// A generation a boundary change has left behind is refused at the enqueue
    /// boundary: it is never restamped under the generation in force, and a
    /// refused event queues nothing.
    #[test]
    fn a_stale_generation_is_refused_rather_than_restamped() {
        let (viewer, mut queue) = writer_viewer();
        let first = viewer.snapshot().input_generation;

        // A revocation refuses first, because the policy in force is what stops
        // this event before its generation is even compared.
        let revoked = viewer.set_input_policy(ViewerInputPolicy::read_only());
        assert!(revoked.revoked, "read-only stops admitting input");
        assert!(matches!(
            viewer.send_rustdesk_key(control_key_event(true), first),
            Err(ViewerError::InputNotAllowed)
        ));

        // Admitted again: the generation the caller named is gone, so the event
        // is refused instead of being emitted under the new one.
        let regranted = viewer.set_input_policy(ViewerInputPolicy::interactive());
        assert!(
            regranted.input_generation > first,
            "the boundary moved while the caller was acting on the old one"
        );
        assert!(matches!(
            viewer.send_rustdesk_key(control_key_event(true), first),
            Err(ViewerError::StaleInputGeneration)
        ));
        assert!(matches!(
            viewer.send_mouse(3, 0, 0, 1, first),
            Err(ViewerError::StaleInputGeneration)
        ));
        assert!(
            queue.try_recv().is_err(),
            "a refused event queues nothing for the peer"
        );

        // The generation the boundary published now is admitted, and its receipt
        // is that generation — never the stale one the caller started with.
        let receipt = viewer
            .send_rustdesk_key(control_key_event(true), regranted.input_generation)
            .expect("the generation in force is admitted");
        assert_eq!(receipt, regranted.input_generation);
        let event = queue.try_recv().expect("the admitted event was queued");
        assert_eq!(event.generation, regranted.input_generation);
    }

    /// The second-factor entry point admits one code per peer answer, only while
    /// the session really waits for one, and never reports an admission it did
    /// not make.
    ///
    /// The gate is driven the way authentication drives it: the sender published
    /// there is what a submission travels on, and clearing `submitted` is what
    /// the peer's own `Wrong 2FA Code` does before a retry.
    #[test]
    fn a_second_factor_code_is_admitted_only_while_the_peer_waits_for_one() {
        let state = writer_state();
        let (mouse, _queue) = mpsc::channel(COMMANDS);
        let viewer = Viewer {
            state: state.clone(),
            mouse,
        };

        // Before the peer asks: refused, and nothing is held for a later step.
        assert!(matches!(
            viewer.send_second_factor("111111".into()),
            Err(ViewerError::SecondFactorNotAwaiting)
        ));

        // The authentication loop installs the entry point when the peer asks,
        // and it is the channel that loop is itself reading.
        let (codes, mut answers) = mpsc::channel(1);
        *lock(&state.second_factor) = SecondFactorGate {
            code: Some(codes.clone()),
            submitted: false,
        };
        viewer
            .send_second_factor("222222".into())
            .expect("the code the peer asked for is admitted");
        assert_eq!(
            answers
                .try_recv()
                .expect("the admitted code reached the loop"),
            "222222"
        );

        // A second code while the first is unanswered is refused, not queued
        // into whichever attempt answers next.
        assert!(matches!(
            viewer.send_second_factor("333333".into()),
            Err(ViewerError::Backpressure)
        ));
        assert!(answers.try_recv().is_err());

        // The peer's own `Wrong 2FA Code` re-arms the step for the retry.
        {
            let mut gate = lock(&state.second_factor);
            gate.submitted = false;
        }
        viewer
            .send_second_factor("444444".into())
            .expect("a retry after the peer's answer is admitted");
        assert_eq!(
            answers.try_recv().expect("the retry reached the loop"),
            "444444"
        );

        // Once authentication leaves the step, the entry point is gone even
        // though the channel is still open.
        *lock(&state.second_factor) = SecondFactorGate::default();
        assert!(matches!(
            viewer.send_second_factor("555555".into()),
            Err(ViewerError::SecondFactorNotAwaiting)
        ));

        // A viewer that is closing refuses before it looks at the gate at all.
        *lock(&state.second_factor) = SecondFactorGate {
            code: Some(codes),
            submitted: false,
        };
        viewer.request_close();
        assert!(matches!(
            viewer.send_second_factor("666666".into()),
            Err(ViewerError::Closed)
        ));
        assert!(answers.try_recv().is_err());
    }

    /// The actual authentication driver must not cancel an echo write when a
    /// local code arrives. A one-byte duplex forces every write to yield.
    #[tokio::test]
    async fn second_factor_driver_preserves_probe_and_repeated_rejections() {
        use crate::handshake::{self, ViewerIdentity};
        use crate::session::ViewerSession;
        use base::message_proto::{Hash, LoginResponse, PeerInfo, TestDelay};

        async fn wait_challenge(state: &State, revision: u64) {
            while lock(&state.inner).snapshot.second_factor_challenge != revision {
                tokio::task::yield_now().await;
            }
        }

        tokio::time::timeout(RECEIVE_LIMIT, async {
            for mode in [crate::session::SessionMode::Desktop, crate::session::SessionMode::FileTransfer] {
            let address = "127.0.0.1:1".parse().unwrap();
            let (client, peer) = tokio::io::duplex(1);
            let mut peer = FramedStream::from(peer, address);
            let (established, greeting) = tokio::join!(
                handshake::viewer(
                    FramedStream::from(client, address),
                    ViewerIdentity::LegacyUnverified,
                    RECEIVE_LIMIT,
                ),
                receive(&mut peer),
            );
            assert!(greeting.union.is_none());
            let session = ViewerSession::from_established(
                established.unwrap(), RECEIVE_LIMIT, RECEIVE_LIMIT,
            );
            let state = writer_state();
            state.authenticated.store(false, super::Ordering::Release);
            let (mouse, _) = mpsc::channel(COMMANDS);
            let viewer = Viewer { state: state.clone(), mouse };
            let options = super::ViewerOptions {
                target: super::ViewerTarget::RustDesk { address: None },
                mode,
                transfer_root: None,
                username: "fixture".into(),
                local_id: "controller".into(),
                local_name: "fixture".into(),
                password: String::new(),
                conn_token: None,
                requested_fps: 0,
                input_policy: ViewerInputPolicy::interactive(),
                session_options: Default::default(),
            };
            let mut password = super::Password(Vec::new());
            let (codes, answers) = mpsc::channel(1);
            let (passwords, password_answers) = mpsc::channel(1);
            let mut answers = super::AuthAnswers {
                codes: answers,
                passwords: password_answers,
            };
            let driver = super::authenticate_loop(
                &state, session, &options, &mut password, None, Default::default(),
                &codes, &passwords, &mut answers,
            );
            let fixture = async {
                let mut challenge = Message::new();
                challenge.set_hash(Hash {
                    salt: "fixture".into(), challenge: "challenge".into(),
                    ..Default::default()
                });
                peer.send(&challenge).await.unwrap();
                let Some(message::Union::LoginRequest(request)) = receive(&mut peer).await.union else {
                    panic!("expected the owned login request");
                };
                assert_eq!(request.has_file_transfer(), mode == crate::session::SessionMode::FileTransfer);
                assert_eq!(request.option.is_some(), mode == crate::session::SessionMode::Desktop);
                refuse(&mut peer, "2FA Required").await;
                wait_challenge(&state, 1).await;

                let mut probe = Message::new();
                probe.set_test_delay(TestDelay { time: 37, ..Default::default() });
                peer.send(&probe).await.unwrap();
                viewer.send_second_factor("111111".into()).unwrap();
                let mut echoed = false;
                let mut answered = false;
                for _ in 0..2 {
                    match receive(&mut peer).await.union {
                        Some(message::Union::TestDelay(probe)) => {
                            assert!(!echoed);
                            assert_eq!(probe.time, 37);
                            echoed = true;
                        }
                        Some(message::Union::Auth2fa(factor)) => {
                            assert!(!answered);
                            assert_eq!(factor.code, "111111");
                            answered = true;
                        }
                        _ => panic!("unexpected authentication reply"),
                    }
                }
                assert!(echoed && answered);
                for revision in 2..=3 {
                    refuse(&mut peer, "Wrong 2FA Code").await;
                    wait_challenge(&state, revision).await;
                    assert_eq!(lock(&state.inner).snapshot.phase, "second_factor_rejected");
                    viewer.send_second_factor("222222".into()).unwrap();
                    assert_eq!(lock(&state.inner).snapshot.phase, "verifying_second_factor");
                    assert!(matches!(receive(&mut peer).await.union,
                        Some(message::Union::Auth2fa(_))));
                }
                let mut success = LoginResponse::new();
                success.set_peer_info(PeerInfo::new());
                let mut message = Message::new();
                message.set_login_response(success);
                peer.send(&message).await.unwrap();
            };
            let (result, ()) = tokio::join!(driver, fixture);
            assert!(result.is_ok());
            assert_eq!(lock(&state.inner).snapshot.second_factor_challenge, 3);
            }
        }).await.expect("authentication and all replies must finish within one budget");
    }

    /// The password entry point admits one answer per peer demand, only while
    /// this session really waits for one, and never reports an admission it did
    /// not make.
    ///
    /// The gate is driven the way authentication drives it: the sender published
    /// there is what a submission travels on, and clearing `submitted` is what
    /// the peer's own `Wrong Password` does before the retry.
    #[test]
    fn a_password_is_admitted_only_while_the_peer_waits_for_one() {
        let state = writer_state();
        state.authenticated.store(false, super::Ordering::Release);
        let (mouse, _queue) = mpsc::channel(COMMANDS);
        let viewer = Viewer {
            state: state.clone(),
            mouse,
        };

        // Before the peer asks: refused, and nothing is held for a later step.
        assert!(matches!(
            viewer.send_password("secret-1".into()),
            Err(ViewerError::PasswordNotAwaiting)
        ));

        // The authentication loop installs the entry point when the peer demands
        // one, and it is the channel that loop is itself reading.
        let (passwords, mut answers) = mpsc::channel(1);
        {
            let mut gate = lock(&state.password);
            gate.password = Some(passwords.clone());
            gate.submitted = false;
            let mut inner = lock(&state.inner);
            inner.snapshot.phase = "awaiting_password".into();
            inner.snapshot.password_failure = Some(super::LoginFailure::EmptyPassword);
        }
        viewer
            .send_password("secret-2".into())
            .expect("the password the peer demanded is admitted");
        assert_eq!(
            answers
                .try_recv()
                .expect("the admitted password reached the loop"),
            "secret-2"
        );
        // Queued is not authenticated: the phase says the answer is being
        // written and the session stays unauthorized until the peer says
        // otherwise.
        assert_eq!(lock(&state.inner).snapshot.phase, "verifying_password");
        assert_eq!(lock(&state.inner).snapshot.password_failure, None);
        assert!(!viewer.snapshot().authenticated);

        // A second answer while the first is unwritten is refused, not queued
        // into whichever attempt answers next.
        assert!(matches!(
            viewer.send_password("secret-3".into()),
            Err(ViewerError::Backpressure)
        ));
        // An empty string is not an answer: the wire spells "no password" that
        // way, which is the attempt the peer just refused.
        assert!(matches!(
            viewer.send_password(String::new()),
            Err(ViewerError::InvalidPassword)
        ));
        assert!(answers.try_recv().is_err());

        // The peer's own `Wrong Password` re-arms the step for the retry.
        {
            let mut gate = lock(&state.password);
            gate.submitted = false;
        }
        viewer
            .send_password("secret-4".into())
            .expect("a retry after the peer's answer is admitted");
        assert_eq!(
            answers.try_recv().expect("the retry reached the loop"),
            "secret-4"
        );

        // Once authentication leaves the step, the entry point is gone even
        // though the channel is still open.
        *lock(&state.password) = PasswordGate::default();
        assert!(matches!(
            viewer.send_password("secret-5".into()),
            Err(ViewerError::PasswordNotAwaiting)
        ));

        // A viewer that is closing refuses before it looks at the gate at all.
        {
            let mut gate = lock(&state.password);
            gate.password = Some(passwords);
            gate.submitted = false;
        }
        viewer.request_close();
        assert!(matches!(
            viewer.send_password("secret-6".into()),
            Err(ViewerError::Closed)
        ));
        assert!(answers.try_recv().is_err());
    }

    /// The password a peer demands is answered on the same wire.
    ///
    /// The refused login is resent with the answer under the identity, session
    /// id and role it carried — one login attempt, not a second dial — and the
    /// exchange then reaches the second-factor step instead of ending at the
    /// password. A one-byte duplex forces every write to yield, so the probe
    /// echo and the two logins also prove the read select never held a
    /// half-written wire.
    #[tokio::test]
    async fn password_retry_reuses_the_refused_login_and_reaches_the_next_step() {
        use crate::handshake::{self, ViewerIdentity};
        use crate::session::ViewerSession;
        use base::message_proto::{Hash, LoginResponse, PeerInfo, TestDelay};

        async fn wait_password(state: &State, revision: u64) {
            while lock(&state.inner).snapshot.password_challenge != revision {
                tokio::task::yield_now().await;
            }
        }

        tokio::time::timeout(RECEIVE_LIMIT, async {
            for mode in [
                crate::session::SessionMode::Desktop,
                crate::session::SessionMode::FileTransfer,
            ] {
                let address: SocketAddr = "127.0.0.1:1".parse().unwrap();
                let (client, peer) = tokio::io::duplex(1);
                let mut peer = FramedStream::from(peer, address);
                let (established, greeting) = tokio::join!(
                    handshake::viewer(
                        FramedStream::from(client, address),
                        ViewerIdentity::LegacyUnverified,
                        RECEIVE_LIMIT,
                    ),
                    receive(&mut peer),
                );
                assert!(greeting.union.is_none());
                let session = ViewerSession::from_established(
                    established.unwrap(),
                    RECEIVE_LIMIT,
                    RECEIVE_LIMIT,
                );
                let state = writer_state();
                state.authenticated.store(false, super::Ordering::Release);
                let (mouse, _) = mpsc::channel(COMMANDS);
                let viewer = Viewer {
                    state: state.clone(),
                    mouse,
                };
                let options = super::ViewerOptions {
                    target: super::ViewerTarget::RustDesk { address: None },
                    mode,
                    transfer_root: None,
                    username: "fixture".into(),
                    local_id: "controller".into(),
                    local_name: "fixture".into(),
                    password: String::new(),
                    conn_token: None,
                    requested_fps: 0,
                    input_policy: ViewerInputPolicy::interactive(),
                    session_options: Default::default(),
                };
                // The attempt starts without one, which is what makes the peer
                // demand it.
                let mut password = super::Password(Vec::new());
                let (codes, code_answers) = mpsc::channel(1);
                let (passwords, password_answers) = mpsc::channel(1);
                let mut answers = super::AuthAnswers {
                    codes: code_answers,
                    passwords: password_answers,
                };
                let driver = super::authenticate_loop(
                    &state,
                    session,
                    &options,
                    &mut password,
                    None,
                    Default::default(),
                    &codes,
                    &passwords,
                    &mut answers,
                );
                let fixture = async {
                    let mut challenge = Message::new();
                    challenge.set_hash(Hash {
                        salt: "fixture".into(),
                        challenge: "challenge".into(),
                        ..Default::default()
                    });
                    peer.send(&challenge).await.unwrap();
                    // The first login is the one a retry has to reuse.
                    let Some(message::Union::LoginRequest(first)) =
                        receive(&mut peer).await.union
                    else {
                        panic!("expected the owned login request");
                    };
                    assert!(first.password.is_empty());
                    assert_eq!(
                        first.has_file_transfer(),
                        mode == crate::session::SessionMode::FileTransfer
                    );
                    assert_eq!(
                        first.option.is_some(),
                        mode == crate::session::SessionMode::Desktop
                    );
                    let (identity, session_id) = (first.my_id.clone(), first.session_id);

                    // The peer wants a password this attempt did not send.
                    refuse(&mut peer, "Empty Password").await;
                    wait_password(&state, 1).await;
                    {
                        let inner = lock(&state.inner);
                        assert_eq!(inner.snapshot.phase, "awaiting_password");
                        assert_eq!(
                            inner.snapshot.password_failure,
                            Some(super::LoginFailure::EmptyPassword)
                        );
                    }
                    assert!(
                        !viewer.snapshot().authenticated,
                        "a demanded password is not an authorization"
                    );

                    // The read select still answers probes while it waits for
                    // the operator's answer: the echo is written outside it.
                    let mut probe = Message::new();
                    probe.set_test_delay(TestDelay {
                        time: 41,
                        ..Default::default()
                    });
                    peer.send(&probe).await.unwrap();
                    // Queue the answer while the one-byte wire is still writing
                    // the probe reply. `submitted` must not disable reception of
                    // this already admitted answer on the next loop pass.
                    viewer.send_password("first-try".into()).unwrap();
                    assert_eq!(lock(&state.inner).snapshot.phase, "verifying_password");
                    let Some(message::Union::TestDelay(echoed)) = receive(&mut peer).await.union
                    else {
                        panic!("expected the probe echo");
                    };
                    assert_eq!(echoed.time, 41);

                    // The answer is the refused login again, not a new one.
                    let Some(message::Union::LoginRequest(retried)) =
                        receive(&mut peer).await.union
                    else {
                        panic!("expected the retried login request");
                    };
                    assert_eq!(retried.session_id, session_id, "the same login attempt");
                    assert_eq!(retried.my_id, identity);
                    assert_eq!(retried.username, "fixture");
                    assert!(!retried.password.is_empty());
                    assert_eq!(
                        retried.has_file_transfer(),
                        mode == crate::session::SessionMode::FileTransfer
                    );

                    // The peer refused it: the step is armed again, and the
                    // second answer is that same login once more.
                    refuse(&mut peer, "Wrong Password").await;
                    wait_password(&state, 2).await;
                    {
                        let inner = lock(&state.inner);
                        assert_eq!(inner.snapshot.phase, "password_rejected");
                        assert_eq!(
                            inner.snapshot.password_failure,
                            Some(super::LoginFailure::WrongPassword)
                        );
                    }
                    viewer.send_password("second-try".into()).unwrap();
                    let Some(message::Union::LoginRequest(accepted)) =
                        receive(&mut peer).await.union
                    else {
                        panic!("expected the second retried login request");
                    };
                    assert_eq!(accepted.session_id, session_id);
                    assert!(!accepted.password.is_empty());

                    // Past the password, the session reaches the next step it
                    // owns: a code on this same wire.
                    refuse(&mut peer, "2FA Required").await;
                    while lock(&state.inner).snapshot.second_factor_challenge != 1 {
                        tokio::task::yield_now().await;
                    }
                    viewer.send_second_factor("111111".into()).unwrap();
                    let Some(message::Union::Auth2fa(factor)) =
                        receive(&mut peer).await.union
                    else {
                        panic!("expected the second-factor answer");
                    };
                    assert_eq!(factor.code, "111111");

                    let mut success = LoginResponse::new();
                    success.set_peer_info(PeerInfo::new());
                    let mut message = Message::new();
                    message.set_login_response(success);
                    peer.send(&message).await.unwrap();
                };
                let (result, ()) = tokio::join!(driver, fixture);
                assert!(result.is_ok(), "the same wire reaches authorization");
                let snapshot = lock(&state.inner).snapshot.clone();
                assert_eq!(snapshot.password_challenge, 2);
                assert_eq!(snapshot.second_factor_challenge, 1);
                // The last answer is on the wire, so no mid-flight reason is
                // left beside the authorized session.
                assert_eq!(snapshot.password_failure, None);
            }
        })
        .await
        .expect("the whole exchange must finish within one budget");
    }
