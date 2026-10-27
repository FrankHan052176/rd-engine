#ifndef RD_WINDOWS_INPUT_H_
#define RD_WINDOWS_INPUT_H_

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define RD_INPUT_CALL __cdecl
#if defined(RD_INPUT_BUILD)
#define RD_INPUT_API __declspec(dllexport)
#else
#define RD_INPUT_API __declspec(dllimport)
#endif
#else
#define RD_INPUT_CALL
#define RD_INPUT_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Checked keyboard/pointer injection for the Windows host, with an observation
 * guard.
 *
 * Everything this adapter injects goes through SendInput. It deliberately
 * cannot:
 *
 *   * reach the secure (UAC prompt, Ctrl+Alt+Del, logon) desktop,
 *   * raise its own integrity level or UIAccess,
 *   * serve a session that is not the session whose input desktop is open,
 *   * produce the secure attention sequence (Ctrl+Alt+Del) or the Win+L shell
 *     action; the caller refuses those before they reach here,
 *   * register raw input devices, install a driver, block local input, or
 *     claim a per-device view of the keyboard and mouse.
 *
 * # Two Win32 facts that bound what "success" can mean
 *
 *   * SendInput reports how many events it inserted, not how many were
 *     delivered. UIPI silently withholds injected input whose target window is
 *     at a higher integrity level, and this adapter never tries to defeat that.
 *     It inserts a batch in order and does not claim that a short count means a
 *     leading prefix took effect, so the count is never used to decide which
 *     events of a batch happened here.
 *   * A low-level hook runs on the thread that installed it, needs a message
 *     loop there, and is silently removed by Windows when it exceeds
 *     LowLevelHooksTimeout (1000 ms at most on Windows 10 1709 and later) with
 *     no API to observe the removal. A heartbeat on that thread proves the
 *     message loop ran recently; it does not prove the hook is still in the
 *     chain, and it cannot. What the guard can prove is the fate of the events
 *     it was asked to observe: an own event that carries this adapter's token
 *     and never reaches the hook leaves its receipt unknown, which faults the
 *     guard and stops new injection. That detection is after the fact - the
 *     event that was never observed may already have been delivered.
 *
 * # The observation guard
 *
 * One process-wide guard, referenced by leases. The first lease starts a
 * dedicated message thread that installs WH_KEYBOARD_LL and WH_MOUSE_LL and a
 * heartbeat timer. A start opens an observation generation before that thread
 * exists - so a hook of this start can only record events into a state that is
 * already being initialized - installs both hooks and the heartbeat timer (the
 * id SetTimer actually assigned, which is also the id its message loop watches
 * and kills), and publishes the guard as armed only when the hooks, the timer
 * and the initial key-state coordination are all done. The guard holds no peer
 * ownership: it owns the observed state of every canonical hold key, the
 * injection episodes it has seen pass, their sticky collision state, and the
 * per-event receipts of the transactions in flight. Ownership of a peer's holds
 * is the caller's table; this adapter only reports what it observed.
 *
 * Every key starts unknown. While the guard is armed it establishes a key's
 * state from the events it observes. At arm time it also takes a
 * GetAsyncKeyState sample in a usable ordinary-desktop context, but only to
 * establish a key this generation has not established: an event of this
 * generation that was already observed is never overwritten by a sample that
 * read the state before the event took effect. GetAsyncKeyState takes one
 * virtual key and does not separate a key from its E0 twin (a main Enter from a
 * numpad Enter, the extended Insert from the one beside the numpad), so a key
 * that reads down marks both canonical forms down - nothing may claim either
 * form while the sample cannot say which one is down - and a key that reads up
 * establishes both. The same holds for the Shift, Control and Menu families,
 * whose sides are read separately because a sample of the wildcard alone does
 * not say whether either side is down; either side down marks the family down.
 * A sample is a statement about the merged input stream in this session, never
 * about individual devices: no low-level hook carries a device id, so two
 * devices holding the same key cannot be told apart, and a key that is down
 * cannot be attributed to a physical keyboard, another injector or an earlier
 * injection.
 *
 * Per key the guard keeps: whether the state is established at all; whether the
 * merged stream last said down, and whether that down was this adapter's own
 * tracked injection; whether the down of the episode that holds the key was
 * seen to pass this guard and the rest of the hook chain; the encoding that down
 * was injected with, as the hook saw it; a sticky collision flag once a down
 * that is not this adapter's own was observed while an own hold was open; the
 * observation sequence of the last collision and of the last qualifying external
 * release; the observation sequence of the last event observed for the key; and
 * whether an own episode still holds the key. The observation sequence is
 * monotonic for the life of the process and never wraps: at its limit the guard
 * latches instead of handing out a value a stale sequence could be taken for.
 *
 * # Injection episodes, tokens and receipts
 *
 * Before SendInput is called, one descriptor per hold event of the batch (key
 * and mouse-button down/up events, at most RD_INPUT_MAX_HOLDS of them) is
 * published in a fixed table inside the guard, and each such event carries the
 * descriptor's cookie in dwExtraInfo. Cookies stay in the uint32 range because
 * mouse delivery can discard the upper half on x64. They increase without reuse;
 * the guard remembers the issued interval across clean stops, and refuses new
 * issuance before the range is exhausted. The hook correlates an injected event
 * with its descriptor by the full received cookie, canonical key and direction,
 * never a pointer from dwExtraInfo or the caller's batch. Only after
 * CallNextHookEx returns does it publish that event's terminal receipt. The
 * cookie is an association mark, not a credential: another process can supply
 * the same value. Non-injected events remain external regardless of their mark.
 *
 * A tracked event is refused by the guard ("vetoed") when it is an own event
 * that must not reach the system:
 *
 *   * a down for a key that is not clear, or a down whose event does not name
 *     the exact episode, lease and epoch the key already holds - it must never
 *     duplicate a hold, and a new episode is admitted by rd_input_key_admit(),
 *     not by an injection,
 *   * an up for an episode the guard no longer holds, for an episode the guard
 *     never saw pass the hook chain, or for one whose down the chain vetoed: an
 *     up must never lift a hold this adapter never pressed,
 *   * a hold event for an episode whose key carries a sticky collision - the
 *     up that would release the caller's hold would also release the local or
 *     foreign hold observed underneath it, so the caller's record stays owned
 *     and the hold is resolved by evidence instead (see below),
 *   * any own event while the guard is not armed, and any injected event whose
 *     issued cookie has no live transaction or disagrees with its expected key
 *     or direction. Such an event is refused and faults the guard; a mismatched
 *     event never supplies a receipt for the event the descriptor describes.
 *
 * A down that names the episode, lease and epoch the key already holds, in the
 * same encoding its opening down was injected with, is a repeat of the caller's
 * own hold. It may pass when that down was seen to pass the hook chain, when the
 * key carries no collision and is not unknown, and when the merged stream still
 * holds the key; a repeat reopens no episode, claims nothing, releases nothing
 * and clears no collision history. A repeat of a hold that was refused
 * downstream, that carries a collision, or that is otherwise not confirmed is
 * refused like any other hold event, so a hold in doubt is never re-confirmed by
 * pressing the same key again.
 *
 * Local and third-party events always pass through. Events that are not the
 * guard's own but are injected (LLKHF_INJECTED / LLMHF_INJECTED) are not
 * treated as physical: they are external occupancy, and a down of that kind
 * observed while an own hold is open marks the same sticky collision, because
 * this adapter must not lift a hold it cannot attribute either.
 *
 * # Retirement, and what it is not
 *
 * A collision is never resolved by re-sending an up or a down. rd_input_episode_
 * retire() resolves one episode of one key only when all of these hold, checked
 * at the moment of the call: the guard is still armed for that epoch; the calling
 * thread is on the ordinary interactive desktop; the merged state of that key
 * reads up; no event for that key was observed after the sample; the episode has
 * no event in flight; and, when the episode carries a collision, a release of
 * the colliding source was observed after the last collision (a non-injected one
 * when the collision itself was physical).
 *
 * Resolving an episode is not the same as the key being claimable again, and the
 * two are not conflated here. An episode that was retired after a collision
 * leaves the key unknown, not clear: no low-level hook carries a device id, so a
 * release that is not this adapter's says nothing about who held the key, an
 * automatic repeat cannot be told from a second device's press, and a key that
 * two devices hold together reads up as soon as one of them lets go. The key
 * therefore stays blocked - rd_input_key_admit() answers RD_INPUT_KEY_HELD_UNKNOWN
 * and no new episode may claim it - until an event establishes what the key is
 * again, and the guard reports that this happened in
 * RD_INPUT_GUARD_FLAG_RETIRED_UNATTRIBUTED. An episode with no collision is
 * resolved against the same merged-state sample that establishes a key at arm
 * time, so that key reads clear. A retirement in no case claims that a device is
 * physically released, lifts anything, or proves that every device holding the
 * key let go. A key with an episode that ran out of observation - a fault, a
 * desktop change, a missing receipt - can no longer be retired at all, because
 * continuity is gone; the guard keeps the record and the caller keeps its
 * ownership.
 *
 * # Explicit lifetimes
 *
 * Guard state is referenced by lease. rd_input_guard_acquire() gives one lease
 * and an epoch; rd_input_guard_release() takes it back. A lease is added only to
 * a guard that is armed at that moment, so an acquire never returns a lease on a
 * guard that is idle or stopping. When the last lease is given back and nothing
 * is unresolved - no key blocked by a collision that was not retired, no own
 * event whose fate is unknown - the guard closes admission, removes both hooks,
 * stops the message thread, joins it, and reports the guard idle; a message
 * thread that exited on its own and is still accounted for is joined there too,
 * so a guard that stops leaves nothing behind.
 *
 * A lease is consumed only when the guard's resources really are given up. If the
 * message thread cannot be joined, if a hook the system was asked to remove is
 * still installed, or if a start could not reclaim what it created, the guard
 * reports RD_INPUT_RECLAMATION_UNCONFIRMED and keeps what it could not release -
 * for a release that includes the lease itself, so the next release retries the
 * same checked stop, and for an acquire the thread, its startup event, its module
 * reference and its hook handles, so a later acquire or release reclaims them. No
 * repeated call can turn an unfinished stop into a clean one, and the caller must
 * not treat such a release as done. While any key is still blocked, or while an
 * own event is still in flight, or while a lease is still outstanding, the guard
 * stays installed and armed for observation: unhooking it would let a late own
 * event through unguarded.
 *
 * The hook callbacks live in the module that contains them. As long as any of
 * this guard's code can still run - its message thread, or a thread that could
 * not be joined - the guard holds a reference to that module (not an
 * unchanged-refcount lookup), together with the startup event its thread may
 * still signal, and releases both only after the message thread has been joined;
 * a callback in flight when UnhookWindowsHookEx returns is the reason that order
 * is required, not an optional nicety.
 *
 * The guard's internal lock is one exclusive SRW lock. It is short - it is never
 * held across SendInput, a sleep, a hook-chain call, a GetAsyncKeyState sample or
 * a join - but taking it is a blocking acquisition, not a try-lock, so a hook
 * callback can wait for a sender that holds it for such a bounded operation.
 *
 * # No input content leaves this adapter
 *
 * Nothing here logs, stores or returns a key, a coordinate, a character, a text
 * sequence or a window title. Every receipt, verdict and flag describes resource
 * state only.
 */

typedef enum rd_input_status {
  RD_INPUT_OK = 0,
  RD_INPUT_INVALID_ARGUMENT = 1,
  RD_INPUT_DESKTOP_UNAVAILABLE = 2,
  RD_INPUT_INJECTION_FAILED = 3,
  RD_INPUT_UNSUPPORTED = 4,
  /* The observation guard is not armed for the epoch the caller asked for, or
   * it has faulted: no injection happens. */
  RD_INPUT_GUARD_UNAVAILABLE = 5,
  /* A hold this adapter injected may still be down, and the state that would
   * confirm or resolve it is not available. Records stay owned. */
  RD_INPUT_RECLAMATION_UNCONFIRMED = 6
} rd_input_status;

/* One batch carries at most this many events, and at most this many hold events
 * (key and mouse button down/up events). The caller bounds a batch the same
 * way, and a batch beyond either bound is refused before anything is injected.
 */
enum {
  RD_INPUT_MAX_EVENTS = 4112,
  RD_INPUT_MAX_HOLDS = 64
};

/* What desktop the calling session currently has as its input desktop.
 * RD_INPUT_DESKTOP_INTERACTIVE is the ordinary user desktop ("Default"); a
 * secure desktop (Winlogon, the UAC prompt) or any other desktop, including a
 * session that has no input desktop at all, is not an injection target. */
typedef enum rd_input_desktop_kind {
  RD_INPUT_DESKTOP_UNKNOWN = 0,
  RD_INPUT_DESKTOP_INTERACTIVE = 1,
  RD_INPUT_DESKTOP_SECURE = 2,
  RD_INPUT_DESKTOP_OTHER = 3
} rd_input_desktop_kind;

typedef enum rd_input_event_kind {
  RD_INPUT_EVENT_MOUSE = 0,
  RD_INPUT_EVENT_KEY = 1,
  RD_INPUT_EVENT_TEXT = 2
} rd_input_event_kind;

typedef enum rd_input_mouse_action {
  /* x,y are normalized 0..65535 across the virtual desktop; the adapter always
   * sets MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK for them. */
  RD_INPUT_MOUSE_MOVE_ABSOLUTE = 0,
  /* x,y are signed pixel deltas. */
  RD_INPUT_MOUSE_MOVE_RELATIVE = 1,
  RD_INPUT_MOUSE_BUTTON_DOWN = 2,
  RD_INPUT_MOUSE_BUTTON_UP = 3,
  /* data is a signed rotation in WHEEL_DELTA (120) units. */
  RD_INPUT_MOUSE_WHEEL = 4,
  RD_INPUT_MOUSE_HWHEEL = 5
} rd_input_mouse_action;

typedef enum rd_input_button {
  RD_INPUT_BUTTON_LEFT = 0,
  RD_INPUT_BUTTON_RIGHT = 1,
  RD_INPUT_BUTTON_MIDDLE = 2,
  RD_INPUT_BUTTON_BACK = 3,
  RD_INPUT_BUTTON_FORWARD = 4
} rd_input_button;

typedef enum rd_input_key_flags {
  RD_INPUT_KEY_DOWN = 0,
  RD_INPUT_KEY_UP = 1,
  RD_INPUT_KEY_EXTENDED = 2,
  /* Physical Windows Map scan code: SendInput gets wVk=0 and
   * KEYEVENTF_SCANCODE. virtual_key remains the OS-mapped canonical identity
   * for the existing guard, not a virtual-key injection fallback. */
  RD_INPUT_KEY_SCANCODE = 4
} rd_input_key_flags;

typedef struct rd_input_event {
  uint32_t struct_size;
  uint32_t kind;         /* rd_input_event_kind */
  uint32_t flags;        /* key/text: rd_input_key_flags; mouse: 0 */
  uint32_t action;       /* mouse: rd_input_mouse_action; otherwise 0 */
  uint32_t button;       /* mouse DOWN/UP: rd_input_button; otherwise 0 */
  uint32_t virtual_key;  /* key: Win32 key; SCANCODE: frozen mapped guard key */
  uint32_t scan_code;    /* virtual-key mode: layout scan, 0 if none;
                         * SCANCODE mode: pinned Windows wire scan, 0x01..0xFF
                         * or 0xE001..0xE0FF, retaining its E0 prefix */
  uint32_t reserved;     /* must be 0 */
  int32_t x;             /* mouse: normalized absolute coordinate or delta */
  int32_t y;             /* mouse: normalized absolute coordinate or delta */
  int32_t data;          /* mouse WHEEL/HWHEEL: signed rotation */
  int32_t code_unit;     /* text: one UTF-16 code unit */
} rd_input_event;

/*
 * The fate of one tracked event of a transaction, as this guard observed it.
 *
 * PASSED means this guard let the event through and no hook later in the chain
 * vetoed it; it does not mean a window, an application or another integrity
 * level's process received it. NOT_TRACKED means the event carries no ownership
 * decision (a move, a wheel or text). NOT_SUBMITTED means the event never
 * reached SendInput. SELF_VETOED and DOWNSTREAM_VETOED mean the event was
 * refused by this guard or by a later hook and must not be treated as an
 * injection that happened. UNKNOWN means no terminal receipt was observed for a
 * tracked event: it may or may not have been delivered, and the guard faults.
 */
typedef enum rd_input_receipt {
  RD_INPUT_RECEIPT_UNKNOWN = 0,
  RD_INPUT_RECEIPT_PASSED = 1,
  RD_INPUT_RECEIPT_SELF_VETOED = 2,
  RD_INPUT_RECEIPT_DOWNSTREAM_VETOED = 3,
  RD_INPUT_RECEIPT_NOT_SUBMITTED = 4,
  RD_INPUT_RECEIPT_NOT_TRACKED = 5
} rd_input_receipt;

typedef enum rd_input_guard_state {
  /* No lease holds the guard and no hook is installed. */
  RD_INPUT_GUARD_IDLE = 0,
  /* Observing. Only an armed guard admits, injects or retires. */
  RD_INPUT_GUARD_ARMED = 1,
  /* Installed but not usable for injection: a known fault closed admission and
   * the pending records are kept. A later acquire arms a new epoch; the keys
   * that fault left blocked stay blocked. */
  RD_INPUT_GUARD_FAULTED = 2,
  /* Shutting down, or stopped short of a clean stop. */
  RD_INPUT_GUARD_STOPPING = 3
} rd_input_guard_state;

typedef enum rd_input_guard_flag {
  /* An injected event carried an issued token but matched no live transaction
   * or disagreed with its expected key/direction. It was refused and admission
   * is closed; a mismatched event does not settle the expected event's receipt. */
  RD_INPUT_GUARD_FLAG_LATE_SELF_EVENT = 1u << 0,
  /* A tracked event of a submitted transaction got no terminal receipt within
   * the guard's bounded wait: the guard was not observing it. Admission is
   * closed and the transaction is sealed, never reused. */
  RD_INPUT_GUARD_FLAG_MISSING_RECEIPT = 1u << 1,
  /* The message thread found the session off the ordinary interactive desktop.
   * The epoch is invalid: observation is not continuous across a desktop
   * change. */
  RD_INPUT_GUARD_FLAG_DESKTOP_LEFT = 1u << 2,
  /* The message thread's heartbeat expired. Weak evidence: it says the message
   * loop stopped running, not that the hook is gone, and a live heartbeat does
   * not prove the hook is still installed. */
  RD_INPUT_GUARD_FLAG_HEARTBEAT_STALE = 1u << 3,
  /* No room for another transaction's descriptors, key state or lease. */
  RD_INPUT_GUARD_FLAG_STORAGE_EXHAUSTED = 1u << 4,
  /* A serial the guard must never reuse is exhausted: the token serial, the
   * epoch or the observation sequence. Nothing further is handed out and
   * admission is closed, rather than let a stale value compare as a current
   * one. */
  RD_INPUT_GUARD_FLAG_SERIAL_EXHAUSTED = 1u << 5,
  /* The message thread stopped, or a hook could not be installed or removed.
   * A hook UnhookWindowsHookEx did not remove stays in the guard's state. */
  RD_INPUT_GUARD_FLAG_THREAD_EXITED = 1u << 6,
  RD_INPUT_GUARD_FLAG_INSTALL_FAILED = 1u << 7,
  /* A hold that was not this adapter's own was observed on a key this adapter
   * holds. Recorded for honesty: such a hold has no physical owner that can be
   * named. */
  RD_INPUT_GUARD_FLAG_FOREIGN_INJECTED_HOLD = 1u << 8,
  /* An episode with a collision that could not be attributed to a source was
   * retired: the merged stream showed the key up and the episode had no event in
   * flight. This is not a statement about any device, and the key is left
   * unknown rather than clear. */
  RD_INPUT_GUARD_FLAG_RETIRED_UNATTRIBUTED = 1u << 9
} rd_input_guard_flag;

/* One snapshot of the guard. */
typedef struct rd_input_guard_snapshot {
  uint32_t struct_size;
  uint32_t state;      /* rd_input_guard_state */
  uint32_t epoch;      /* the armed epoch, 0 when none */
  uint32_t leases;     /* live leases */
  uint32_t flags;      /* rd_input_guard_flag bits */
  /* Unresolved holds: keys still blocked by a collision that was not retired,
   * plus own events whose fate is still unknown. Each of these keeps the guard
   * installed, so a guard with unresolved holds cannot reach a stopped state. */
  uint32_t unresolved;
} rd_input_guard_snapshot;

/* What the guard says about claiming one canonical hold key. */
typedef enum rd_input_key_verdict {
  /* No hold of anyone's is known: a new episode may start. */
  RD_INPUT_KEY_ADMIT = 0,
  /* The merged stream holds it and no engine lease owns it. */
  RD_INPUT_KEY_HELD_EXTERNAL = 1,
  /* An engine episode holds it. */
  RD_INPUT_KEY_HELD_ENGINE = 2,
  /* Cannot be decided - an observation fault, or a blocked key (including a key
   * a collision retirement left unknown). Do not claim. */
  RD_INPUT_KEY_HELD_UNKNOWN = 3,
  /* No armed guard for this epoch. Do not claim and do not inject. */
  RD_INPUT_KEY_GUARD_UNAVAILABLE = 4
} rd_input_key_verdict;

/* One transaction to inject. The caller keeps the arrays alive for the call. */
typedef struct rd_input_send_request {
  uint32_t struct_size;
  uint32_t epoch;       /* the guard epoch this batch was planned under */
  uint64_t lease;       /* the caller's guard lease */
  uint64_t transaction; /* never-reused id of this batch */
  const rd_input_event* events;
  uint32_t count;
  uint32_t reserved;    /* must be 0 */
  /* count entries: the never-reused episode a hold event belongs to, or 0 for
   * an event that is not part of a hold. A hold event (a key or mouse button
   * down/up, that is a canonical hold key that is not 0) must carry a nonzero
   * episode, and an event that is not a hold must carry 0. */
  const uint64_t* episodes;
  /* count entries, written by the adapter: rd_input_receipt per event index.
   * Filled for every event, whatever the status, so the caller never has to
   * infer an event's fate from the inserted count. */
  uint32_t* receipts;
} rd_input_send_request;

typedef struct rd_input_send_result {
  uint32_t struct_size;
  uint32_t inserted;    /* SendInput's own return: events the OS accepted */
  uint32_t submitted;   /* events handed to SendInput, 0 when refused */
  uint32_t epoch;       /* the epoch the receipts belong to: the requested epoch
                         * when the batch was submitted, and the guard's current
                         * epoch on a refusal that submitted nothing */
  uint32_t guard_state; /* rd_input_guard_state after the call */
  uint32_t flags;       /* rd_input_guard_flag bits after the call */
} rd_input_send_result;

/* Reports the calling session's input desktop as rd_input_desktop_kind. A probe
 * that cannot read the desktop returns a status other than RD_INPUT_OK, never
 * INTERACTIVE. */
RD_INPUT_API rd_input_status RD_INPUT_CALL rd_input_desktop_state(
    uint32_t* kind);
/* Virtual-screen rectangle in desktop coordinates (SM_*VIRTUALSCREEN). */
RD_INPUT_API rd_input_status RD_INPUT_CALL rd_input_virtual_screen(
    int32_t* left, int32_t* top, int32_t* width, int32_t* height);

/*
 * The canonical hold identity of one key or mouse button: 0 for an event that
 * holds nothing (a move, a wheel, or text - VK_PACKET included), otherwise the
 * virtual key with the E0 form folded in as bit 0x100 and the left/right
 * modifier families folded to their generic virtual key (VK_LSHIFT and
 * VK_RSHIFT to VK_SHIFT, and the same for Control and Menu). The mouse buttons
 * are VK_LBUTTON through VK_XBUTTON2, which no keyboard key uses. The guard and
 * the caller both use this function, so they cannot disagree about which events
 * touch the same key.
 */
RD_INPUT_API uint32_t RD_INPUT_CALL rd_input_hold_key(
    uint32_t virtual_key, uint32_t extended);

/*
 * Takes one guard lease and arms the guard if needed. On RD_INPUT_OK the caller
 * holds a lease and the snapshot reports ARMED with the epoch to plan with; the
 * lease is added only to a guard that is armed at that moment, so a lease is
 * never left on a guard that is idle, stopping or faulted. A start that fails
 * cleanly (both hooks and the heartbeat timer were not installed, and what it
 * created was reclaimed) reports that failure and leaves nothing installed. A
 * start that could not reclaim what it created - a message thread that did not
 * join, a hook that did not come out of the chain - reports
 * RD_INPUT_RECLAMATION_UNCONFIRMED and keeps that thread, its startup event, its
 * module reference and its hook handles held for a later acquire or release to
 * reclaim; the snapshot says what state those resources are in.
 */
RD_INPUT_API rd_input_status RD_INPUT_CALL rd_input_guard_acquire(
    uint64_t lease, rd_input_guard_snapshot* snapshot);
/* The guard's health, whether or not this lease is current. epoch 0 asks about
 * whatever epoch is armed. A name distinct from the rd_input_guard_state type:
 * C keeps typedef names and function names in one namespace. */
RD_INPUT_API rd_input_status RD_INPUT_CALL rd_input_guard_health(
    uint32_t epoch, rd_input_guard_snapshot* snapshot);
/*
 * Releases one lease. RD_INPUT_OK means the lease is gone; the snapshot says
 * whether the guard kept observing (other leases, or holds still unresolved) or
 * stopped. The last lease is consumed only after the checked stop succeeded: if
 * the guard could not reach a stopped state - a message thread that did not
 * join, a hook that did not come out of the chain - it reports
 * RD_INPUT_RECLAMATION_UNCONFIRMED, keeps the lease and the state, and a later
 * call retries the same stop. Such a call must never be read as "this lease is
 * released": hooks or the message thread are still there, and no repeated
 * release reports a clean stop that did not happen.
 */
RD_INPUT_API rd_input_status RD_INPUT_CALL rd_input_guard_release(
    uint64_t lease, rd_input_guard_snapshot* snapshot);
/* What the guard says about claiming `key` for a new episode of `lease`. */
RD_INPUT_API rd_input_status RD_INPUT_CALL rd_input_key_admit(
    uint32_t epoch, uint64_t lease, uint32_t key, uint32_t* verdict,
    rd_input_guard_snapshot* snapshot);
/*
 * Retires one episode of one key: see the note above on what retirement proves.
 * RD_INPUT_RECLAMATION_UNCONFIRMED means the episode is not resolved and must
 * stay owned; nothing was injected either way. RD_INPUT_OK means this episode is
 * resolved - which is not a statement that the key is claimable again: an
 * episode retired after a collision leaves the key unknown until an event
 * establishes it.
 */
RD_INPUT_API rd_input_status RD_INPUT_CALL rd_input_episode_retire(
    uint32_t epoch, uint64_t lease, uint64_t episode, uint32_t key,
    rd_input_guard_snapshot* snapshot);
/*
 * Injects one batch in order through the guard. The batch is validated in full
 * before any of it is injected, so a refused batch injects nothing: every
 * refusal reports inserted 0 and submitted 0 with a coherent snapshot
 * (epoch, guard_state and flags of the guard as it was at the refusal) and a
 * full set of receipts - NOT_SUBMITTED for every hold event and NOT_TRACKED for
 * every event that holds nothing - so a caller can tell a confirmed zero
 * submission from a submission whose fate is unknown. The one exception is a
 * request this build cannot read (a null structure, a struct_size or count it
 * cannot hold, or a null array): there the receipts are left untouched, because
 * the caller's array cannot be trusted, and the snapshot is still coherent. A
 * batch that carries more hold events than RD_INPUT_MAX_HOLDS is such a
 * parameter refusal (INVALID_ARGUMENT), not a fault. One SendInput call carries
 * the batch, which keeps the OS's promise that a batch's events are not
 * interspersed with other input. The per-event receipts, not the inserted count,
 * say what happened to each event. A tracked event whose receipt does not become
 * terminal faults the guard and is reported as UNKNOWN. If the adapter cannot
 * complete the call after it published descriptors (the defensive boundary for
 * an internal fault, which no path here is expected to reach), it reports the
 * descriptors sealed, every hold event as UNKNOWN, submitted as the batch's
 * event count - never as zero, which would assert that SendInput was not
 * reached - and the guard closed for admission (RD_INPUT_GUARD_UNAVAILABLE).
 */
RD_INPUT_API rd_input_status RD_INPUT_CALL rd_input_send(
    const rd_input_send_request* request, rd_input_send_result* result);

/* Virtual key, scan code, extended-key fact and required shift state for one
 * UTF-16 character in the keyboard layout active for this thread. A character
 * the layout cannot produce returns RD_INPUT_UNSUPPORTED. shift_state is a
 * VkKeyScanExW shift state: 1 shift, 2 ctrl, 4 alt, 8 hankaku. */
RD_INPUT_API rd_input_status RD_INPUT_CALL rd_input_key_for_character(
    uint32_t character, uint32_t* virtual_key, uint32_t* scan_code,
    uint32_t* extended, uint32_t* shift_state);
/* Scan code and extended-key fact for one virtual key. */
RD_INPUT_API rd_input_status RD_INPUT_CALL rd_input_key_scan(
    uint32_t virtual_key, uint32_t* scan_code, uint32_t* extended);
/* Read-only canonical VK lookup for a pinned Windows Map wire scan code, using
 * MapVirtualKeyExW(MAPVK_VSC_TO_VK_EX) in the foreground layout. It never
 * injects, changes layout/desktop or supplies a handwritten key table. A held
 * down's scan and returned VK must be retained through repeat/up/cleanup;
 * querying a new layout must never re-key that episode. Pause is the pinned
 * sender's Legacy control-key exception, not a Map E1 sequence. */
RD_INPUT_API rd_input_status RD_INPUT_CALL rd_input_key_for_scancode(
    uint32_t scan_code, uint32_t* virtual_key);

#ifdef __cplusplus
}  /* extern "C" */

#include <type_traits>
static_assert(sizeof(rd_input_event) == 48, "rd_input_event ABI");
static_assert(std::is_standard_layout<rd_input_event>::value,
              "rd_input_event layout");
static_assert(offsetof(rd_input_event, virtual_key) == 20,
              "rd_input_event ABI");
static_assert(offsetof(rd_input_event, x) == 32, "rd_input_event ABI");
static_assert(offsetof(rd_input_event, code_unit) == 44, "rd_input_event ABI");
static_assert(alignof(rd_input_event) == 4, "rd_input_event alignment");

static_assert(sizeof(rd_input_guard_snapshot) == 24,
              "rd_input_guard_snapshot ABI");
static_assert(alignof(rd_input_guard_snapshot) == 4,
              "rd_input_guard_snapshot alignment");
static_assert(sizeof(rd_input_send_request) == 56,
              "rd_input_send_request ABI");
static_assert(offsetof(rd_input_send_request, lease) == 8,
              "rd_input_send_request ABI");
static_assert(offsetof(rd_input_send_request, events) == 24,
              "rd_input_send_request ABI");
static_assert(offsetof(rd_input_send_request, episodes) == 40,
              "rd_input_send_request ABI");
static_assert(offsetof(rd_input_send_request, receipts) == 48,
              "rd_input_send_request ABI");
static_assert(alignof(rd_input_send_request) == 8,
              "rd_input_send_request alignment");
static_assert(sizeof(rd_input_send_result) == 24, "rd_input_send_result ABI");
static_assert(offsetof(rd_input_send_result, epoch) == 12,
              "rd_input_send_result ABI");
static_assert(alignof(rd_input_send_result) == 4,
              "rd_input_send_result alignment");
#endif

#endif  /* RD_WINDOWS_INPUT_H_ */
