import native from 'librd_engine_native_har.so';

export function nativeVersion(): string {
  return native.nativeVersion();
}

export function harSurfaceManifest(): string {
  return native.harSurfaceManifest();
}

export function queryDecoderCapabilities(): Promise<string> {
  return native.queryDecoderCapabilities();
}

/**
 * Same async hardware metadata query as queryDecoderCapabilities.
 * JSON: {ok,evidence,source,error,h264_decoder,hevc_decoder,not_measured}.
 * evidence is "advertised_metadata"; each decoder/field retains its own ok/error.
 * No capabilities[]/software/recommended list, measured throughput or HDR result.
 */
export function runtimeGetDecoderCapabilities(): Promise<string> {
  return native.runtimeGetDecoderCapabilities();
}

export function appSetLifecycle(privacyAccepted: boolean, foreground: boolean): Promise<string> {
  return native.appSetLifecycle(privacyAccepted, foreground);
}

export function appInit(filesDir: string): Promise<string> {
  return native.appInit(filesDir);
}

export function validateServerProfile(profileJson: string): string {
  return native.validateServerProfile(profileJson);
}

/**
 * Binds the one official account owner to the server profile this app itself saved
 * and approved. An empty string binds the local authority (the saved profile, or the
 * built-in official default at revision 0 when nothing is saved); a supplied profile
 * is only compared with the saved one and is never trusted on its own. Switching to a
 * different account scope logs out; the same scope never does.
 * JSON: {ok:true,mode,profileRevision:number,sessionRetained} or
 * {ok:false,code,error}.
 */
export function accountBindServer(approvedProfileJson: string): Promise<string> {
  return native.accountBindServer(approvedProfileJson);
}

/**
 * Committed account state; no credential is part of it.
 * JSON: {ok:true,receipt,loggedIn,serverBinding:{mode,profileRevision},user?:
 * {name,displayName,avatar?,status?}}. serverBinding.profileRevision is numeric. Unbound/unsupported is an error,
 * not an empty account. receipt is the opaque token every
 * later account and cloud call names; it goes stale after any account change.
 */
export function accountSnapshot(): Promise<string> {
  return native.accountSnapshot();
}

/** JSON: {ok:true,providers:[{id,label}]}. Ids are the values accountOidcStart accepts. */
export function accountProviders(): Promise<string> {
  return native.accountProviders();
}

/** Starts (or replaces) the OIDC sign-in. JSON: {ok:true,attemptReceipt,state:"pending"}. */
export function accountOidcStart(receipt: string, providerId: string, rememberMe: boolean): Promise<string> {
  return native.accountOidcStart(receipt, providerId, rememberMe);
}

/**
 * Polls one attempt. JSON: {ok:true,state,url?,message?}; state is pending, url-ready,
 * complete, failed, cancelled or needs-business. url is present only for url-ready and
 * is an http(s) provider URL to open in the system browser. After complete, read
 * accountSnapshot. The authorization code never reaches ArkTS.
 */
export function accountOidcResult(attemptReceipt: string): Promise<string> {
  return native.accountOidcResult(attemptReceipt);
}

/** JSON: {ok,cancelled,attemptReceipt}; never logs out a committed account. */
export function accountOidcCancel(attemptReceipt: string): Promise<string> {
  return native.accountOidcCancel(attemptReceipt);
}

/** Revokes the committed credential and caches. JSON: {ok:true}. Re-read accountSnapshot. */
export function accountLogout(receipt: string): Promise<string> {
  return native.accountLogout(receipt);
}

/** JSON: {ok:true,books:[{id,name,kind,writable,capabilities?}]}. */
export function cloudAddressBookList(receipt: string): Promise<string> {
  return native.cloudAddressBookList(receipt);
}

/** JSON: {ok:true,book:{id,name,kind,writable},peers:[{id,alias,tags,hostname?,platform?}],tags,revision?}. */
export function cloudAddressBookLoad(receipt: string, bookId: string): Promise<string> {
  return native.cloudAddressBookLoad(receipt, bookId);
}

/**
 * mutationJson: {action:"upsertPeer",peer:{id,alias?,tags?}} | {action:"deletePeer",id} |
 * {action:"upsertTag",name,newName?} | {action:"deleteTag",name}. The server has no CAS.
 * JSON: {ok:true,sent:boolean} or {ok:false,code,error,sent}; sent:true means the request
 * may already have reached the server.
 */
export function cloudAddressBookMutate(receipt: string, bookId: string, mutationJson: string): Promise<string> {
  return native.cloudAddressBookMutate(receipt, bookId, mutationJson);
}

export function lanScanStart(ownerGeneration: string): Promise<string> {
  return native.lanScanStart(ownerGeneration);
}

export function lanPeersQuery(ownerGeneration: string, expectedScanId: string): Promise<string> {
  return native.lanPeersQuery(ownerGeneration, expectedScanId);
}

export function lanScanStop(ownerGeneration: string, scanId: string): Promise<string> {
  return native.lanScanStop(ownerGeneration, scanId);
}

export function lanPeerRemove(ownerGeneration: string, expectedScanId: string, claimedId: string): Promise<string> {
  return native.lanPeerRemove(ownerGeneration, expectedScanId, claimedId);
}


/**
 * optionsJson may carry isFileTransfer and transferRoot (an absolute authorized
 * local directory fixed at add). File sessions use no decoder or Surface.
 * approvedServerProfile and rustdeskIdOnly:true keep even
 * IP-shaped LAN IDs on the approved RustDesk route. Existing ids are never
 * overwritten. At 256 registered/live/quarantined/unacknowledged records, new
 * registration is refused; consume and ACK confirmed receipts to free capacity.
 * add/start/poll/close carry session:{sessionId,coreSessionId,lifecycleEpoch,
 * kind,target,phase}. lifecycleEpoch is a nonzero native decimal string, not a
 * UI counter; a reused sessionId receives a new epoch.
 */
export function sessionAdd(sessionId: string, peerTarget: string, optionsJson: string): string {
  return native.sessionAdd(sessionId, peerTarget, optionsJson);
}

/**
 * Registers the C side of a B to C share from the invite code, without dialling.
 * The code is the only thing that crosses from B: it names the nearby transport,
 * the ephemeral host id C has to prove and a single-use token. No address is
 * carried or recorded; the parsed endpoint field must be the literal "nearby".
 * Native parses it, keeps the token in the record's scrubbed password field and
 * fixes the session to a read-only desktop view. Nothing about A, B's long-term
 * identity or any server route is recorded.
 * The nearby byte transport is created here rather than at sessionStart, so bytes
 * that arrive before the login completes already have this record's bounded queue
 * to land in; the framed stream waits in the record until sessionStart consumes it
 * exactly once.
 * optionsJson is "" | "{}" | {"customFps":1..=240,"isViewOnly":true}; every other
 * option (role, route, transfer, connToken, password, profile) is refused.
 * A code that is expired, not `RKS1.` base64url JSON, names anything but the nearby
 * transport, carries a non-32-byte pin or an unknown field is refused before a
 * record exists. JSON adds shared:true, view_only:true and expiresAtMs; `target`
 * is an opaque `share:<epoch>` label, never B's address.
 * sessionStart dials only that pinned peer over this transport; the invite's
 * deadline is enforced again there.
 */
export function sessionAddShared(sessionId: string, inviteCode: string, optionsJson: string): string {
  return native.sessionAddShared(sessionId, inviteCode, optionsJson);
}

/**
 * Takes the next already-framed chunk this shared view's transport queued.
 * Same contract as sharePollSendData: hand `chunk.buffer` to sendData unchanged,
 * and treat only a non-empty array as a chunk to send. An empty array also covers
 * a stale lifecycleEpoch, a terminal record and a closed transport.
 */
export function sessionPollSendData(sessionId: string, lifecycleEpoch: string): Uint8Array {
  return native.sessionPollSendData(sessionId, lifecycleEpoch);
}

/**
 * Hands one chunk received from the nearby transport to this shared view.
 * JSON {ok:true,action:"session_receive_data",sessionId,accepted:true,bytes} or
 * {ok:false,code,...} with code unknown_session|stale_lifecycle_epoch|
 * session_terminal|not_a_shared_view|empty_data|transport_rejected.
 * accepted means the chunk entered the core's bounded queue, not that the peer
 * read it.
 */
export function sessionPushReceiveData(sessionId: string, lifecycleEpoch: string,
  data: Uint8Array): string {
  return native.sessionPushReceiveData(sessionId, lifecycleEpoch, data);
}

/**
 * Reports what the platform's sendData call did for this shared view.
 * ok:true is only "the platform call completed". ok:false answers
 * {ok:false,code:"send_failed",label,platformCode,transportClosed:true} and closes
 * this record's transport. label is a fixed name (send_data_rejected|
 * send_data_timeout|transport_closed|transport_error|unknown) and code a numeric
 * platform code: never pass platform message text.
 */
export function sessionReportSendResult(sessionId: string, lifecycleEpoch: string, ok: boolean,
  label: string, code: number = 0): string {
  return native.sessionReportSendResult(sessionId, lifecycleEpoch, ok, label, code);
}

/**
 * Observed nearby-transport state of this shared view.
 * JSON {ok:true,sessionId,lifecycleEpoch,transportClosed} |
 * {ok:false,code:unknown_session|stale_lifecycle_epoch|session_terminal|not_a_shared_view}.
 * A record registered but not yet started reports transportClosed:false: the byte
 * queues exist from sessionAddShared on. transportClosed is the only field to act
 * on; it is not a queue depth or a delivery acknowledgement.
 */
export function sessionGetTransportStatus(sessionId: string, lifecycleEpoch: string): string {
  return native.sessionGetTransportStatus(sessionId, lifecycleEpoch);
}

/**
 * Publishes one selected peer display without changing B's current display.
 * optionsJson: {sessionId, display, ttlSeconds?, acceptUnverifiedSource?}.
 * The native owner captures the source identity/lifecycle. An authenticated
 * plaintext source is allowed; unverified-source consent does not grant input.
 * The B-to-C hop is the nearby byte transport, not a LAN listener: the answer's
 * `endpoint` is always the literal "nearby" and no address is ever published.
 * Frames travel through sharePollSendData/sharePushReceiveData under the returned
 * shareEpoch; ArkTS sends each chunk with abilityConnectionManager sendData.
 */
export function shareStart(optionsJson: string): Promise<string> {
  return native.shareStart(optionsJson);
}

/**
 * Stops the named share: the nearby transport is closed first, so no further chunk
 * can be taken, and the core run is revoked. reclaimed is the run's own answer;
 * false means poll shareGetStatus for confirmed reclamation.
 */
export function shareStop(shareEpoch: string): Promise<string> {
  return native.shareStop(shareEpoch);
}

/**
 * Observed share state and counters, never the invite token, the pin or any
 * address. display.index names the selected A screen. encrypted describes B-to-C;
 * sourceEncrypted describes A-to-B. peerVerified reports the source's actual
 * identity-verification state. transportClosed reports the nearby transport.
 */
export function shareGetStatus(): string {
  return native.shareGetStatus();
}

/** The invite code, only while a share is listening and its code is unconsumed. */
export function shareGetInvite(shareEpoch: string): string {
  return native.shareGetInvite(shareEpoch);
}

/**
 * Takes the next already-framed chunk the core queued for the collaborator.
 * The bytes cross unchanged (the core's own sequence/length framing is in them):
 * hand `chunk.buffer` to abilityConnectionManager sendData as ArrayBuffer and do
 * not rebuild, join, re-frame or text-encode them.
 * An empty array means nothing is queued right now, the epoch is stale, or the
 * transport closed. Only a non-empty array is a chunk to send; the empty one is
 * not a frame boundary or an end marker.
 */
export function sharePollSendData(shareEpoch: string): Uint8Array {
  return native.sharePollSendData(shareEpoch);
}

/**
 * Hands one chunk received from the nearby transport to the core.
 * JSON {ok:true,action:"share_receive_data",shareEpoch,accepted:true,bytes} or
 * {ok:false,code,...} with code invalid_share_epoch|stale_share_epoch|
 * share_closed|empty_data|transport_rejected. accepted means the chunk entered the
 * core's bounded queue: it is not an acknowledgement that the peer read it.
 */
export function sharePushReceiveData(shareEpoch: string, data: Uint8Array): string {
  return native.sharePushReceiveData(shareEpoch, data);
}

/**
 * Activates the named share's nearby run once the platform link is really up.
 *
 * shareStart arms the run before a collaborator exists, and the core's bounded
 * wait for the login must not start until DMS has connected and ArkTS is about to
 * pump bytes. Call this after the collaborator connection resolves and before the
 * first sharePollSendData/sharePushReceiveData.
 * JSON {ok:true,action:"share_connect_transport",shareEpoch,connected:true} or
 * {ok:false,code:"app_not_admitted"|"stale_share_epoch"|"share_closed"|
 * "connect_failed"}. A refusal activates nothing: the run and the invite stay
 * valid, and shareGetInvite keeps working until a connection is admitted.
 */
export function shareConnectTransport(shareEpoch: string): string {
  return native.shareConnectTransport(shareEpoch);
}

/**
 * Observed nearby-transport state for this share epoch.
 * JSON {ok:true,shareEpoch,state,reason,transportClosed} |
 * {ok:false,code:invalid_share_epoch|stale_share_epoch}. transportClosed is the
 * only field to act on: a stale epoch is a refusal, never a fabricated "closed",
 * and this carries no address, token or pin.
 */
export function shareGetTransportStatus(shareEpoch: string): string {
  return native.shareGetTransportStatus(shareEpoch);
}

/**
 * Reports what the platform's sendData call did with one chunk.
 * ok:true means only that the platform call completed
 * (JSON {ok:true,reported:true,meaning:"platform_call_completed"}) — not that the
 * collaborator read or displayed anything.
 * ok:false closes the share: actual send rejection returns code:"send_failed"
 * with platformCode/sendFailures; peer_disconnected or user_stop reports the
 * terminal reason without counting a failed send. Already-terminated shares
 * return code:"share_closed" without replacing the original reason.
 * label must be send_data_rejected|send_data_timeout|transport_closed|
 * transport_error|peer_disconnected|user_stop|unknown; code is numeric. Never pass the
 * platform's message text, which can quote the frame or the session.
 */
export function shareReportSendResult(shareEpoch: string, ok: boolean, label: string,
  code: number = 0): string {
  return native.shareReportSendResult(shareEpoch, ok, label, code);
}

export function sessionStart(sessionId: string): string {
  return native.sessionStart(sessionId);
}

/** Same-wire password answer; queued is not authorized. Before start, only records the initial password. */
export function sessionLogin(sessionId: string, loginJson: string): string {
  return native.sessionLogin(sessionId, loginJson);
}

/** Same-session 2FA answer; ok/queued is not authentication success. true trust is explicitly refused. */
export function sessionSend2fa(sessionId: string, code: string, trustThisDevice: boolean): string {
  return native.sessionSend2fa(sessionId, code, trustThisDevice);
}

/** Explicit reusable password-equivalent credential; null before authentication or after close. */
export function sessionGetConnToken(sessionId: string): string | null {
  return native.sessionGetConnToken(sessionId);
}

/** Non-secret query; does not serialize or return reconnect material. */
export function sessionHasConnToken(sessionId: string): boolean {
  return native.sessionHasConnToken(sessionId);
}

/**
 * Resolves only after native teardown finishes, not when the request is accepted.
 * JSON always carries released and settle ("settled" | "unconfirmed" |
 * "neverstarted"); only released:true permits destroying the Surface.
 * surfaces names actual lease bindings, retaining their Surface ids after release.
 * Remote/auth errors and input-release counters survive even a confirmed release.
 * Abandoning this Promise neither releases ownership nor acknowledges the record.
 */
export function sessionClose(sessionId: string): Promise<string> {
  return native.sessionClose(sessionId);
}

/** Removes only this epoch after a complete close/poll receipt and confirmed reclamation. */
export function sessionAcknowledgeClose(sessionId: string, lifecycleEpoch: string): string {
  return native.sessionAcknowledgeClose(sessionId, lifecycleEpoch);
}

/**
 * Binds this epoch's one Surface from the componentId `xcomponentAttach` returned
 * on this UI environment; a Surface id or any other string is refused and never
 * promoted into a lease. Empty componentId is a give-back request; a live/closing
 * viewer returns held:true/released:false. Only no viewer ever started or
 * confirmed reclamation permits released:true. Binding/give-back never counts as
 * a terminal ACK.
 */
export function sessionBindSurface(sessionId: string, display: number, componentId: string,
  lifecycleEpoch: string): string {
  return native.sessionBindSurface(sessionId, display, componentId, lifecycleEpoch);
}

/**
 * Persistent login_failure: null | "empty_password" | "wrong_password" | "refused".
 * Optional peer_close_reason: "manual_request" | null, a typed confirmed-terminal
 * fact only; never raw peer text or a new UI action. Registered/no-viewer polls use null.
 * Confirmed terminal snapshots retain error, input-release counters and telemetry
 * until sessionAcknowledgeClose(sessionId, lifecycleEpoch) ACKs consumption.
 * Events remain one-shot; released/settle/surfaces and terminal facts persist.
 */
export function sessionPollEvents(sessionId: string, limit: number): string {
  return native.sessionPollEvents(sessionId, limit);
}

export function sessionRefresh(sessionId: string, display: number): string {
  return native.sessionRefresh(sessionId, display);
}

/**
 * Applies a local expected-image geometry gate, not a remote resolution request.
 * JSON effect=local_applied; native_render_ready follows only a new matching
 * native submission. Its presentation_generation is an opaque decimal string.
 */
export function sessionSetSize(sessionId: string, display: number, width: number, height: number): string {
  return native.sessionSetSize(sessionId, display, width, height);
}

/** Decode/receive continue. Already admitted native submissions may still finish. */
export function sessionSetVideoPaused(sessionId: string, paused: boolean): string {
  return native.sessionSetVideoPaused(sessionId, paused);
}

/** Rearms native_render_ready without treating historical frame counters as a new image. */
export function sessionOnWaitingForImageDialogShow(sessionId: string): string {
  return native.sessionOnWaitingForImageDialogShow(sessionId);
}

/**
 * JSON cumulative counters, not physical presentation FPS. pipelineTimings v1
 * exposes recordAdmission, decoderAdmission, inputWait, inputDispatch, pushApi
 * and renderApi as null (unmeasured) or {samples,totalNs,peakNs,over8Ms}.
 * peakNs is a dial-lifetime maximum; over8Ms counts samples strictly above 8 ms.
 * Legacy queueCalls/queueNs/busyFrames are null, not measured zero waits.
 * readerProgress is null until this session's one reader publishes, otherwise
 * {phase,ageMs}: phase is wire_wait, wire_decode, video_dispatch,
 * cursor_dispatch, transfer_dispatch, cliprdr_dispatch, control_dispatch,
 * other_dispatch or stopped, and ageMs is how long it has been in that phase.
 */
export function sessionGetFrameRateSnapshot(sessionId: string, display: number): string {
  return native.sessionGetFrameRateSnapshot(sessionId, display);
}

export function sessionSendMouse(sessionId: string, mouseJson: string, inputGeneration: number): string {
  return native.sessionSendMouse(sessionId, mouseJson, inputGeneration);
}

/** VNC/RDP X11 keysym transition; keysym is an integer in 1..=0x1FFFFFFF. ok means queued, not applied. */
export function sessionSendKeysym(sessionId: string, keysym: number, down: boolean, inputGeneration: number): string {
  return native.sessionSendKeysym(sessionId, keysym, down, inputGeneration);
}

export function sessionInputKey(sessionId: string, keyJson: string, inputGeneration: number): string {
  return native.sessionInputKey(sessionId, keyJson, inputGeneration);
}

export function sessionInputString(sessionId: string, value: string, inputGeneration: number): string {
  return native.sessionInputString(sessionId, value, inputGeneration);
}

/**
 * Sends one clipboard copy through the session's one writer.
 * JSON: {ok,queued,applied,action,clipboard_revision,formats} or
 * {ok:false,queued:false,applied:false,action,reason,error}. queued:true means the
 * payload entered the writer's queue under clipboard_revision; it does not mean the
 * peer applied it, because the protocol has no clipboard acknowledgement, so applied
 * is always false. Empty content is the protocol's clear. A refusal (not_allowed,
 * not_deliverable, too_large, corrupt, closed, backpressure, unknown_session) never
 * reports ok:true.
 */
export function sessionSendClipboard(sessionId: string, content: string): string {
  return native.sessionSendClipboard(sessionId, content);
}

/**
 * Sends an encoded PNG as this session's image clipboard. The size bound is checked
 * against the typed array's own length before any copy; the receipt is
 * sessionSendClipboard's.
 */
export function sessionSendClipboardImage(sessionId: string, image: Uint8Array): string {
  return native.sessionSendClipboardImage(sessionId, image);
}

/**
 * Hands out the next peer clipboard update and reserves its image for
 * sessionTakeClipboardImage.
 * JSON: {ok,queued:false,applied:false,action,revision,text,html,image,formats}.
 * No pending update: {ok:false,reason:"no_pending_update"}. Missing text/html/image
 * formats are omitted, never null. Text "" is a real clear. Image is
 * {format:"rgba"|"png"|"svg",width,height,byteLength}, with width/height 0 for PNG/SVG.
 */
export function sessionTakeClipboard(sessionId: string): string {
  return native.sessionTakeClipboard(sessionId);
}

/**
 * Returns exactly the bytes the descriptor from sessionTakeClipboard described. An
 * empty array means no image was described, or the permission that described it was
 * withdrawn before this call: compare the length with byteLength instead of applying
 * an image the engine did not hand out now.
 */
export function sessionTakeClipboardImage(sessionId: string): Uint8Array {
  return native.sessionTakeClipboardImage(sessionId);
}

/** Queues real staged paths; queued is not a peer-applied acknowledgement. */
export function sessionSendClipboardFiles(sessionId: string, pathsJson: string): string {
  return native.sessionSendClipboardFiles(sessionId, pathsJson);
}

/** Queues the session's private incoming root; filesystem errors arrive as events. */
export function sessionSetClipboardFileRoot(sessionId: string, root: string): string {
  return native.sessionSetClipboardFileRoot(sessionId, root);
}

/** Non-consuming JSON {ok,allowed,revision,pending}; no clipboard paths. */
export function sessionGetClipboardFileState(sessionId: string): string {
  return native.sessionGetClipboardFileState(sessionId);
}

/** Takes at most 8 facts. Recheck Files.revision against the live state before applying. */
export function sessionTakeClipboardFileEvents(sessionId: string): string {
  return native.sessionTakeClipboardFileEvents(sessionId);
}

export function sessionSetCustomFps(sessionId: string, fps: number): string {
  return native.sessionSetCustomFps(sessionId, fps);
}

/**
 * Advances input_generation without changing input or clipboard policy.
 * Queued old-generation input is dropped; the existing writer releases its held
 * keys/buttons. release_pending/release counters are not a remote release ACK.
 * No running viewer is an error, never a fabricated generation.
 */
export function sessionReleaseInput(sessionId: string): string {
  return native.sessionReleaseInput(sessionId);
}

export function sessionSetViewOnly(sessionId: string, enabled: boolean): string {
  return native.sessionSetViewOnly(sessionId, enabled);
}

export function sessionSetUnverifiedInputAccepted(sessionId: string, accepted: boolean): string {
  return native.sessionSetUnverifiedInputAccepted(sessionId, accepted);
}

export function sessionSetCommon(sessionId: string, key: string, value: string): string {
  return native.sessionSetCommon(sessionId, key, value);
}

/**
 * Cancels one live job owned by this session. No actId (including 0) closes a
 * viewer, releases a Surface or ACKs a receipt. ok/queued is local admission.
 */
export function sessionCancelJob(sessionId: string, actId: number): string {
  return native.sessionCancelJob(sessionId, actId);
}

export function transferNextJobId(): number {
  return native.transferNextJobId();
}

export function sessionReadRemoteDir(sessionId: string, path: string, includeHidden: boolean): string {
  return native.sessionReadRemoteDir(sessionId, path, includeHidden);
}

export function sessionSendFiles(sessionId: string, actId: number, path: string, to: string,
  fileNum: number, includeHidden: boolean, isRemote: boolean, isDir: boolean): string {
  return native.sessionSendFiles(sessionId, actId, path, to, fileNum, includeHidden, isRemote, isDir);
}

export function sessionSetConfirmOverrideFile(sessionId: string, actId: number, fileNum: number,
  needOverride: boolean, remember: boolean, isUpload: boolean): string {
  return native.sessionSetConfirmOverrideFile(sessionId, actId, fileNum, needOverride, remember, isUpload);
}

/**
 * Reads the native-committed server profile and an optional raw editor draft.
 * `draft` contains public route text and Asset-backed Key metadata, never Key text.
 * Resolves with
 * `config: null` when none was saved; an approval is not a reachability or
 * account claim, and a failed read is not an empty profile.
 */
export function runtimeGetServerConfig(): Promise<string> {
  return native.runtimeGetServerConfig();
}

/** Manual edit: {mode,idServer,relayServer,apiServer,keyUpdate:{action:'keep'|'set'|'clear',value?,draftRevision?}}.
 * `draftOnly:true` protects raw/invalid editor text first, without approving it.
 * Otherwise commits a valid effective route with manual-edit provenance.
 * Shared Key text lives only in Asset; keep+draftRevision references the current native draft.
 * A commit is not reachability, peer identity, account login or device acceptance. */
export function runtimeSetServerConfig(profileJson: string): Promise<string> {
  return native.runtimeSetServerConfig(profileJson);
}

/** One bounded TCP connect per endpoint; a listen socket is not proof of a RustDesk server. */
export function runtimeTestServerConfig(profileJson: string): Promise<string> {
  return native.runtimeTestServerConfig(profileJson);
}

/** Engine-owned recent targets; `exists:false` means no data, never a successful empty list. */
export function runtimeListRecentPeers(): Promise<string> {
  return native.runtimeListRecentPeers();
}

/** Engine-owned favourite targets; the same exists/ok distinction applies. */
export function runtimeListFavorites(): Promise<string> {
  return native.runtimeListFavorites();
}

export function runtimeSetFavorite(peerId: string, favorite: boolean): Promise<string> {
  return native.runtimeSetFavorite(peerId, favorite);
}

/** The client records a target only after it really observed a session. */
export function runtimeRecordRecentPeer(peerJson: string): Promise<string> {
  return native.runtimeRecordRecentPeer(peerJson);
}

export function runtimeRemoveRecentPeer(peerId: string): Promise<string> {
  return native.runtimeRemoveRecentPeer(peerId);
}

/**
 * Online state from a strict hbbs OnlineRequest/OnlineResponse pair, against an
 * explicitly saved profile. Only a real answer decides online/offline: a LAN
 * scan hit, a saved address or a session in progress is never "online".
 */
export function peerQueryOnline(idsJson: string, approvedProfileJson: string): Promise<string> {
  return native.peerQueryOnline(idsJson, approvedProfileJson);
}

/** Cancels exactly the query generation this call names; it does not retire other work. */
export function peerPresenceCancel(queryGeneration: string): string {
  return native.peerPresenceCancel(queryGeneration);
}

/**
 * Adopts one live ArkUI node's SurfaceHolder on the UI environment thread: call it
 * from that thread, after the node is attached. nodeId is only a label.
 * JSON: {ok,componentId,nodeId,nodeUniqueId,environmentGeneration,surfaceId,
 * bindingToken,ready,held,released,destroyed,callbacksRegistered,
 * frameCallbackRegistered,frameCallbacks,notificationResult,error,api,result}.
 * componentId is opaque, never reused, and the only value sessionBindSurface
 * accepts. ok:false is a real refusal: when cleanup could not be confirmed the same
 * componentId is returned with cleanup, so the caller detaches it instead of
 * dropping it. onSurfaceEvent receives one coalesced JSON lifecycle notice.
 */
export function xcomponentAttach(nodeId: string, frameNode: Object,
  onSurfaceEvent: (event: string) => void): string {
  return native.xcomponentAttach(nodeId, frameNode, onSurfaceEvent);
}

/**
 * Releases this bridge's claim on one holder. held:true means a borrowed loan or an
 * active native callback still owns resources: the holder, its callback and its
 * window stay retained and only a later detach may complete. released:true is the
 * only successful teardown; no answer claims a release that did not happen.
 */
export function xcomponentDetach(componentId: string): string {
  return native.xcomponentDetach(componentId);
}

/**
 * Declares the rate the attached node should be drawn at. ok separates the
 * frame-rate call (result) from the on-frame callback registration
 * (registerResult); frameCallbacks counts native signal callbacks, not decoded
 * frames or measured presentation FPS.
 */
export function xcomponentSetFrameRateRangeNative(componentId: string, expected: number, min: number,
  max: number): string {
  return native.xcomponentSetFrameRateRangeNative(componentId, expected, min, max);
}

export function sessionSetImageQuality(sessionId: string, quality: string): string {
  return native.sessionSetImageQuality(sessionId, quality);
}

export function sessionSetCustomImageQuality(sessionId: string, quality: number): string {
  return native.sessionSetCustomImageQuality(sessionId, quality);
}

export function sessionSetCodecPreference(sessionId: string, codec: string): string {
  return native.sessionSetCodecPreference(sessionId, codec);
}

export function sessionSetShowRemoteCursor(sessionId: string, enabled: boolean): string {
  return native.sessionSetShowRemoteCursor(sessionId, enabled);
}

export function sessionSwitchDisplay(sessionId: string, displaysJson: string): string {
  return native.sessionSwitchDisplay(sessionId, displaysJson);
}

export function sessionChangeResolution(sessionId: string, display: number, width: number, height: number): string {
  return native.sessionChangeResolution(sessionId, display, width, height);
}

export function sessionGetImageQuality(sessionId: string): string {
  return native.sessionGetImageQuality(sessionId);
}

export function sessionGetToggleOption(sessionId: string, option: string): boolean {
  return native.sessionGetToggleOption(sessionId, option);
}

export function sessionToggleOption(sessionId: string, option: string): string {
  return native.sessionToggleOption(sessionId, option);
}

export function sessionGetRemoteAudioState(sessionId: string): string {
  return native.sessionGetRemoteAudioState(sessionId);
}

export function sessionGetEnableTrustedDevices(sessionId: string): boolean {
  return native.sessionGetEnableTrustedDevices(sessionId);
}

export function controlledServerStart(optionsJson: string): Promise<string> {
  return native.controlledServerStart(optionsJson);
}

export function controlledServerStop(runEpoch: string): Promise<string> {
  return native.controlledServerStop(runEpoch);
}

export function controlledServerGetStatus(): string {
  return native.controlledServerGetStatus();
}

/**
 * Authorization JSON carries requestId: an opaque decimal string, empty without
 * an owner; it is neither runEpoch nor input_generation. Starting with
 * enableInput:true also requires that inputAuthorizationRequestId.
 */
export function controlledInputAuthorizationRequest(): string {
  return native.controlledInputAuthorizationRequest();
}

export function controlledInputAuthorizationStatus(): string {
  return native.controlledInputAuthorizationStatus();
}

/** Cancels exactly requestId, including before a host run exists. Never pass runEpoch or input_generation. */
export function controlledInputAuthorizationCancel(requestId: string): string {
  return native.controlledInputAuthorizationCancel(requestId);
}

export function controlledScreenCaptureGetStatus(): string {
  return native.controlledScreenCaptureGetStatus();
}

export function controlledScreenCaptureStop(runEpoch: string): Promise<string> {
  return native.controlledScreenCaptureStop(runEpoch);
}

export function controlledScreenConfigure(configJson: string): string {
  return native.controlledScreenConfigure(configJson);
}

export function controlledIncomingPoll(limit: number): string {
  return native.controlledIncomingPoll(limit);
}

export function controlledIncomingResolve(requestId: string, allow: boolean): string {
  return native.controlledIncomingResolve(requestId, allow);
}

export function controlledPasswordGet(): Promise<string> {
  return native.controlledPasswordGet();
}

export function controlledPasswordRefresh(): Promise<string> {
  return native.controlledPasswordRefresh();
}

export function controlledPasswordSetPermanent(password: string): Promise<string> {
  return native.controlledPasswordSetPermanent(password);
}

export function controlledPasswordSetVerificationMethod(method: string): Promise<string> {
  return native.controlledPasswordSetVerificationMethod(method);
}

export function controlledSettingSet(key: string, value: string): Promise<string> {
  return native.controlledSettingSet(key, value);
}

export function controlledTwoFactorBegin(): Promise<string> {
  return native.controlledTwoFactorBegin();
}

export function controlledTwoFactorVerify(code: string): Promise<string> {
  return native.controlledTwoFactorVerify(code);
}

export function controlledTwoFactorDisable(): Promise<string> {
  return native.controlledTwoFactorDisable();
}

export function controlledTwoFactorGet(): Promise<string> {
  return native.controlledTwoFactorGet();
}

export function controlledTwoFactorRemoveTrustedDevices(hwidsJson: string): Promise<string> {
  return native.controlledTwoFactorRemoveTrustedDevices(hwidsJson);
}

export function controlledTwoFactorClearTrustedDevices(): Promise<string> {
  return native.controlledTwoFactorClearTrustedDevices();
}
