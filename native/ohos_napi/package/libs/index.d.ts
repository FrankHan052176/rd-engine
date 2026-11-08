/* Maintained alongside package/index.ets and the owning NAPI exports. */
/* eslint-disable */

export declare function nativeVersion(): string

export declare function harSurfaceManifest(): string

export declare function queryDecoderCapabilities(): Promise<string>

/**
 * Same async hardware metadata query as queryDecoderCapabilities.
 * JSON: {ok,evidence,source,error,h264_decoder,hevc_decoder,not_measured}.
 * evidence is "advertised_metadata"; each decoder/field retains its own ok/error.
 * No capabilities[]/software/recommended list, measured throughput or HDR result.
 */
export declare function runtimeGetDecoderCapabilities(): Promise<string>

export declare function appSetLifecycle(privacyAccepted: boolean, foreground: boolean): Promise<string>

export declare function appInit(filesDir: string): Promise<string>

export declare function validateServerProfile(profileJson: string): string

/** See accountBindServer in index.ets. JSON: {ok,mode,profileRevision:number,sessionRetained} | {ok:false,code,error}. */
export declare function accountBindServer(approvedProfileJson: string): Promise<string>

/** JSON: {ok,receipt,loggedIn,serverBinding:{mode,profileRevision},user?:{name,displayName,avatar?,status?}}; no credential. */
export declare function accountSnapshot(): Promise<string>

/** JSON: {ok,providers:[{id,label}]}. */
export declare function accountProviders(): Promise<string>

/** JSON: {ok,attemptReceipt,state:"pending"}. */
export declare function accountOidcStart(receipt: string, providerId: string, rememberMe: boolean): Promise<string>

/** JSON: {ok,state,url?,message?}; state is pending|url-ready|complete|failed|cancelled|needs-business. */
export declare function accountOidcResult(attemptReceipt: string): Promise<string>

/** JSON: {ok,cancelled:boolean,attemptReceipt}; retires exactly this attempt. */
export declare function accountOidcCancel(attemptReceipt: string): Promise<string>

/** JSON: {ok}. */
export declare function accountLogout(receipt: string): Promise<string>

/** JSON: {ok,books:[{id,name,kind,writable,capabilities?}]}. */
export declare function cloudAddressBookList(receipt: string): Promise<string>

/** JSON: {ok,book:{id,name,kind,writable},peers:[{id,alias,tags,hostname?,platform?}],tags,revision?}. */
export declare function cloudAddressBookLoad(receipt: string, bookId: string): Promise<string>

/** mutationJson actions: upsertPeer|deletePeer|upsertTag|deleteTag. JSON: {ok,sent:boolean} | {ok:false,code,error,sent}. */
export declare function cloudAddressBookMutate(receipt: string, bookId: string, mutationJson: string): Promise<string>

export declare function lanScanStart(ownerGeneration: string): Promise<string>

export declare function lanPeersQuery(ownerGeneration: string, expectedScanId: string): Promise<string>

export declare function lanScanStop(ownerGeneration: string, scanId: string): Promise<string>

export declare function lanPeerRemove(ownerGeneration: string, expectedScanId: string, claimedId: string): Promise<string>


/**
 * isFileTransfer selects the real file role (no decoder/Surface); transferRoot
 * fixes its absolute authorized local directory at add.
 * approvedServerProfile and rustdeskIdOnly:true require
 * the approved RustDesk ID route. Existing ids are never overwritten; the registry
 * refuses registration at 256 records, including quarantine and unacknowledged terminals.
 * add/start/poll/close carry session:{sessionId,coreSessionId,lifecycleEpoch,
 * kind,target,phase}. lifecycleEpoch is a nonzero native decimal string, renewed
 * whenever a sessionId is registered again after ACK.
 */
export declare function sessionAdd(sessionId: string, peerTarget: string, optionsJson: string): string

/**
 * Registers the C side of a B to C share from the invite code, without dialling.
 * Native parses the `RKS1.` code, pins the one-time host id and Ed25519 key, keeps
 * the single-use token in the record's scrubbed password field and fixes the
 * session to a read-only desktop view. Nothing about A, B's long-term identity or
 * any server route is recorded, and no address is carried: the code's endpoint
 * field must be the literal "nearby".
 * The nearby byte transport is created here rather than at sessionStart, so bytes
 * arriving before the login completes already have this record's bounded queue;
 * the framed stream waits in the record until sessionStart consumes it once.
 * optionsJson is "" | "{}" | {customFps?:1..=240,isViewOnly?:true}; any other option
 * is refused, and so is an expired, malformed, non-nearby, unbounded or
 * unknown-field code. The answer adds shared:true, view_only:true and expiresAtMs;
 * `target` is an opaque `share:<epoch>` label rather than B's address.
 */
export declare function sessionAddShared(sessionId: string, inviteCode: string, optionsJson: string): string

/**
 * Next already-framed chunk this shared view's transport queued. Hand
 * `chunk.buffer` to abilityConnectionManager sendData unchanged; do not rebuild,
 * join, re-frame or text-encode it. Empty array covers nothing-queued-now, a stale
 * lifecycleEpoch, a terminal record and a closed transport.
 */
export declare function sessionPollSendData(sessionId: string, lifecycleEpoch: string): Uint8Array

/**
 * Hands one received chunk to this shared view.
 * JSON {ok:true,action:"session_receive_data",sessionId,accepted:true,bytes} or
 * {ok:false,code∈unknown_session|stale_lifecycle_epoch|session_terminal|
 * not_a_shared_view|empty_data|transport_rejected}. accepted means the chunk
 * entered the core's bounded queue, not that the peer read it.
 */
export declare function sessionPushReceiveData(sessionId: string, lifecycleEpoch: string, data: Uint8Array): string

/**
 * Records what the platform's sendData call did. ok:true is only
 * "platform_call_completed". ok:false answers {ok:false,code:"send_failed",label,
 * platformCode,transportClosed:true} and closes this record's transport.
 * label is a fixed name and code a numeric platform code; never pass platform text,
 * which can quote the frame or the transport session. package/index.ets defaults
 * code to 0 for a caller that has none.
 */
export declare function sessionReportSendResult(sessionId: string, lifecycleEpoch: string, ok: boolean, label: string, code: number): string

/**
 * Observed nearby-transport state of this shared view.
 * JSON {ok:true,sessionId,lifecycleEpoch,transportClosed} |
 * {ok:false,code∈unknown_session|stale_lifecycle_epoch|session_terminal|
 * not_a_shared_view}. A registered-but-not-started record reports
 * transportClosed:false, because sessionAddShared created the byte queues.
 */
export declare function sessionGetTransportStatus(sessionId: string, lifecycleEpoch: string): string

/**
 * Publishes one selected peer display without changing B's current display.
 * optionsJson: {sessionId, display, ttlSeconds?, acceptUnverifiedSource?}.
 * The native owner captures the source identity/lifecycle. An authenticated
 * plaintext source is allowed; unverified-source consent does not grant input.
 * The B-to-C hop is the nearby byte transport, not a LAN listener: `endpoint` is
 * always the literal "nearby" and no address is published. Frames travel through
 * sharePollSendData/sharePushReceiveData under the returned shareEpoch.
 */
export declare function shareStart(optionsJson: string): Promise<string>

/**
 * Closes the nearby transport first, then revokes the core run. reclaimed is the
 * run's own answer; false means poll shareGetStatus for confirmed reclamation.
 */
export declare function shareStop(shareEpoch: string): Promise<string>

/**
 * Observed share state and counters, never the invite token, the pin or any
 * address. display.index names the selected A screen. encrypted describes B-to-C;
 * sourceEncrypted describes A-to-B. peerVerified reports the source's actual
 * identity-verification state. transportClosed reports the nearby transport.
 */
export declare function shareGetStatus(): string

/** The invite code, only while a share is listening and its code is unconsumed. */
export declare function shareGetInvite(shareEpoch: string): string

/**
 * Next already-framed chunk the core queued for the collaborator. Empty array
 * means nothing queued now, a stale epoch, or a closed transport; only a non-empty
 * array is a chunk to send.
 */
export declare function sharePollSendData(shareEpoch: string): Uint8Array

/**
 * Hands one received chunk to the core.
 * JSON {ok:true,action:"share_receive_data",shareEpoch,accepted:true,bytes} or
 * {ok:false,code∈invalid_share_epoch|stale_share_epoch|share_closed|empty_data|
 * transport_rejected}. accepted only names the bounded queue.
 */
export declare function sharePushReceiveData(shareEpoch: string, data: Uint8Array): string

/**
 * Activates the named share's nearby run once the platform link is up: call it
 * after the collaborator connection resolves and before the first pump.
 * JSON {ok:true,connected:true} or {ok:false,code∈app_not_admitted|
 * stale_share_epoch|share_closed|connect_failed}. A refusal activates nothing.
 */
export declare function shareConnectTransport(shareEpoch: string): string

/**
 * Observed nearby-transport state for this share epoch.
 * JSON {ok:true,shareEpoch,state,reason,transportClosed} |
 * {ok:false,code∈invalid_share_epoch|stale_share_epoch}. A stale epoch is a
 * refusal, never a fabricated "closed"; no address, token or pin is included.
 */
export declare function shareGetTransportStatus(shareEpoch: string): string

/**
 * Reports what the platform's sendData call did with one chunk.
 * ok:true is only {ok:true,reported:true,meaning:"platform_call_completed"}.
 * ok:false closes the share. Send rejection returns code:"send_failed" with
 * platformCode/sendFailures; peer_disconnected/user_stop reports its reason
 * without a failed-send count. Already-terminated shares return "share_closed".
 * Fixed labels: send_data_rejected|send_data_timeout|transport_closed|
 * transport_error|peer_disconnected|user_stop|unknown; code is numeric.
 * Platform message text is never accepted. package/index.ets defaults code to 0
 * for a caller that has no numeric code to report.
 */
export declare function shareReportSendResult(shareEpoch: string, ok: boolean, label: string, code: number): string

export declare function sessionStart(sessionId: string): string

/** Same-wire password answer; queued is not authorized. Before start, only records the initial password. */
export declare function sessionLogin(sessionId: string, loginJson: string): string

/** Same authentication; queued is not authorized. Trusted enrollment is explicitly refused. */
export declare function sessionSend2fa(sessionId: string, code: string, trustThisDevice: boolean): string

/** Explicit reusable password-equivalent credential; null before authentication or after close. */
export declare function sessionGetConnToken(sessionId: string): string | null

/** Non-secret query; does not serialize or return reconnect material. */
export declare function sessionHasConnToken(sessionId: string): boolean

/**
 * Resolves with native teardown completion, never request acceptance.
 * JSON always carries released:boolean and settle:"settled"|"unconfirmed"|"neverstarted";
 * only released:true permits destroying the Surface. surfaces retains real binding
 * token/sourceIdentity/surfaceId strings and released/quarantined verdicts.
 * Remote failures, input-release counters and telemetry persist until explicit ACK.
 * Abandoning the Promise does not relinquish native cleanup ownership.
 */
export declare function sessionClose(sessionId: string): Promise<string>

/** Requires the exact epoch, confirmed reclamation and a complete close/poll receipt. */
export declare function sessionAcknowledgeClose(sessionId: string, lifecycleEpoch: string): string

/**
 * Binds this epoch's one Surface from the `componentId` that `xcomponentAttach`
 * returned on this UI environment. A Surface id, a node id or any other string is
 * refused and never promoted into a lease.
 * Empty componentId is a give-back request: held:true/released:false while a
 * viewer or quarantined decoder still owns the loan; released:true requires
 * never-started or confirmed-reclaimed ownership.
 * One destination per session: another componentId cannot replace it.
 */
export declare function sessionBindSurface(sessionId: string, display: number, componentId: string, lifecycleEpoch: string): string

/**
 * Persistent login_failure: null | "empty_password" | "wrong_password" | "refused".
 * Optional peer_close_reason: "manual_request" | null, only for a typed confirmed
 * terminal peer close; registered/no-viewer polls use null. Raw peer text is never exposed.
 * Final error, input-release counters, telemetry and released/settle/surfaces survive
 * reclamation until sessionAcknowledgeClose(sessionId,lifecycleEpoch);
 * close/authorization events remain one-shot. Return type remains JSON string.
 */
export declare function sessionPollEvents(sessionId: string, limit: number): string

export declare function sessionRefresh(sessionId: string, display: number): string

/**
 * Local expected-image geometry, never ChangeResolution. JSON effect=local_applied.
 * native_render_ready reports new matching native submission, not physical scanout;
 * presentation_generation is an opaque decimal string.
 */
export declare function sessionSetSize(sessionId: string, display: number, width: number, height: number): string

/** Decode/receive continue; already admitted native submissions may still finish. */
export declare function sessionSetVideoPaused(sessionId: string, paused: boolean): string

/** Rearms native_render_ready; historical counters cannot satisfy this generation. */
export declare function sessionOnWaitingForImageDialogShow(sessionId: string): string

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
export declare function sessionGetFrameRateSnapshot(sessionId: string, display: number): string

export declare function sessionSendMouse(sessionId: string, mouseJson: string, inputGeneration: number): string

/** VNC/RDP X11 keysym transition; keysym is an integer in 1..=0x1FFFFFFF. ok means queued, not applied. */
export declare function sessionSendKeysym(sessionId: string, keysym: number, down: boolean, inputGeneration: number): string

export declare function sessionInputKey(sessionId: string, keyJson: string, inputGeneration: number): string

export declare function sessionInputString(sessionId: string, value: string, inputGeneration: number): string

/**
 * Sends one clipboard copy; queued:true means it entered the session's one writer
 * under clipboard_revision, never that the peer applied it (the wire has no clipboard
 * acknowledgement, so applied is always false). Empty content is the protocol's clear.
 * A refusal carries ok:false/queued:false and a reason such as not_allowed,
 * not_deliverable, too_large, closed, backpressure or unknown_session.
 */
export declare function sessionSendClipboard(sessionId: string, content: string): string

/** Sends an encoded PNG image clipboard; the bound is checked before any copy. */
export declare function sessionSendClipboardImage(sessionId: string, image: Uint8Array): string

/**
 * Next peer clipboard update, reserving its image for sessionTakeClipboardImage.
 * JSON: {ok,queued:false,applied:false,action,revision,text,html,image,formats};
 * No pending update: {ok:false,reason:"no_pending_update"}; absent text/html/image
 * are omitted, never null. The image descriptor exists only when the update
 * carried one.
 */
export declare function sessionTakeClipboard(sessionId: string): string

/**
 * The bytes the descriptor from sessionTakeClipboard described, or an empty array when
 * no image was described or the acceptance was withdrawn before this call.
 */
export declare function sessionTakeClipboardImage(sessionId: string): Uint8Array

/** Queues staged local files, not a peer-applied acknowledgement. */
export declare function sessionSendClipboardFiles(sessionId: string, pathsJson: string): string

/** Queues the private incoming root; filesystem failures arrive as events. */
export declare function sessionSetClipboardFileRoot(sessionId: string, root: string): string

/** Non-consuming JSON {ok,allowed,revision,pending}. */
export declare function sessionGetClipboardFileState(sessionId: string): string

/** Takes at most 8 facts; Files carry the original revision, never a refreshed one. */
export declare function sessionTakeClipboardFileEvents(sessionId: string): string

export declare function sessionSetCustomFps(sessionId: string, fps: number): string

/**
 * Advances input_generation without changing input or clipboard policy.
 * Queued old-generation input is dropped; the existing writer releases its held
 * keys/buttons. release_pending/release counters are not a remote release ACK.
 * No running viewer is an error, never a fabricated generation.
 */
export declare function sessionReleaseInput(sessionId: string): string

export declare function sessionSetViewOnly(sessionId: string, enabled: boolean): string

export declare function sessionSetUnverifiedInputAccepted(sessionId: string, accepted: boolean): string

export declare function sessionSetCommon(sessionId: string, key: string, value: string): string

/**
 * Cancels one live job of this session; ok/queued is local admission only.
 * No actId, including 0, closes a viewer or ACKs/removes a terminal record.
 */
export declare function sessionCancelJob(sessionId: string, actId: number): string

export declare function transferNextJobId(): number

export declare function sessionReadRemoteDir(sessionId: string, path: string, includeHidden: boolean): string

export declare function sessionSendFiles(sessionId: string, actId: number, path: string, to: string,
  fileNum: number, includeHidden: boolean, isRemote: boolean, isDir: boolean): string

export declare function sessionSetConfirmOverrideFile(sessionId: string, actId: number, fileNum: number,
  needOverride: boolean, remember: boolean, isUpload: boolean): string

/** Native-committed route plus optional raw draft; never shared Key text. */
export declare function runtimeGetServerConfig(): Promise<string>

/** {mode,idServer,relayServer,apiServer,keyUpdate:{action:'keep'|'set'|'clear',value?,draftRevision?},draftOnly?}.
 * draftOnly stores raw text and an Asset-backed Key reference without approval.
 * A valid effective commit returns v2 manual-edit provenance, not reachability. */
export declare function runtimeSetServerConfig(profileJson: string): Promise<string>

export declare function runtimeTestServerConfig(profileJson: string): Promise<string>

export declare function runtimeListRecentPeers(): Promise<string>

export declare function runtimeListFavorites(): Promise<string>

export declare function runtimeSetFavorite(peerId: string, favorite: boolean): Promise<string>

export declare function runtimeRecordRecentPeer(peerJson: string): Promise<string>

export declare function runtimeRemoveRecentPeer(peerId: string): Promise<string>

export declare function peerQueryOnline(idsJson: string, approvedProfileJson: string): Promise<string>

export declare function peerPresenceCancel(queryGeneration: string): string

/**
 * Adopts one live ArkUI node's SurfaceHolder on the UI environment thread (call it
 * from that thread, after the node is attached). `nodeId` is only a label.
 * The answer carries the opaque componentId this bridge allocates (never reused,
 * and the only value sessionBindSurface accepts), the node's unique id and the
 * holder state. ok:false is a real refusal; when cleanup could not be confirmed
 * the same componentId is still returned so the caller can detach it instead of
 * losing the holder.
 */
export declare function xcomponentAttach(nodeId: string, frameNode: Object, onSurfaceEvent: (event: string) => void): string

/**
 * Releases this bridge's claim on one holder. held:true means a borrowed loan or
 * an active native callback still owns resources: the holder, its callback and its
 * window stay retained, and only a later detach may complete. No answer here
 * claims a release that did not happen.
 */
export declare function xcomponentDetach(componentId: string): string

/**
 * Declares the rate the attached node should be drawn at. ok separates the
 * frame-rate call (result) from the on-frame callback registration
 * (registerResult); frameCallbacks counts native signal callbacks, not decoded
 * frames or measured presentation FPS.
 */
export declare function xcomponentSetFrameRateRangeNative(componentId: string, expected: number, min: number, max: number): string

export declare function sessionSetImageQuality(sessionId: string, quality: string): string

export declare function sessionSetCustomImageQuality(sessionId: string, quality: number): string

export declare function sessionSetCodecPreference(sessionId: string, codec: string): string

export declare function sessionSetShowRemoteCursor(sessionId: string, enabled: boolean): string

export declare function sessionSwitchDisplay(sessionId: string, displaysJson: string): string

export declare function sessionChangeResolution(sessionId: string, display: number, width: number, height: number): string

export declare function sessionGetImageQuality(sessionId: string): string

export declare function sessionGetToggleOption(sessionId: string, option: string): boolean

export declare function sessionToggleOption(sessionId: string, option: string): string

export declare function sessionGetRemoteAudioState(sessionId: string): string

export declare function sessionGetEnableTrustedDevices(sessionId: string): boolean

export declare function controlledServerStart(optionsJson: string): Promise<string>

export declare function controlledServerStop(runEpoch: string): Promise<string>

export declare function controlledServerGetStatus(): string

/**
 * Authorization JSON carries requestId: an opaque decimal string, empty without
 * an owner; it is neither runEpoch nor input_generation. Starting with
 * enableInput:true also requires that inputAuthorizationRequestId.
 */
export declare function controlledInputAuthorizationRequest(): string

export declare function controlledInputAuthorizationStatus(): string

/** Cancels exactly requestId, including before a host run exists. Never pass runEpoch or input_generation. */
export declare function controlledInputAuthorizationCancel(requestId: string): string

export declare function controlledScreenCaptureGetStatus(): string

export declare function controlledScreenCaptureStop(runEpoch: string): Promise<string>

export declare function controlledScreenConfigure(configJson: string): string

export declare function controlledIncomingPoll(limit: number): string

export declare function controlledIncomingResolve(requestId: string, allow: boolean): string

export declare function controlledPasswordGet(): Promise<string>

export declare function controlledPasswordRefresh(): Promise<string>

export declare function controlledPasswordSetPermanent(password: string): Promise<string>

export declare function controlledPasswordSetVerificationMethod(method: string): Promise<string>

export declare function controlledSettingSet(key: string, value: string): Promise<string>

export declare function controlledTwoFactorBegin(): Promise<string>

export declare function controlledTwoFactorVerify(code: string): Promise<string>

export declare function controlledTwoFactorDisable(): Promise<string>

export declare function controlledTwoFactorGet(): Promise<string>

export declare function controlledTwoFactorRemoveTrustedDevices(hwidsJson: string): Promise<string>

export declare function controlledTwoFactorClearTrustedDevices(): Promise<string>
