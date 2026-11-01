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

export declare function sessionStart(sessionId: string): string

/** Same-wire password answer; queued is not authorized. Before start, only records the initial password. */
export declare function sessionLogin(sessionId: string, loginJson: string): string

/** Same authentication; queued is not authorized. Trusted enrollment is explicitly refused. */
export declare function sessionSend2fa(sessionId: string, code: string, trustThisDevice: boolean): string

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

export declare function sessionGetFrameRateSnapshot(sessionId: string, display: number): string

export declare function sessionSendMouse(sessionId: string, mouseJson: string, inputGeneration: number): string

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

export declare function sessionSetCustomFps(sessionId: string, fps: number): string

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

export declare function runtimeGetServerConfig(): Promise<string>

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
