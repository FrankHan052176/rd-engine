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
 * optionsJson may carry approvedServerProfile and rustdeskIdOnly; true keeps even
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

export function sessionStart(sessionId: string): string {
  return native.sessionStart(sessionId);
}

/** Records credentials only before terminal/closing state; never reauthenticates a closed viewer. */
export function sessionLogin(sessionId: string, loginJson: string): string {
  return native.sessionLogin(sessionId, loginJson);
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
 * Echo the native epoch. One Surface only: no running-viewer hot rebind.
 * Empty surfaceId is a give-back request; a live/closing viewer returns
 * held:true/released:false. Only no viewer ever started or confirmed reclamation
 * permits released:true. Binding/give-back never counts as a terminal ACK.
 */
export function sessionBindSurface(sessionId: string, display: number, surfaceId: string,
  lifecycleEpoch: string): string {
  return native.sessionBindSurface(sessionId, display, surfaceId, lifecycleEpoch);
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

export function sessionGetFrameRateSnapshot(sessionId: string, display: number): string {
  return native.sessionGetFrameRateSnapshot(sessionId, display);
}

export function sessionSendMouse(sessionId: string, mouseJson: string, inputGeneration: number): string {
  return native.sessionSendMouse(sessionId, mouseJson, inputGeneration);
}

export function sessionInputKey(sessionId: string, keyJson: string, inputGeneration: number): string {
  return native.sessionInputKey(sessionId, keyJson, inputGeneration);
}

export function sessionInputString(sessionId: string, value: string, inputGeneration: number): string {
  return native.sessionInputString(sessionId, value, inputGeneration);
}

export function sessionSetCustomFps(sessionId: string, fps: number): string {
  return native.sessionSetCustomFps(sessionId, fps);
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
 * Explicitly unsupported until a real transfer-job owner is wired here.
 * No actId (including 0) closes a viewer, releases a Surface or ACKs a receipt.
 * Use sessionClose/sessionAcknowledgeClose for the viewer lifecycle.
 */
export function sessionCancelJob(sessionId: string, actId: number): string {
  return native.sessionCancelJob(sessionId, actId);
}

/**
 * Reads the server profile this engine has itself explicitly saved. Resolves with
 * `config: null` when none was saved; an approval is not a reachability or
 * account claim, and a failed read is not an empty profile.
 */
export function runtimeGetServerConfig(): Promise<string> {
  return native.runtimeGetServerConfig();
}

/** Saves a profile only after the same validation as validateServerProfile; saving is not reachability. */
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
