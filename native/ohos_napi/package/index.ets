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

/** Requests close without ACKing/removing the record; keep the Surface until its terminal poll confirms reclamation. */
export function sessionClose(sessionId: string): string {
  return native.sessionClose(sessionId);
}

export function sessionBindSurface(sessionId: string, display: number, surfaceId: string): string {
  return native.sessionBindSurface(sessionId, display, surfaceId);
}

/**
 * Persistent login_failure: null | "empty_password" | "wrong_password" | "refused".
 * Optional peer_close_reason: "manual_request" | null, a typed confirmed-terminal
 * fact only; never raw peer text or a new UI action. Registered/no-viewer polls use null.
 * Confirmed terminal snapshots retain error, input-release counters and telemetry
 * until sessionCancelJob(sessionId, 0) ACKs consumption. Events remain one-shot.
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
 * Live: whole-viewer cancellation only (record_removed:false, actId ignored).
 * Terminal: actId=0 ACKs only a confirmed, successfully polled receipt and returns
 * {ok:true, record_removed:true}. Unknown/unconfirmed/unpolled records are refused.
 */
export function sessionCancelJob(sessionId: string, actId: number): string {
  return native.sessionCancelJob(sessionId, actId);
}
