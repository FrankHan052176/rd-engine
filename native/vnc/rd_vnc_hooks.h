/* Minimal typed error/policy seam. No protocol parsing lives here. */
#ifndef RD_VNC_HOOKS_H
#define RD_VNC_HOOKS_H
#include "rd_vnc.h"
#include <rfb/rfbclient.h>
void rd_vnc_fail(rfbClient *client, int code);
/* Records the first failing operation (first wins, never overwritten). */
void rd_vnc_note(rfbClient *client, int stage, int os_errno, unsigned int want);
void rd_vnc_reason(rfbClient *client, const char *reason);
void rd_vnc_auth_result(rfbClient *client, uint32_t result);
int rd_vnc_allow_security(rfbClient *client, uint32_t security);
void rd_vnc_prefer_security(uint8_t *types, unsigned int count);
/* One real framebuffer rectangle, recorded after upstream has handled every
 * pseudo-encoding. Counts the units this session receives and names the
 * encoding the server actually chose. */
void rd_vnc_rectangle(rfbClient *client, uint32_t encoding);
#endif
