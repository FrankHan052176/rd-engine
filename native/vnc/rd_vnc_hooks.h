/* Minimal typed error/policy seam. No protocol parsing lives here. */
#ifndef RD_VNC_HOOKS_H
#define RD_VNC_HOOKS_H
#include "rd_vnc.h"
#include <rfb/rfbclient.h>
void rd_vnc_fail(rfbClient *client, int code);
void rd_vnc_reason(rfbClient *client, const char *reason);
void rd_vnc_auth_result(rfbClient *client, uint32_t result);
int rd_vnc_allow_security(rfbClient *client, uint32_t security);
void rd_vnc_prefer_security(uint8_t *types, unsigned int count);
#endif
