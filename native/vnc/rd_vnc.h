/* Engine ownership adapter for LibVNCClient 0.9.15; see ORIGIN.txt. */
#ifndef RD_VNC_H
#define RD_VNC_H
#include <stddef.h>
#include <stdint.h>

typedef struct rd_vnc rd_vnc;
typedef struct rd_vnc_rect { int x, y, width, height; } rd_vnc_rect;
typedef struct rd_vnc_frame {
    const uint8_t *pixels;
    size_t length;
    const rd_vnc_rect *damage;
    size_t damage_count;
    int width, height;
    int resized, painted, bell;
    const char *clipboard;
    size_t clipboard_length;
} rd_vnc_frame;

enum rd_vnc_error {
    RD_VNC_OK = 0, RD_VNC_TRANSPORT = 1, RD_VNC_CLOSED = 2,
    RD_VNC_AUTH = 3, RD_VNC_SECURITY = 4, RD_VNC_REFUSED = 5,
    RD_VNC_VERSION = 6, RD_VNC_GEOMETRY = 7, RD_VNC_PROTOCOL = 8,
    RD_VNC_CREDENTIAL = 9, RD_VNC_MEMORY = 10
};

/* Where the first failing native operation stopped. Fixed vocabulary only: the
 * kind of operation, an errno captured at the failing call, and counts. No peer
 * text, credentials, or frame/clipboard bytes are ever recorded. */
enum rd_vnc_stage {
    RD_VNC_STAGE_NONE = 0,
    RD_VNC_STAGE_READ_EOF = 1,      /* read() returned 0: the peer closed */
    RD_VNC_STAGE_READ_ERRNO = 2,    /* read() failed with a real errno */
    RD_VNC_STAGE_READ_TIMEOUT = 3,  /* readTimeout of no data mid-read */
    RD_VNC_STAGE_READ_WAIT = 4,     /* select() while waiting to read failed */
    RD_VNC_STAGE_WRITE_ERRNO = 5,   /* write() failed with a real errno */
    RD_VNC_STAGE_WRITE_ZERO = 6,    /* write() returned 0 */
    RD_VNC_STAGE_WRITE_WAIT = 7,    /* select() while waiting to write failed */
    RD_VNC_STAGE_WRITE_LAYER = 8,   /* TLS/SASL write layer refused */
    RD_VNC_STAGE_READ_NULL = 9,     /* read into a NULL buffer (caller malloc failed) */
    RD_VNC_STAGE_HANDLE_FALSE = 10  /* HandleRFBServerMessage failed with no I/O failure:
                                       decoding, unknown message type, bounds check */
};
typedef struct rd_vnc_origin {
    int stage;              /* enum rd_vnc_stage */
    int os_errno;           /* errno captured at the failing call; 0 when not applicable */
    unsigned int want;      /* bytes the failing ReadFromRFBServer/Write call needed */
    unsigned int buffered;  /* bytes already buffered by the client at that moment */
    unsigned int reads;     /* ReadFromRFBServer calls so far in the current message; 1 = failed at its first read */
} rd_vnc_origin;

/* On success the client owns socket. On allocation failure the caller retains it. */
rd_vnc *rd_vnc_create(uintptr_t socket, const char *password, int shared);
int rd_vnc_connect(rd_vnc *session);
int rd_vnc_handle(rd_vnc *session, rd_vnc_frame *frame);
int rd_vnc_buffered(const rd_vnc *session);
int rd_vnc_pointer(rd_vnc *session, int x, int y, int buttons);
int rd_vnc_key(rd_vnc *session, uint32_t key, int down);
int rd_vnc_clipboard(rd_vnc *session, const char *text, int length);
int rd_vnc_error_code(const rd_vnc *session);
/* Returns 1 and fills out when a failing native operation was recorded. */
int rd_vnc_origin_get(const rd_vnc *session, rd_vnc_origin *out);
const char *rd_vnc_error_reason(const rd_vnc *session);
const char *rd_vnc_name(const rd_vnc *session);
int rd_vnc_width(const rd_vnc *session);
int rd_vnc_height(const rd_vnc *session);
uint32_t rd_vnc_authentication(const rd_vnc *session);
void rd_vnc_destroy(rd_vnc *session);
#endif
