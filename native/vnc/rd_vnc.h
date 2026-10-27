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

/* On success the client owns socket. On allocation failure the caller retains it. */
rd_vnc *rd_vnc_create(uintptr_t socket, const char *password, int shared);
int rd_vnc_connect(rd_vnc *session);
int rd_vnc_handle(rd_vnc *session, rd_vnc_frame *frame);
int rd_vnc_buffered(const rd_vnc *session);
int rd_vnc_pointer(rd_vnc *session, int x, int y, int buttons);
int rd_vnc_key(rd_vnc *session, uint32_t key, int down);
int rd_vnc_clipboard(rd_vnc *session, const char *text, int length);
int rd_vnc_error_code(const rd_vnc *session);
const char *rd_vnc_error_reason(const rd_vnc *session);
const char *rd_vnc_name(const rd_vnc *session);
int rd_vnc_width(const rd_vnc *session);
int rd_vnc_height(const rd_vnc *session);
uint32_t rd_vnc_authentication(const rd_vnc *session);
void rd_vnc_destroy(rd_vnc *session);
#endif
