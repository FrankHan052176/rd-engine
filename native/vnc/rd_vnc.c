/* LibVNCClient owns negotiation, authentication, codecs, requests and input.
 * This file owns only callback storage and the engine's typed boundary.
 */
#include "rd_vnc_hooks.h"
#include <limits.h>
#include <string.h>
#if !defined(_WIN32) && !defined(__APPLE__)
/* linux/tcp.h is where TCP_INFO's own fields are declared: the OHOS SDK's
 * netinet/tcp.h only forward-declares struct tcp_info, so a build that read the
 * measurement through that header alone could not see tcpi_rtt at all. */
#include <linux/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

struct rd_vnc {
    rfbClient *client;
    uint8_t *pixels;
    size_t pixel_length;
    rd_vnc_rect *damage;
    size_t damage_count, damage_capacity;
    char *password, *reason, *clipboard;
    size_t clipboard_length;
    int error, resized, bell;
    rd_vnc_origin origin;
    unsigned int reads; /* ReadFromRFBServer calls in the current message */
    uint32_t encoding;
    unsigned int rectangles;
};
static char client_tag;

static rd_vnc *owner(rfbClient *client) {
    return (rd_vnc *)rfbClientGetClientData(client, &client_tag);
}
static void erase_password(rd_vnc *session) {
    if (session->password) {
        volatile char *p = session->password;
        size_t n = strlen(session->password);
        while (n--) *p++ = 0;
        free(session->password);
        session->password = NULL;
    }
}
void rd_vnc_fail(rfbClient *client, int code) {
    rd_vnc *session = owner(client);
    if (session && session->error == RD_VNC_OK) session->error = code;
}
void rd_vnc_note(rfbClient *client, int stage, int os_errno, unsigned int want) {
    rd_vnc *session = owner(client);
    if (!session || session->origin.stage != RD_VNC_STAGE_NONE) return;
    session->origin.stage = stage;
    session->origin.os_errno = os_errno;
    session->origin.want = want;
    session->origin.buffered = client->buffered;
    session->origin.reads = session->reads;
}
void rd_vnc_reason(rfbClient *client, const char *reason) {
    rd_vnc *session = owner(client);
    if (!session) return;
    free(session->reason);
    session->reason = strdup(reason);
    if (!session->reason) rd_vnc_fail(client, RD_VNC_MEMORY);
}
void rd_vnc_auth_result(rfbClient *client, uint32_t result) {
    if (result != rfbVncAuthOK) rd_vnc_fail(client, RD_VNC_AUTH);
}
int rd_vnc_allow_security(rfbClient *client, uint32_t security) {
    /* Also enforce this for 3.3, where upstream's allowlist is not consulted. */
    if (security == rfbConnFailed || security == rfbNoAuth || security == rfbVncAuth)
        return 1;
    rd_vnc_fail(client, RD_VNC_SECURITY);
    return 0;
}
void rd_vnc_prefer_security(uint8_t *types, unsigned int count) {
    unsigned int i;
    for (i = 0; i < count; ++i) {
        if (types[i] == rfbVncAuth) {
            uint8_t first = types[0];
            types[0] = types[i];
            types[i] = first;
            return;
        }
    }
}

/* The original upstream I/O functions still do every read/write. These wrappers
 * preserve failures as typed evidence instead of scraping process-wide logs. */
extern rfbBool rd_vnc_read_upstream(rfbClient *, char *, unsigned int);
extern rfbBool rd_vnc_write_upstream(rfbClient *, const char *, unsigned int);
rfbBool ReadFromRFBServer(rfbClient *client, char *out, unsigned int count) {
    rd_vnc *session = owner(client);
    rfbBool ok;
    if (session) ++session->reads;
    ok = rd_vnc_read_upstream(client, out, count);
    if (!ok) rd_vnc_fail(client, RD_VNC_TRANSPORT);
    return ok;
}
rfbBool WriteToRFBServer(rfbClient *client, const char *bytes, unsigned int count) {
    rfbBool ok = rd_vnc_write_upstream(client, bytes, count);
    if (!ok) rd_vnc_fail(client, RD_VNC_TRANSPORT);
    return ok;
}
static char *password(rfbClient *client) {
    rd_vnc *session = owner(client);
    size_t n = session->password ? strlen(session->password) : 0;
    char *result;
    if (!n) {
        rd_vnc_fail(client, RD_VNC_CREDENTIAL);
        return NULL;
    }
    if (n > 8) n = 8;
    result = (char *)malloc(n + 1);
    if (!result) {
        rd_vnc_fail(client, RD_VNC_MEMORY);
        return NULL;
    }
    memcpy(result, session->password, n);
    result[n] = 0;
    return result; /* LibVNCClient wipes and frees this allocation. */
}
static rfbBool allocate_frame(rfbClient *client) {
    rd_vnc *session = owner(client);
    uint64_t length;
    uint8_t *pixels;
    if (client->width <= 0 || client->height <= 0 ||
        client->width > UINT16_MAX || client->height > UINT16_MAX) {
        rd_vnc_fail(client, RD_VNC_GEOMETRY);
        return FALSE;
    }
    length = (uint64_t)client->width * client->height * 4;
    /* Upstream bitmap callbacks use signed-int byte offsets. */
    if (length > SIZE_MAX || length > INT_MAX) {
        rd_vnc_fail(client, RD_VNC_GEOMETRY);
        return FALSE;
    }
    pixels = (uint8_t *)calloc((size_t)length, 1);
    if (!pixels) {
        rd_vnc_fail(client, RD_VNC_MEMORY);
        return FALSE;
    }
    free(session->pixels);
    session->pixels = pixels;
    session->pixel_length = (size_t)length;
    client->frameBuffer = pixels;
    session->damage_count = 0;
    session->resized = 1;
    return TRUE;
}
static void damage(rfbClient *client, int x, int y, int width, int height) {
    rd_vnc *session = owner(client);
    rd_vnc_rect *rect;
    if (!width || !height) return;
    if (x < 0 || y < 0 || width < 0 || height < 0 ||
        width > client->width || height > client->height ||
        x > client->width - width || y > client->height - height) {
        rd_vnc_fail(client, RD_VNC_GEOMETRY);
        return;
    }
    if (session->damage_count == session->damage_capacity) {
        size_t capacity = session->damage_capacity ? session->damage_capacity * 2 : 16;
        rd_vnc_rect *next = (rd_vnc_rect *)realloc(session->damage, capacity * sizeof(*next));
        if (!next) {
            rd_vnc_fail(client, RD_VNC_MEMORY);
            return;
        }
        session->damage = next;
        session->damage_capacity = capacity;
    }
    rect = &session->damage[session->damage_count++];
    rect->x = x; rect->y = y; rect->width = width; rect->height = height;
}
static void bell(rfbClient *client) { owner(client)->bell = 1; }
static void clipboard(rfbClient *client, const char *text, int length) {
    rd_vnc *session = owner(client);
    char *copy;
    if (length < 0 || length > 1024 * 1024) {
        rd_vnc_fail(client, RD_VNC_PROTOCOL);
        return;
    }
    copy = (char *)malloc((size_t)length + 1);
    if (!copy) {
        rd_vnc_fail(client, RD_VNC_MEMORY);
        return;
    }
    memcpy(copy, text, (size_t)length);
    copy[length] = 0;
    free(session->clipboard);
    session->clipboard = copy;
    session->clipboard_length = (size_t)length;
}
/* --- rectangle accounting ------------------------------------------------
 * Upstream calls this for every real framebuffer rectangle, after its own
 * pseudo-encoding branches, so cursor shapes, pointer positions and capability
 * announcements are never counted as pixels this session received. */
void rd_vnc_rectangle(rfbClient *client, uint32_t encoding) {
    rd_vnc *session = owner(client);
    if (!session) return;
    ++session->rectangles;
    session->encoding = encoding;
}

/* --- remote cursor -------------------------------------------------------
 * No cursor shape is requested (see rd_vnc_create), so a server composites its
 * own pointer into the framebuffer it sends. Whatever it renders, including a
 * pointer drawn against the real background, arrives as ordinary pixels and is
 * kept as is: this adapter neither paints nor restores a cursor. */
#if defined(_WIN32) || defined(__APPLE__)
/* Neither platform's socket API exposes TCP_INFO, so this measurement is
 * unavailable here rather than zero. */
static int socket_rtt_us(const rfbClient *client) {
    (void)client;
    return -1;
}
#else
/* The kernel's own smoothed round trip for this socket, in microseconds. An RFB
 * server offers no delay probe, so this is the only round trip that exists. */
static int socket_rtt_us(const rfbClient *client) {
    struct tcp_info info;
    socklen_t length = (socklen_t)sizeof(info);
    if (!client) return -1;
    memset(&info, 0, sizeof(info));
    if (getsockopt((int)client->sock, IPPROTO_TCP, TCP_INFO, &info, &length) != 0) return -1;
    if (length < (socklen_t)(offsetof(struct tcp_info, tcpi_rtt) + sizeof(info.tcpi_rtt)))
        return -1;
    if (info.tcpi_rtt == 0) return -1;
    return info.tcpi_rtt > (uint32_t)INT_MAX ? INT_MAX : (int)info.tcpi_rtt;
}
#endif

rd_vnc *rd_vnc_create(uintptr_t socket, const char *secret, int shared) {
    const uint32_t schemes[] = { rfbVncAuth, rfbNoAuth };
    rd_vnc *session = (rd_vnc *)calloc(1, sizeof(*session));
    rfbClient *client;
    if (!session) return NULL;
    session->client = client = rfbGetClient(8, 3, 4);
    if (!client) { free(session); return NULL; }
    session->password = strdup(secret);
    rfbClientSetClientData(client, &client_tag, session);
    SetClientAuthSchemes(client, schemes, 2);
    if (!session->password || !owner(client) || !client->clientAuthSchemes) {
        rd_vnc_destroy(session);
        return NULL;
    }
    client->sock = (rfbSocket)socket;
    client->listenSpecified = TRUE; /* Adopt the cancellable, already-connected socket. */
    client->appData.shareDesktop = shared ? TRUE : FALSE;
    client->appData.encodingsString = "zrle zlib hextile corre rre copyrect raw";
    client->appData.enableJPEG = FALSE;
    /* Cursor shapes are deliberately not requested (useRemoteCursor stays
     * FALSE, so upstream sends no XCursor/RichCursor/PointerPos encodings). RFB
     * shapes are fixed colours plus a 1-bit mask and cannot express an inverted
     * (XOR) pointer; a server that has not been asked for a shape draws its own
     * pointer into the framebuffer it sends, against the real background. */
    client->appData.useRemoteCursor = FALSE;
    client->canHandleNewFBSize = TRUE;
    client->format.bigEndian = FALSE;
    client->format.redShift = 16;
    client->format.greenShift = 8;
    client->format.blueShift = 0;
    client->readTimeout = 30;
    client->GetPassword = password;
    client->MallocFrameBuffer = allocate_frame;
    client->GotFrameBufferUpdate = damage;
    client->GotXCutText = clipboard;
    client->Bell = bell;
    return session;
}
int rd_vnc_connect(rd_vnc *session) {
    /* rfbInitClient sends the initial full update request. On failure upstream
     * frees rfbClient itself, but never frees our framebuffer or callback data. */
    int ok = rfbInitClient(session->client, NULL, NULL);
    if (!ok) session->client = NULL;
    erase_password(session);
    if (!ok && !session->error) session->error = RD_VNC_PROTOCOL;
    return ok && !session->error;
}
int rd_vnc_handle(rd_vnc *session, rd_vnc_frame *frame) {
    rfbClient *client = session->client;
    if (!client || session->error) return 0;
    session->damage_count = 0;
    session->resized = session->bell = 0;
    session->reads = 0;
    session->rectangles = 0;
    free(session->clipboard);
    session->clipboard = NULL;
    session->clipboard_length = 0;
    /* This upstream function sends the next incremental request itself. */
    if (!HandleRFBServerMessage(client)) {
        /* A read/write failure already recorded its own stage; this is every
         * other FALSE (decode failure, unknown message type, bounds check). */
        rd_vnc_note(client, RD_VNC_STAGE_HANDLE_FALSE, 0, 0);
        rd_vnc_fail(client, RD_VNC_PROTOCOL);
        return 0;
    }
    if (session->error) return 0;
    frame->pixels = session->pixels;
    frame->length = session->pixel_length;
    frame->damage = session->damage;
    frame->damage_count = session->damage_count;
    frame->width = client->width;
    frame->height = client->height;
    frame->resized = session->resized;
    frame->painted = session->damage_count != 0;
    frame->bell = session->bell;
    frame->clipboard = session->clipboard;
    frame->clipboard_length = session->clipboard_length;
    frame->encoding = session->encoding;
    frame->rectangles = session->rectangles;
    frame->tcp_rtt_us = socket_rtt_us(client);
    return 1;
}
int rd_vnc_buffered(const rd_vnc *s) { return s->client && s->client->buffered != 0; }
int rd_vnc_pointer(rd_vnc *s, int x, int y, int buttons) {
    if (x < 0 || y < 0 || x >= s->client->width || y >= s->client->height) return -1;
    if (!SupportsClient2Server(s->client, rfbPointerEvent)) return 0;
    /* Upstream rfbBool TRUE is -1 on POSIX; reserve -1 here for geometry
     * rejection, not a successful completed socket write. */
    if (!SendPointerEvent(s->client, x, y, buttons)) return 0;
    return 1;
}
int rd_vnc_key(rd_vnc *s, uint32_t key, int down) {
    if (!SupportsClient2Server(s->client, rfbKeyEvent)) return 0;
    return SendKeyEvent(s->client, key, down);
}
int rd_vnc_clipboard(rd_vnc *s, const char *text, int length) {
    if (!SupportsClient2Server(s->client, rfbClientCutText)) return 0;
    return SendClientCutText(s->client, (char *)text, length);
}
int rd_vnc_error_code(const rd_vnc *s) { return s->error; }
int rd_vnc_origin_get(const rd_vnc *s, rd_vnc_origin *out) {
    if (s->origin.stage == RD_VNC_STAGE_NONE) return 0;
    *out = s->origin;
    return 1;
}
const char *rd_vnc_error_reason(const rd_vnc *s) { return s->reason ? s->reason : ""; }
const char *rd_vnc_name(const rd_vnc *s) { return s->client->desktopName; }
int rd_vnc_width(const rd_vnc *s) { return s->client->width; }
int rd_vnc_height(const rd_vnc *s) { return s->client->height; }
uint32_t rd_vnc_authentication(const rd_vnc *s) { return s->client->authScheme; }
void rd_vnc_destroy(rd_vnc *session) {
    if (!session) return;
    erase_password(session);
    if (session->client) rfbClientCleanup(session->client);
    free(session->pixels);
    free(session->damage);
    free(session->reason);
    free(session->clipboard);
    free(session);
}
