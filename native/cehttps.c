/* cehttps.c - modern HTTPS for Windows Mobile / Windows CE on top of wolfSSL.
 *
 * Copyright (C) 2026 the CeHttps authors. GPLv3 (see LICENSE).
 *
 * Design
 *  - One shared WOLFSSL_CTX holding the trusted roots. Each request takes a
 *    reference, so ch_init() can swap in a new set while requests run.
 *  - Each request owns all its state (buffers, error, timings): no globals are
 *    touched per request except under a lock.
 *  - All socket I/O goes through wolfSSL custom I/O callbacks that wait with
 *    select() in short slices, so the deadline and cancellation are always
 *    honoured, even mid-handshake or mid-read.
 *  - HTTP/1.1 with "Connection: close"; Content-Length and chunked bodies.
 *  - A tiny per-host TLS session cache gives TLS 1.3 resumption.
 */
#include <winsock2.h>
#include <windows.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "cehttps.h"

#define CH_DEFAULT_TIMEOUT   30000
#define CH_DEFAULT_MAX_RESP  (8 * 1024 * 1024)
#define CH_SLICE_MS          250
#define CH_SESSIONS          8

#ifdef _WIN32
typedef int ch_socklen;
#define CH_WOULDBLOCK(e) ((e) == WSAEWOULDBLOCK)
#else
typedef socklen_t ch_socklen;
#define CH_WOULDBLOCK(e) ((e) == WSAEWOULDBLOCK || (e) == EAGAIN)
#endif

/* ======================================================================= */
/*  Globals (all guarded by g_lock unless noted)                           */
/* ======================================================================= */

static CRITICAL_SECTION g_lock;          /* ctx, settings, stats, init error */
static CRITICAL_SECTION g_sessLock;      /* session cache                    */
static CRITICAL_SECTION g_dnsLock;       /* gethostbyname is not re-entrant  */
static int              g_globalsReady = 0;

static WOLFSSL_CTX* g_ctx = NULL;
static int          g_wolfReady = 0, g_wsaReady = 0;
static char         g_initErr[256];
static char         g_userAgent[128] = "CeHttps/1.0";
static HANDLE       g_slots = NULL;      /* semaphore: concurrent requests   */
static int          g_maxConcurrent = 4;

static int g_caOk = 0, g_caFail = 0, g_caDateFail = 0, g_caErr1 = 0;

static struct { char host[128]; int port; WOLFSSL_SESSION* sess; } g_sess[CH_SESSIONS];
static int g_sessNext = 0;

static void globals_init(void)
{
    if (g_globalsReady) return;
    InitializeCriticalSection(&g_lock);
    InitializeCriticalSection(&g_sessLock);
    InitializeCriticalSection(&g_dnsLock);
    g_slots = CreateSemaphore(NULL, g_maxConcurrent, 16, NULL);
    g_globalsReady = 1;
}

#if defined(_WIN32_WCE)
BOOL WINAPI DllMain(HANDLE module, DWORD reason, LPVOID reserved)
{
    (void)module; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) globals_init();
    return TRUE;
}
#else
/* Non-CE builds (tests): initialise on load. */
__attribute__((constructor)) static void ch_ctor(void) { globals_init(); }
#endif

/* ======================================================================= */
/*  Request object                                                         */
/* ======================================================================= */

struct ch_request {
    /* input */
    char*          method;
    char           host[256];
    int            port;
    char*          path;
    char*          headers;      /* extra header lines, each ending "\r\n" */
    int            headersLen;
    unsigned char* body;
    int            bodyLen;
    int            timeoutMs;
    int            maxResponse;

    /* run state */
    volatile LONG  state;
    volatile LONG  cancelled;
    DWORD          deadline;     /* GetTickCount() value */
    SOCKET         sock;
    HANDLE         thread;
    DWORD          threadId;
    HANDLE         doneEvent;    /* set when the result is ready       */
    HANDLE         finishEvent;  /* set after callback / PostMessage   */
    volatile LONG  freeInCallback;
    ch_callback    callback;
    void*          user;
    HWND           hwnd;
    UINT           msg;

    /* result */
    int            code;
    int            tlsCode;
    char           error[256];
    int            status;
    char*          resp;         /* whole raw response, then body only */
    int            respLen;
    char*          respHeaders;
    int            respHeadersLen;
    int            tDns, tConnect, tTls, tResponse, resumed;
};

/* Atomic read of a LONG written with Interlocked* by another thread. */
static LONG atomic_read(volatile LONG* p)
{
    return InterlockedCompareExchange((LONG*)p, -12345, -12345);   /* never matches: no write */
}

static char* dup_str(const char* s)
{
    size_t n;
    char* d;
    if (s == NULL) return NULL;
    n = strlen(s);
    d = (char*)malloc(n + 1);
    if (d != NULL) memcpy(d, s, n + 1);
    return d;
}

static int lower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

/* "https://host[:port]/path" -> parts. Returns 0 on success. */
static int parse_url(ch_request* r, const char* url)
{
    const char* p;
    const char* hostEnd;
    const char* slash;
    int hostLen;
    static const char scheme[] = "https://";

    if (url == NULL) return -1;
    for (hostLen = 0; scheme[hostLen]; hostLen++)
        if (lower((unsigned char)url[hostLen]) != scheme[hostLen]) return -1;
    p = url + 8;
    slash = strchr(p, '/');
    hostEnd = slash != NULL ? slash : p + strlen(p);

    r->port = 443;
    {
        const char* colon = NULL;
        const char* q;
        for (q = p; q < hostEnd; q++) if (*q == ':') colon = q;
        if (colon != NULL) {
            r->port = atoi(colon + 1);
            if (r->port <= 0 || r->port > 65535) return -1;
            hostEnd = colon;
        }
    }
    hostLen = (int)(hostEnd - p);
    if (hostLen <= 0 || hostLen >= (int)sizeof(r->host)) return -1;
    memcpy(r->host, p, hostLen);
    r->host[hostLen] = '\0';
    r->path = dup_str(slash != NULL ? slash : "/");
    return r->path == NULL ? -1 : 0;
}

ch_request* ch_request_new(const char* method, const char* url)
{
    ch_request* r;
    if (method == NULL || method[0] == '\0') return NULL;
    globals_init();
    r = (ch_request*)calloc(1, sizeof(ch_request));
    if (r == NULL) return NULL;
    r->method = dup_str(method);
    r->sock = INVALID_SOCKET;
    r->timeoutMs = CH_DEFAULT_TIMEOUT;
    r->maxResponse = CH_DEFAULT_MAX_RESP;
    r->doneEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    r->finishEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (r->method == NULL || r->doneEvent == NULL || r->finishEvent == NULL || parse_url(r, url) != 0) {
        ch_request_free(r);
        return NULL;
    }
    return r;
}

int ch_request_add_header(ch_request* r, const char* line)
{
    int n;
    char* grown;
    if (r == NULL || line == NULL) return CH_E_ARGUMENT;
    if (atomic_read(&r->state) != CH_STATE_NEW) return CH_E_STATE;
    n = (int)strlen(line);
    while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == '\n')) n--;
    if (n == 0 || memchr(line, '\n', n) != NULL || memchr(line, '\r', n) != NULL)
        return CH_E_ARGUMENT;                       /* no header injection */
    grown = (char*)realloc(r->headers, r->headersLen + n + 3);
    if (grown == NULL) return CH_E_MEMORY;
    r->headers = grown;
    memcpy(r->headers + r->headersLen, line, n);
    r->headersLen += n;
    r->headers[r->headersLen++] = '\r';
    r->headers[r->headersLen++] = '\n';
    r->headers[r->headersLen] = '\0';
    return CH_OK;
}

int ch_request_set_body(ch_request* r, const unsigned char* body, int len)
{
    if (r == NULL || len < 0 || (len > 0 && body == NULL)) return CH_E_ARGUMENT;
    if (atomic_read(&r->state) != CH_STATE_NEW) return CH_E_STATE;
    free(r->body);
    r->body = NULL;
    r->bodyLen = 0;
    if (len > 0) {
        r->body = (unsigned char*)malloc(len);
        if (r->body == NULL) return CH_E_MEMORY;
        memcpy(r->body, body, len);
        r->bodyLen = len;
    }
    return CH_OK;
}

int ch_request_set_timeout(ch_request* r, int ms)
{
    if (r == NULL || ms <= 0) return CH_E_ARGUMENT;
    if (atomic_read(&r->state) != CH_STATE_NEW) return CH_E_STATE;
    r->timeoutMs = ms;
    return CH_OK;
}

int ch_request_set_max_response(ch_request* r, int bytes)
{
    if (r == NULL || bytes <= 0) return CH_E_ARGUMENT;
    if (atomic_read(&r->state) != CH_STATE_NEW) return CH_E_STATE;
    r->maxResponse = bytes;
    return CH_OK;
}

/* ======================================================================= */
/*  Errors                                                                 */
/* ======================================================================= */

static void fail(ch_request* r, int code, const char* msg, int detail)
{
    r->code = code;
    memset(r->error, 0, sizeof(r->error));
    if (detail != 0) _snprintf(r->error, sizeof(r->error) - 1, "%s (%d)", msg, detail);
    else             _snprintf(r->error, sizeof(r->error) - 1, "%s", msg);
}

static const char* tls_friendly(int e)
{
    switch (e) {
    case ASN_AFTER_DATE_E:
    case ASN_BEFORE_DATE_E:
        return "certificate date invalid - check the device date/time";
    case ASN_NO_SIGNER_E:
        return g_caDateFail > 0 ? "root certificates were rejected - check the device date/time, then ch_init again"
                                : "no trusted root for this server - update cacert.pem";
    case DOMAIN_NAME_MISMATCH:
        return "certificate does not match the host name";
    default:
        return NULL;
    }
}

static void fail_tls(ch_request* r, int code, const char* what, int e)
{
    const char* f = tls_friendly(e);
    char buf[80];
    r->code = code;
    r->tlsCode = e;
    memset(r->error, 0, sizeof(r->error));
    if (f == NULL) {
        memset(buf, 0, sizeof(buf));
        wolfSSL_ERR_error_string_n((unsigned long)e, buf, sizeof(buf) - 1);
        f = buf;
    }
    _snprintf(r->error, sizeof(r->error) - 1, "%s: %s (%d)", what, f, e);
}

/* ======================================================================= */
/*  Time / waiting helpers                                                 */
/* ======================================================================= */

static int remaining_ms(ch_request* r)
{
    return (int)(r->deadline - GetTickCount());     /* wraps correctly */
}

/* Wait until the socket is readable/writable, the deadline passes, or the
   request is cancelled. Returns 1 ready, 0 timeout, -1 cancelled, -2 error. */
static int wait_socket(ch_request* r, int forWrite)
{
    for (;;) {
        fd_set fds, efds;
        struct timeval tv;
        int left, slice, n;

        if (atomic_read(&r->cancelled)) return -1;
        left = remaining_ms(r);
        if (left <= 0) return 0;
        slice = left < CH_SLICE_MS ? left : CH_SLICE_MS;
        FD_ZERO(&fds);
        FD_SET(r->sock, &fds);
        FD_ZERO(&efds);
        FD_SET(r->sock, &efds);
        tv.tv_sec = slice / 1000;
        tv.tv_usec = (slice % 1000) * 1000;
        n = select((int)r->sock + 1, forWrite ? NULL : &fds, forWrite ? &fds : NULL, &efds, &tv);
        if (n < 0) return -2;
        if (n > 0) return FD_ISSET(r->sock, &efds) && !FD_ISSET(r->sock, &fds) ? -2 : 1;
    }
}

/* wolfSSL I/O callbacks: every byte goes through wait_socket. */
static int io_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    ch_request* r = (ch_request*)ctx;
    int w, n;
    (void)ssl;
    for (;;) {
        w = wait_socket(r, 0);
        if (w == 0) return WOLFSSL_CBIO_ERR_TIMEOUT;
        if (w < 0) return WOLFSSL_CBIO_ERR_GENERAL;
        n = recv(r->sock, buf, sz, 0);
        if (n > 0) return n;
        if (n == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        if (!CH_WOULDBLOCK(WSAGetLastError())) return WOLFSSL_CBIO_ERR_CONN_RST;
    }
}

static int io_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    ch_request* r = (ch_request*)ctx;
    int w, n;
    (void)ssl;
    for (;;) {
        w = wait_socket(r, 1);
        if (w == 0) return WOLFSSL_CBIO_ERR_TIMEOUT;
        if (w < 0) return WOLFSSL_CBIO_ERR_GENERAL;
        n = send(r->sock, buf, sz, 0);
        if (n >= 0) return n;
        if (!CH_WOULDBLOCK(WSAGetLastError())) return WOLFSSL_CBIO_ERR_CONN_RST;
    }
}

/* After an I/O failure: was it our deadline or a cancel? */
static void fail_io(ch_request* r, const char* what, int tlsErr)
{
    if (atomic_read(&r->cancelled)) fail(r, CH_E_CANCELLED, "cancelled", 0);
    else if (remaining_ms(r) <= 0) fail(r, CH_E_TIMEOUT, "timed out", 0);
    else                           fail_tls(r, CH_E_IO, what, tlsErr);
}

/* ======================================================================= */
/*  Shared TLS context                                                     */
/* ======================================================================= */

static WOLFSSL_CTX* ctx_acquire(void)
{
    WOLFSSL_CTX* c;
    EnterCriticalSection(&g_lock);
    c = g_ctx;
    if (c != NULL && wolfSSL_CTX_up_ref(c) != WOLFSSL_SUCCESS) c = NULL;
    LeaveCriticalSection(&g_lock);
    return c;
}

static void ctx_release(WOLFSSL_CTX* c)
{
    if (c != NULL) wolfSSL_CTX_free(c);   /* drops our reference */
}

/* ---- session cache ---------------------------------------------------- */

/* Returns a private copy of the cached session for host:port (or NULL). The
   caller passes it to wolfSSL_set_session and frees it after wolfSSL_free:
   session objects are never shared between threads. */
static WOLFSSL_SESSION* sess_copy(const char* host, int port)
{
    int i;
    WOLFSSL_SESSION* copy = NULL;
    EnterCriticalSection(&g_sessLock);
    for (i = 0; i < CH_SESSIONS; i++)
        if (g_sess[i].sess != NULL && g_sess[i].port == port && strcmp(g_sess[i].host, host) == 0) {
            copy = wolfSSL_SESSION_dup(g_sess[i].sess);
            break;
        }
    LeaveCriticalSection(&g_sessLock);
    return copy;
}

/* Stores a copy of ssl's session (taken while ssl is still alive). */
static void sess_store(const char* host, int port, WOLFSSL* ssl)
{
    int i, slot = -1;
    WOLFSSL_SESSION* live;
    WOLFSSL_SESSION* sess;
    if (strlen(host) >= sizeof(g_sess[0].host)) return;
    live = wolfSSL_get1_session(ssl);
    if (live == NULL) return;
    sess = wolfSSL_SESSION_dup(live);
    wolfSSL_SESSION_free(live);
    if (sess == NULL) return;
    EnterCriticalSection(&g_sessLock);
    for (i = 0; i < CH_SESSIONS; i++)
        if (g_sess[i].sess != NULL && g_sess[i].port == port && strcmp(g_sess[i].host, host) == 0) { slot = i; break; }
    if (slot < 0) { slot = g_sessNext; g_sessNext = (g_sessNext + 1) % CH_SESSIONS; }
    if (g_sess[slot].sess != NULL) wolfSSL_SESSION_free(g_sess[slot].sess);
    strcpy(g_sess[slot].host, host);
    g_sess[slot].port = port;
    g_sess[slot].sess = sess;
    LeaveCriticalSection(&g_sessLock);
}

static void sess_clear(void)
{
    int i;
    EnterCriticalSection(&g_sessLock);
    for (i = 0; i < CH_SESSIONS; i++) {
        if (g_sess[i].sess != NULL) wolfSSL_SESSION_free(g_sess[i].sess);
        g_sess[i].sess = NULL;
        g_sess[i].host[0] = '\0';
    }
    LeaveCriticalSection(&g_sessLock);
}

/* ---- init ------------------------------------------------------------- */

static int load_roots(WOLFSSL_CTX* c, const unsigned char* pem, int len,
                      int* ok, int* bad, int* dateBad, int* err1)
{
    static const char B[] = "-----BEGIN CERTIFICATE-----";
    static const char E[] = "-----END CERTIFICATE-----";
    const int bl = (int)sizeof(B) - 1, el = (int)sizeof(E) - 1;
    int i = 0;

    *ok = *bad = *dateBad = *err1 = 0;
    while (i + bl <= len) {
        int start, end, ret;
        if (memcmp(pem + i, B, bl) != 0) { i++; continue; }
        start = i;
        end = start + bl;
        while (end + el <= len && memcmp(pem + end, E, el) != 0) end++;
        if (end + el > len) break;
        end += el;
        ret = wolfSSL_CTX_load_verify_buffer(c, pem + start, end - start, WOLFSSL_FILETYPE_PEM);
        if (ret == WOLFSSL_SUCCESS) (*ok)++;
        else {
            (*bad)++;
            if (ret == ASN_BEFORE_DATE_E || ret == ASN_AFTER_DATE_E) (*dateBad)++;
            if (*err1 == 0) *err1 = ret;
        }
        i = end;
    }
    return *ok;
}

int ch_init(const unsigned char* caPem, int caLen)
{
    WOLFSSL_CTX* c;
    WOLFSSL_CTX* old;
    int ok, bad, dateBad, err1;
    WSADATA wsa;

    globals_init();
    if (caPem == NULL || caLen <= 0) return CH_E_ARGUMENT;

    EnterCriticalSection(&g_lock);
    if (!g_wsaReady) {
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            _snprintf(g_initErr, sizeof(g_initErr) - 1, "WSAStartup failed (%d)", WSAGetLastError());
            LeaveCriticalSection(&g_lock);
            return CH_E_NOT_READY;
        }
        g_wsaReady = 1;
    }
    if (!g_wolfReady) {
        if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
            _snprintf(g_initErr, sizeof(g_initErr) - 1, "wolfSSL_Init failed");
            LeaveCriticalSection(&g_lock);
            return CH_E_NOT_READY;
        }
        g_wolfReady = 1;
    }
    LeaveCriticalSection(&g_lock);

    /* Build the new context outside the lock: loading roots takes seconds. */
    c = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (c == NULL) {
        EnterCriticalSection(&g_lock);
        _snprintf(g_initErr, sizeof(g_initErr) - 1, "wolfSSL_CTX_new failed");
        LeaveCriticalSection(&g_lock);
        return CH_E_MEMORY;
    }
    wolfSSL_CTX_SetMinVersion(c, WOLFSSL_TLSV1_2);
    wolfSSL_CTX_set_verify(c, WOLFSSL_VERIFY_PEER, NULL);
    wolfSSL_CTX_SetIORecv(c, io_recv);
    wolfSSL_CTX_SetIOSend(c, io_send);
    load_roots(c, caPem, caLen, &ok, &bad, &dateBad, &err1);

    EnterCriticalSection(&g_lock);
    g_caOk = ok; g_caFail = bad; g_caDateFail = dateBad; g_caErr1 = err1;
    if (ok == 0) {
        memset(g_initErr, 0, sizeof(g_initErr));
        if (dateBad > 0)
            _snprintf(g_initErr, sizeof(g_initErr) - 1,
                "all root certificates rejected as expired/not yet valid - check the device date/time (%d)", err1);
        else
            _snprintf(g_initErr, sizeof(g_initErr) - 1,
                "no root certificates loaded (%d failed, first error %d)", bad, err1);
        LeaveCriticalSection(&g_lock);
        wolfSSL_CTX_free(c);
        return CH_E_NOT_READY;
    }
    old = g_ctx;
    g_ctx = c;
    g_initErr[0] = '\0';
    LeaveCriticalSection(&g_lock);

    sess_clear();                 /* sessions belong to the old root set */
    if (old != NULL) wolfSSL_CTX_free(old);   /* freed once running requests drop it */
    return CH_OK;
}

int ch_init_error(char* buf, int cap)
{
    int n;
    if (buf == NULL || cap <= 0) return 0;
    globals_init();
    EnterCriticalSection(&g_lock);
    n = (int)strlen(g_initErr);
    if (n > cap - 1) n = cap - 1;
    memcpy(buf, g_initErr, n);
    buf[n] = '\0';
    LeaveCriticalSection(&g_lock);
    return n;
}

int ch_root_stats(int* loaded, int* rejected, int* dateRejected)
{
    globals_init();
    EnterCriticalSection(&g_lock);
    if (loaded) *loaded = g_caOk;
    if (rejected) *rejected = g_caFail;
    if (dateRejected) *dateRejected = g_caDateFail;
    LeaveCriticalSection(&g_lock);
    return CH_OK;
}

int ch_info(char* buf, int cap)
{
    SYSTEMTIME st;
    long t;
    int n, ok, bad, dateBad, err1;
    if (buf == NULL || cap <= 0) return 0;
    globals_init();
    EnterCriticalSection(&g_lock);
    ok = g_caOk; bad = g_caFail; dateBad = g_caDateFail; err1 = g_caErr1;
    LeaveCriticalSection(&g_lock);
    GetSystemTime(&st);
    t = (long)XTIME(NULL);
    n = _snprintf(buf, cap - 1,
        "Roots loaded: %d, rejected: %d, date-rejected: %d (first error %d)\r\n"
        "Device clock (UTC): %04d-%02d-%02d %02d:%02d\r\n"
        "TLS clock: %ld",
        ok, bad, dateBad, err1, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, t);
    if (n < 0) n = cap - 1;
    buf[n] = '\0';
    return n;
}

int ch_set_user_agent(const char* ua)
{
    int n;
    if (ua == NULL) return CH_E_ARGUMENT;
    n = (int)strlen(ua);
    if (n == 0 || n >= (int)sizeof(g_userAgent) || strchr(ua, '\r') || strchr(ua, '\n')) return CH_E_ARGUMENT;
    globals_init();
    EnterCriticalSection(&g_lock);
    memcpy(g_userAgent, ua, n + 1);
    LeaveCriticalSection(&g_lock);
    return CH_OK;
}

int ch_set_max_concurrent(int count)
{
    HANDLE fresh;
    if (count < 1 || count > 16) return CH_E_ARGUMENT;
    globals_init();
    fresh = CreateSemaphore(NULL, count, 16, NULL);
    if (fresh == NULL) return CH_E_MEMORY;
    EnterCriticalSection(&g_lock);
    /* Requests holding a slot of the old semaphore release it there; it is
       simply left alive (a handful of bytes) rather than risk a race. */
    g_slots = fresh;
    g_maxConcurrent = count;
    LeaveCriticalSection(&g_lock);
    return CH_OK;
}

int ch_sha256(const unsigned char* data, int len, unsigned char* out32)
{
    if ((data == NULL && len > 0) || len < 0 || out32 == NULL) return CH_E_ARGUMENT;
    return wc_Sha256Hash(data, (word32)len, out32) == 0 ? CH_OK : CH_E_ARGUMENT;
}

void ch_cleanup(void)
{
    WOLFSSL_CTX* old;
    globals_init();
    sess_clear();
    EnterCriticalSection(&g_lock);
    old = g_ctx;
    g_ctx = NULL;
    LeaveCriticalSection(&g_lock);
    if (old != NULL) wolfSSL_CTX_free(old);
    EnterCriticalSection(&g_lock);
    if (g_wolfReady) { wolfSSL_Cleanup(); g_wolfReady = 0; }
    if (g_wsaReady) { WSACleanup(); g_wsaReady = 0; }
    LeaveCriticalSection(&g_lock);
}

/* ======================================================================= */
/*  HTTP                                                                   */
/* ======================================================================= */

static int header_value(const char* p, int n, const char* name)
{
    int k = (int)strlen(name), i;
    if (n <= k || p[k] != ':') return -1;
    for (i = 0; i < k; i++)
        if (lower((unsigned char)p[i]) != lower((unsigned char)name[i])) return -1;
    i = k + 1;
    while (i < n && (p[i] == ' ' || p[i] == '\t')) i++;
    return i;
}

static int contains_ci(const char* p, int n, const char* word)
{
    int k = (int)strlen(word), i, j;
    for (i = 0; i + k <= n; i++) {
        for (j = 0; j < k && lower((unsigned char)p[i + j]) == lower((unsigned char)word[j]); j++) ;
        if (j == k) return 1;
    }
    return 0;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c = lower(c);
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Decode a chunked body in place; returns the new length or -1. With
   partialOk, a body that simply ends early returns -2 (need more data). */
static int dechunk(char* b, int len, int partialOk)
{
    int r = 0, w = 0;
    for (;;) {
        long sz = 0;
        int digits = 0, v;
        while (r < len && (v = hexval((unsigned char)b[r])) >= 0) { sz = sz * 16 + v; r++; digits++; }
        if (r >= len) return partialOk ? -2 : -1;
        if (digits == 0) return -1;
        while (r < len && b[r] != '\n') r++;
        if (r >= len) return partialOk ? -2 : -1;
        r++;
        if (sz == 0) return w;
        if (sz > len - r) return partialOk ? -2 : -1;
        if (!partialOk) memmove(b + w, b + r, (size_t)sz);
        w += (int)sz;
        r += (int)sz;
        if (r < len && b[r] == '\r') r++;
        if (r < len && b[r] == '\n') r++;
    }
}

/* Find the end of the headers. */
static int find_header_end(const char* b, int len)
{
    int i;
    for (i = 0; i + 3 < len; i++)
        if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n') return i + 4;
    return -1;
}

static void scan_headers(const char* b, int hdrEnd, int* chunked, long* contentLength)
{
    int i = 0;
    *chunked = 0;
    *contentLength = -1;
    while (i < hdrEnd && b[i] != '\n') i++;
    i++;
    while (i < hdrEnd - 2) {
        int start = i, n, v;
        while (i < hdrEnd && b[i] != '\r' && b[i] != '\n') i++;
        n = i - start;
        if ((v = header_value(b + start, n, "transfer-encoding")) >= 0 && contains_ci(b + start + v, n - v, "chunked"))
            *chunked = 1;
        if ((v = header_value(b + start, n, "content-length")) >= 0)
            *contentLength = atol(b + start + v);
        while (i < hdrEnd && (b[i] == '\r' || b[i] == '\n')) i++;
    }
}

/* Is the response complete (so we needn't wait for the server to close)? */
static int response_complete(ch_request* r, int total)
{
    int hdrEnd, chunked;
    long clen;
    hdrEnd = find_header_end(r->resp, total);
    if (hdrEnd < 0) return 0;
    scan_headers(r->resp, hdrEnd, &chunked, &clen);
    if (strcmp(r->method, "HEAD") == 0) return 1;
    if (chunked) return dechunk(r->resp + hdrEnd, total - hdrEnd, 1) >= 0;
    if (clen >= 0) return total - hdrEnd >= clen;
    return 0;
}

static int grow(ch_request* r, int* cap, int needed)
{
    int newCap;
    char* p;
    if (needed <= *cap) return 1;
    newCap = *cap * 2;
    while (newCap < needed) newCap *= 2;
    p = (char*)realloc(r->resp, newCap + 1);
    if (p == NULL) return 0;
    r->resp = p;
    *cap = newCap;
    return 1;
}

/* The whole request, on the calling thread. Fills in the result fields. */
static void perform(ch_request* r)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_SESSION* resumeFrom = NULL;
    struct sockaddr_in sa;
    char ua[128];
    char* reqHead = NULL;
    int reqLen, total = 0, cap = 16 * 1024, n, err, hdrEnd, chunked;
    long clen;
    DWORD t0, t1;
    HANDLE slots;
    unsigned long nonBlocking;

    r->deadline = GetTickCount() + (DWORD)r->timeoutMs;

    /* wait for a free slot (honouring cancel and the deadline) */
    EnterCriticalSection(&g_lock);
    slots = g_slots;
    memcpy(ua, g_userAgent, sizeof(ua));
    LeaveCriticalSection(&g_lock);
    for (;;) {
        if (atomic_read(&r->cancelled)) { fail(r, CH_E_CANCELLED, "cancelled", 0); return; }
        if (remaining_ms(r) <= 0) { fail(r, CH_E_TIMEOUT, "timed out waiting for a free connection slot", 0); return; }
        if (WaitForSingleObject(slots, CH_SLICE_MS) == WAIT_OBJECT_0) break;
    }

    ctx = ctx_acquire();
    if (ctx == NULL) { fail(r, CH_E_NOT_READY, "ch_init has not succeeded", 0); goto done; }

    /* DNS */
    t0 = GetTickCount();
    {
        struct hostent* he;
        int ok = 0;
        memset(&sa, 0, sizeof(sa));
        EnterCriticalSection(&g_dnsLock);
        he = gethostbyname(r->host);
        if (he != NULL && he->h_addr_list[0] != NULL && he->h_length == 4) {
            memcpy(&sa.sin_addr, he->h_addr_list[0], 4);
            ok = 1;
        }
        LeaveCriticalSection(&g_dnsLock);
        if (!ok) { fail(r, CH_E_DNS, "DNS lookup failed", WSAGetLastError()); goto done; }
    }
    t1 = GetTickCount(); r->tDns = (int)(t1 - t0); t0 = t1;

    /* connect, non-blocking so the deadline and cancel apply */
    r->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (r->sock == INVALID_SOCKET) { fail(r, CH_E_CONNECT, "socket() failed", WSAGetLastError()); goto done; }
    sa.sin_family = AF_INET;
    sa.sin_port = htons((u_short)r->port);
    nonBlocking = 1;
    ioctlsocket(r->sock, FIONBIO, &nonBlocking);
    if (connect(r->sock, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        int e = WSAGetLastError(), w, soErr = 0;
        ch_socklen len = sizeof(soErr);
        if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS) { fail(r, CH_E_CONNECT, "connect() failed", e); goto done; }
        w = wait_socket(r, 1);
        if (w == -1) { fail(r, CH_E_CANCELLED, "cancelled", 0); goto done; }
        if (w == 0) { fail(r, CH_E_TIMEOUT, "connect timed out", 0); goto done; }
        getsockopt(r->sock, SOL_SOCKET, SO_ERROR, (char*)&soErr, &len);
        if (w < 0 || soErr != 0) { fail(r, CH_E_CONNECT, "connect() failed", soErr); goto done; }
    }
    t1 = GetTickCount(); r->tConnect = (int)(t1 - t0); t0 = t1;

    /* TLS */
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) { fail(r, CH_E_MEMORY, "wolfSSL_new failed", 0); goto done; }
    wolfSSL_SetIOReadCtx(ssl, r);
    wolfSSL_SetIOWriteCtx(ssl, r);
    wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, r->host, (word16)strlen(r->host));
    wolfSSL_check_domain_name(ssl, r->host);
    resumeFrom = sess_copy(r->host, r->port);
    if (resumeFrom != NULL) wolfSSL_set_session(ssl, resumeFrom);
    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, 0);
        if (atomic_read(&r->cancelled) || remaining_ms(r) <= 0) fail_io(r, "TLS handshake failed", err);
        else fail_tls(r, CH_E_TLS, "TLS handshake failed", err);
        goto done;
    }
    r->resumed = wolfSSL_session_reused(ssl);
    t1 = GetTickCount(); r->tTls = (int)(t1 - t0); t0 = t1;

    /* request */
    reqHead = (char*)malloc(strlen(r->method) + strlen(r->path) + strlen(r->host) + strlen(ua) +
                            r->headersLen + 200);
    if (reqHead == NULL) { fail(r, CH_E_MEMORY, "out of memory", 0); goto done; }
    {
        char hostPort[300];
        if (r->port == 443) _snprintf(hostPort, sizeof(hostPort) - 1, "%s", r->host);
        else                _snprintf(hostPort, sizeof(hostPort) - 1, "%s:%d", r->host, r->port);
        hostPort[sizeof(hostPort) - 1] = '\0';
        reqLen = sprintf(reqHead,
            "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
            r->method, r->path, hostPort, ua);
        if (r->headersLen > 0) { memcpy(reqHead + reqLen, r->headers, r->headersLen); reqLen += r->headersLen; }
        if (r->bodyLen > 0 || strcmp(r->method, "POST") == 0 || strcmp(r->method, "PUT") == 0 ||
            strcmp(r->method, "PATCH") == 0)
            reqLen += sprintf(reqHead + reqLen, "Content-Length: %d\r\n", r->bodyLen);
        reqHead[reqLen++] = '\r';
        reqHead[reqLen++] = '\n';
    }
    if (wolfSSL_write(ssl, reqHead, reqLen) != reqLen ||
        (r->bodyLen > 0 && wolfSSL_write(ssl, r->body, r->bodyLen) != r->bodyLen)) {
        fail_io(r, "sending the request failed", wolfSSL_get_error(ssl, 0));
        goto done;
    }

    /* response */
    r->resp = (char*)malloc(cap + 1);
    if (r->resp == NULL) { fail(r, CH_E_MEMORY, "out of memory", 0); goto done; }
    for (;;) {
        if (total >= cap && !grow(r, &cap, total + 16 * 1024)) { fail(r, CH_E_MEMORY, "out of memory", 0); goto done; }
        n = wolfSSL_read(ssl, r->resp + total, cap - total);
        if (n > 0) {
            total += n;
            if (total > r->maxResponse + 64 * 1024) { fail(r, CH_E_TOO_LARGE, "response larger than the limit", r->maxResponse); goto done; }
            if (response_complete(r, total)) break;
            continue;
        }
        err = wolfSSL_get_error(ssl, n);
        if (n == 0 || err == WOLFSSL_ERROR_ZERO_RETURN || err == SOCKET_PEER_CLOSED_E) break;
        if (total > 0 && !atomic_read(&r->cancelled) && remaining_ms(r) > 0 && response_complete(r, total)) break;
        fail_io(r, "receiving the response failed", err);
        goto done;
    }
    t1 = GetTickCount(); r->tResponse = (int)(t1 - t0);

    sess_store(r->host, r->port, ssl);

    /* parse */
    if (total < 12 || memcmp(r->resp, "HTTP/", 5) != 0) { fail(r, CH_E_HTTP, "not an HTTP response", total); goto done; }
    {
        int i;
        for (i = 5; i < total && r->resp[i] != ' '; i++) ;
        r->status = atoi(r->resp + i + 1);
    }
    hdrEnd = find_header_end(r->resp, total);
    if (hdrEnd < 0) { fail(r, CH_E_HTTP, "no end of HTTP headers", total); goto done; }
    scan_headers(r->resp, hdrEnd, &chunked, &clen);
    {
        int lineEnd = 0;
        while (lineEnd < hdrEnd && r->resp[lineEnd] != '\n') lineEnd++;
        lineEnd++;
        r->respHeadersLen = hdrEnd - 2 - lineEnd;
        if (r->respHeadersLen < 0) r->respHeadersLen = 0;
        r->respHeaders = (char*)malloc(r->respHeadersLen + 1);
        if (r->respHeaders == NULL) { fail(r, CH_E_MEMORY, "out of memory", 0); goto done; }
        memcpy(r->respHeaders, r->resp + lineEnd, r->respHeadersLen);
        r->respHeaders[r->respHeadersLen] = '\0';
    }
    r->respLen = total - hdrEnd;
    memmove(r->resp, r->resp + hdrEnd, r->respLen);
    if (chunked) {
        r->respLen = dechunk(r->resp, r->respLen, 0);
        if (r->respLen < 0) { r->respLen = 0; fail(r, CH_E_HTTP, "bad chunked encoding", 0); goto done; }
    } else if (clen >= 0 && r->respLen > clen) {
        r->respLen = (int)clen;
    }
    if (r->respLen > r->maxResponse) { r->respLen = 0; fail(r, CH_E_TOO_LARGE, "response larger than the limit", r->maxResponse); goto done; }
    r->resp[r->respLen] = '\0';
    r->code = CH_OK;

done:
    if (ssl != NULL) {
        if (r->code == CH_OK) wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }
    if (resumeFrom != NULL) wolfSSL_SESSION_free(resumeFrom);
    if (r->sock != INVALID_SOCKET) { closesocket(r->sock); r->sock = INVALID_SOCKET; }
    free(reqHead);
    ctx_release(ctx);
    if (r->code != CH_OK) r->respLen = 0;
    ReleaseSemaphore(slots, 1, NULL);
}

/* ======================================================================= */
/*  Running                                                                */
/* ======================================================================= */

static int begin(ch_request* r)
{
    if (r == NULL) return CH_E_ARGUMENT;
    if (InterlockedCompareExchange((LONG*)&r->state, CH_STATE_RUNNING, CH_STATE_NEW) != CH_STATE_NEW)
        return CH_E_STATE;
    r->code = CH_E_IO;      /* until proven otherwise */
    return CH_OK;
}

int ch_request_run(ch_request* r)
{
    int rc = begin(r);
    if (rc != CH_OK) return rc;
    r->threadId = GetCurrentThreadId();
    perform(r);
    InterlockedExchange((LONG*)&r->state, CH_STATE_DONE);
    SetEvent(r->doneEvent);
    SetEvent(r->finishEvent);
    return r->code;
}

static void destroy(ch_request* r);

static DWORD WINAPI worker(LPVOID arg)
{
    ch_request* r = (ch_request*)arg;
    r->threadId = GetCurrentThreadId();     /* before any callback can call free */
    perform(r);
    InterlockedExchange((LONG*)&r->state, CH_STATE_DONE);
    SetEvent(r->doneEvent);
    if (r->callback != NULL) r->callback(r, r->user);
    /* r may have been freed by the callback only via freeInCallback */
    if (atomic_read(&r->freeInCallback)) { destroy(r); return 0; }
    if (r->hwnd != NULL) PostMessage(r->hwnd, r->msg, (WPARAM)r, 0);
    SetEvent(r->finishEvent);
    return 0;
}

int ch_request_start(ch_request* r, ch_callback callback, void* user, void* hwnd, unsigned int msg)
{
    int rc = begin(r);
    if (rc != CH_OK) return rc;
    r->callback = callback;
    r->user = user;
    r->hwnd = (HWND)hwnd;
    r->msg = msg;
    r->thread = CreateThread(NULL, 0, worker, r, 0, &r->threadId);
    if (r->thread == NULL) {
        fail(r, CH_E_MEMORY, "could not start a thread", (int)GetLastError());
        InterlockedExchange((LONG*)&r->state, CH_STATE_DONE);
        SetEvent(r->doneEvent);
        SetEvent(r->finishEvent);
        return CH_E_MEMORY;
    }
    return CH_OK;
}

int ch_request_wait(ch_request* r, int timeoutMs)
{
    if (r == NULL) return CH_E_ARGUMENT;
    if (atomic_read(&r->state) == CH_STATE_NEW) return CH_E_STATE;
    return WaitForSingleObject(r->doneEvent, timeoutMs < 0 ? INFINITE : (DWORD)timeoutMs) == WAIT_OBJECT_0
        ? CH_OK : CH_E_TIMEOUT;
}

int ch_request_cancel(ch_request* r)
{
    if (r == NULL) return CH_E_ARGUMENT;
    InterlockedExchange((LONG*)&r->cancelled, 1);
    return CH_OK;
}

int ch_request_state(ch_request* r)
{
    return r == NULL ? CH_E_ARGUMENT : (int)atomic_read(&r->state);
}

static void destroy(ch_request* r)
{
    if (r->thread != NULL) CloseHandle(r->thread);
    if (r->doneEvent != NULL) CloseHandle(r->doneEvent);
    if (r->finishEvent != NULL) CloseHandle(r->finishEvent);
    free(r->method);
    free(r->path);
    free(r->headers);
    free(r->body);
    free(r->resp);
    free(r->respHeaders);
    free(r);
}

void ch_request_free(ch_request* r)
{
    if (r == NULL) return;
    if (atomic_read(&r->state) != CH_STATE_NEW) {
        if (r->thread != NULL && GetCurrentThreadId() == r->threadId) {   /* inside its own callback */
            InterlockedExchange((LONG*)&r->freeInCallback, 1);
            return;
        }
        ch_request_cancel(r);
        WaitForSingleObject(r->finishEvent, INFINITE);    /* run() or worker is finished with r */
        if (r->thread != NULL) WaitForSingleObject(r->thread, INFINITE);
    }
    destroy(r);
}

/* ======================================================================= */
/*  Results                                                                */
/* ======================================================================= */

static int done(ch_request* r) { return r != NULL && atomic_read(&r->state) == CH_STATE_DONE; }

int ch_result_code(ch_request* r)      { return done(r) ? r->code : (r == NULL ? CH_E_ARGUMENT : CH_E_STATE); }
int ch_result_tls_code(ch_request* r)  { return done(r) ? r->tlsCode : 0; }
int ch_response_status(ch_request* r)  { return done(r) ? r->status : 0; }
int ch_response_body_len(ch_request* r){ return done(r) && r->code == CH_OK ? r->respLen : 0; }

const unsigned char* ch_response_body(ch_request* r)
{
    return done(r) && r->code == CH_OK && r->resp != NULL ? (const unsigned char*)r->resp : (const unsigned char*)"";
}

static int copy_out(const char* src, int len, char* buf, int cap)
{
    if (buf == NULL || cap <= 0) return len;
    if (len > cap - 1) len = cap - 1;
    if (len > 0) memcpy(buf, src, len);
    buf[len < 0 ? 0 : len] = '\0';
    return len;
}

int ch_result_error(ch_request* r, char* buf, int cap)
{
    if (!done(r)) return copy_out("request not finished", 20, buf, cap);
    return copy_out(r->error, (int)strlen(r->error), buf, cap);
}

int ch_result_timing(ch_request* r, int* dnsMs, int* connectMs, int* tlsMs, int* responseMs, int* resumed)
{
    if (!done(r)) return CH_E_STATE;
    if (dnsMs) *dnsMs = r->tDns;
    if (connectMs) *connectMs = r->tConnect;
    if (tlsMs) *tlsMs = r->tTls;
    if (responseMs) *responseMs = r->tResponse;
    if (resumed) *resumed = r->resumed;
    return CH_OK;
}

int ch_response_copy_body(ch_request* r, unsigned char* buf, int cap)
{
    int n;
    if (!done(r) || r->code != CH_OK || buf == NULL || cap < 0) return 0;
    n = r->respLen < cap ? r->respLen : cap;
    if (n > 0) memcpy(buf, r->resp, n);
    return n;
}

int ch_response_headers(ch_request* r, char* buf, int cap)
{
    if (!done(r) || r->respHeaders == NULL) return copy_out("", 0, buf, cap);
    return copy_out(r->respHeaders, r->respHeadersLen, buf, cap);
}

int ch_response_header(ch_request* r, const char* name, char* buf, int cap)
{
    int i = 0, len;
    if (!done(r) || r->respHeaders == NULL || name == NULL) return -1;
    len = r->respHeadersLen;
    while (i < len) {
        int start = i, n, v;
        while (i < len && r->respHeaders[i] != '\r' && r->respHeaders[i] != '\n') i++;
        n = i - start;
        if ((v = header_value(r->respHeaders + start, n, name)) >= 0)
            return copy_out(r->respHeaders + start + v, n - v, buf, cap);
        while (i < len && (r->respHeaders[i] == '\r' || r->respHeaders[i] == '\n')) i++;
    }
    return -1;
}
