/* cehttps.h - modern HTTPS (TLS 1.2 / 1.3) for Windows Mobile and Windows CE.
 *
 * Copyright (C) 2026 the CeHttps authors.
 * CeHttps is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License version 3 (see LICENSE). It includes
 * wolfSSL, which is also GPLv3.
 *
 * Usage, in short:
 *
 *   ch_init(caPem, caLen);                       // once, with cacert.pem's bytes
 *
 *   ch_request* r = ch_request_new("GET", "https://example.com/");
 *   ch_request_add_header(r, "Accept: application/json");
 *   ch_request_start(r, my_callback, my_data, NULL, 0);   // returns at once
 *   ...
 *   void my_callback(ch_request* r, void* user) {         // on a worker thread
 *       if (ch_result_code(r) == CH_OK) use(ch_response_status(r), ch_response_body(r));
 *       ch_request_free(r);                               // allowed here
 *   }
 *
 * Instead of a callback you can pass a window and a message number: when the
 * request finishes, PostMessage(hwnd, msg, (WPARAM)request, 0) is sent, so the
 * result arrives on your UI thread. Or call ch_request_run() to do it blocking
 * on a thread of your own.
 *
 * Every function is thread-safe. Several requests can run at once (see
 * ch_set_max_concurrent). A request object is used for one request only.
 */
#ifndef CEHTTPS_H
#define CEHTTPS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ch_request ch_request;

/* Called on the request's worker thread when it has finished. */
typedef void (*ch_callback)(ch_request* request, void* user);

/* Result codes (ch_result_code and most function return values). */
#define CH_OK              0
#define CH_E_ARGUMENT     -1   /* bad parameter or URL                          */
#define CH_E_NOT_READY    -2   /* ch_init not called / failed                   */
#define CH_E_STATE        -3   /* request already started                       */
#define CH_E_MEMORY       -4
#define CH_E_DNS          -10
#define CH_E_CONNECT      -11
#define CH_E_TLS          -20  /* handshake failed: see ch_result_tls_code      */
#define CH_E_IO           -30  /* send / receive failed                         */
#define CH_E_TIMEOUT      -31
#define CH_E_CANCELLED    -32
#define CH_E_TOO_LARGE    -33  /* response bigger than the limit                */
#define CH_E_HTTP         -40  /* not a valid HTTP response                     */

/* Request states. */
#define CH_STATE_NEW       0
#define CH_STATE_RUNNING   1
#define CH_STATE_DONE      2

/* ---- library ---------------------------------------------------------- */

/* Load the trusted root certificates (PEM, e.g. curl's cacert.pem). Call again
   to reload them - for example after the device clock was fixed, because roots
   are date-checked when they are loaded. Requests already running keep the old
   set until they finish. Returns CH_OK or a negative code. */
int  ch_init(const unsigned char* caPem, int caLen);

/* Why ch_init failed. */
int  ch_init_error(char* buf, int cap);

/* Roots loaded / rejected by the last ch_init. dateRejected > 0 usually means
   the device clock is wrong. */
int  ch_root_stats(int* loaded, int* rejected, int* dateRejected);

/* One-line-per-item diagnostics: roots and the clock as the TLS code sees it. */
int  ch_info(char* buf, int cap);

/* Default "User-Agent" header (default "CeHttps/1.0"). */
int  ch_set_user_agent(const char* userAgent);

/* How many requests may be on the network at once (default 4, 1..16). Others
   wait their turn. */
int  ch_set_max_concurrent(int count);

/* SHA-256 of data into out32 (32 bytes). */
int  ch_sha256(const unsigned char* data, int len, unsigned char* out32);

/* Free everything. Only call when no request is running. */
void ch_cleanup(void);

/* ---- requests --------------------------------------------------------- */

/* method: "GET", "POST", "PUT", "DELETE", ...   url: "https://host[:port]/path".
   Returns NULL if the arguments are invalid or memory is short. */
ch_request* ch_request_new(const char* method, const char* url);

/* Add a request header line, e.g. "Authorization: Bearer abc". Host,
   User-Agent, Connection and Content-Length are added for you. */
int  ch_request_add_header(ch_request* r, const char* headerLine);

/* Request body (copied). A Content-Length header is sent automatically. */
int  ch_request_set_body(ch_request* r, const unsigned char* body, int len);

/* Whole-request time limit in ms (default 30000). */
int  ch_request_set_timeout(ch_request* r, int ms);

/* Largest response body accepted, in bytes (default 8 MB). */
int  ch_request_set_max_response(ch_request* r, int bytes);

/* Run the request on the calling thread; returns when done (result code). */
int  ch_request_run(ch_request* r);

/* Start the request on a worker thread and return immediately. When it is
   done, `callback(r, user)` is called on the worker thread (if not NULL), then
   PostMessage(hwnd, msg, (WPARAM)r, 0) is sent (if hwnd is not NULL). */
int  ch_request_start(ch_request* r, ch_callback callback, void* user, void* hwnd, unsigned int msg);

/* Wait for a started request. Returns CH_OK when done, CH_E_TIMEOUT if it is
   still running after timeoutMs (-1 = wait forever). */
int  ch_request_wait(ch_request* r, int timeoutMs);

/* Ask a running request to stop; it finishes soon with CH_E_CANCELLED. */
int  ch_request_cancel(ch_request* r);

int  ch_request_state(ch_request* r);

/* Free a request. If it is still running it is cancelled and waited for.
   Safe to call from inside its own callback. */
void ch_request_free(ch_request* r);

/* ---- results (valid once the request is done) ------------------------- */

int  ch_result_code(ch_request* r);           /* CH_OK or a CH_E_* code           */
int  ch_result_tls_code(ch_request* r);       /* wolfSSL error code, if any       */
int  ch_result_error(ch_request* r, char* buf, int cap);   /* readable reason      */
int  ch_result_timing(ch_request* r, int* dnsMs, int* connectMs, int* tlsMs,
                      int* responseMs, int* resumed);

int  ch_response_status(ch_request* r);       /* HTTP status, 0 if none           */
int  ch_response_body_len(ch_request* r);
const unsigned char* ch_response_body(ch_request* r);   /* valid until freed     */
int  ch_response_copy_body(ch_request* r, unsigned char* buf, int cap);
/* All response header lines ("Name: value\r\n" each). Returns the length. */
int  ch_response_headers(ch_request* r, char* buf, int cap);
/* One header's value (case-insensitive name). Returns length, or -1 if absent. */
int  ch_response_header(ch_request* r, const char* name, char* buf, int cap);

#ifdef __cplusplus
}
#endif

#endif /* CEHTTPS_H */
