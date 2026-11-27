# CeHttps

**Modern HTTPS for Windows Mobile and Windows CE.** TLS 1.3 and TLS 1.2 for
.NET Compact Framework 3.5 and native C/C++ apps, on devices whose built-in TLS
stopped at 1.0.

Handhelds such as the Zebra/Motorola MC55, MC65, MC75, MC9090 and MC9190 run
Windows Mobile 6.x, Windows Embedded Handheld 6.5 or Windows CE 5/6. Their
built-in TLS (Microsoft's SChannel) only speaks TLS 1.0. Almost every server
refuses TLS 1.0 today, and no firmware update adds anything newer. As a result,
apps on these devices can no longer reach modern APIs.

CeHttps carries its own TLS stack ([wolfSSL](https://www.wolfssl.com)) and its
own root certificates. It doesn't use the operating system's TLS at all. Add
two files to an app and it can talk to current HTTPS servers again.

> **Tested on:** Zebra MC55A, Windows Embedded Handheld 6.5 Classic (CE 5.2),
> PXA32x 806 MHz. It runs in production there (Book Scout, App Store).
>
> **Should work on:** other ARM devices running Windows Mobile 5/6/6.5 or
> Windows CE 5/6 with .NET CF 3.5 (for the managed API). Not tested on them yet.

---

## At a glance

| | |
|---|---|
| Protocols | TLS 1.3, TLS 1.2 |
| Key exchange | X25519, P-256, P-384, P-521 (ECDHE) |
| Ciphers | AES-128/256-GCM, ChaCha20-Poly1305, AES-CBC with SHA-2 (TLS 1.2) |
| Certificates | RSA up to 4096 bits, ECDSA P-256/P-384, RSA-PSS; SHA-256/384/512 signatures |
| HTTP | HTTP/1.1, any method, custom headers, request bodies, redirects (.NET), chunked and Content-Length responses |
| Threading | Non-blocking and thread-safe; several requests at once |
| APIs | .NET CF 3.5 (`CeHttps.dll`) and C (`cehttps.h`) |
| Size | `CeHttpsNative.dll` ≈ 600 KB, plus `cacert.pem` ≈ 200 KB |
| Licence | GPLv3 (commercial licensing: see [Licence](#licence)) |

---

## Features

### TLS

- **TLS 1.3 and TLS 1.2.** TLS 1.3 is preferred; TLS 1.2 is the fallback for
  servers that don't have 1.3 yet.
- **Full certificate verification, always on.**
  - The server's chain is checked up to a trusted root.
  - The certificate's dates and constraints are checked.
  - The host name must match the certificate.
  - There is no switch to turn any of this off (see [What it doesn't do](#what-it-doesnt-do-and-why)).
- **SNI** (Server Name Indication), which virtually every shared host and CDN
  requires.
- **Cross-signed chains** are accepted (`WOLFSSL_ALT_CERT_CHAINS`), so sites
  behind chains like Let's Encrypt's work.
- **TLS 1.3 session resumption.**
  - Up to 8 recent sessions are kept in memory, one per host and port.
  - A repeat request to the same host skips the expensive certificate work and
    is much faster.
  - Each request gets its own copy of the session, so concurrent requests never
    share TLS state.
- **Extended master secret** and **encrypt-then-MAC** (TLS 1.2 hardening).
- **Timing-attack resistance:** constant-time ECC and big-number code, and RSA
  blinding.
- **Alignment-safe builds.** The XScale (ARMv5) faults on unaligned memory
  access, so wolfSSL's alignment-safe code paths are forced on.

#### Cipher suites

Verified against the compiled library.

| TLS 1.3 | |
|---|---|
| TLS_AES_128_GCM_SHA256 | ✅ |
| TLS_AES_256_GCM_SHA384 | ✅ |
| TLS_CHACHA20_POLY1305_SHA256 | ✅ |

| TLS 1.2 (ECDHE only) | RSA certs | ECDSA certs |
|---|---|---|
| AES_128_GCM_SHA256 | ✅ | ✅ |
| AES_256_GCM_SHA384 | ✅ | ✅ |
| CHACHA20_POLY1305_SHA256 | ✅ | ✅ |
| AES_128_CBC_SHA256 | ✅ | ✅ |
| AES_256_CBC_SHA384 | ✅ | ✅ |
| AES_128_CBC_SHA | ✅ | ✅ |
| AES_256_CBC_SHA | ✅ | ✅ |

The PXA32x has no AES hardware, so ChaCha20-Poly1305 is the fastest cipher on
it. AES-GCM uses a 4-bit table (`GCM_TABLE_4BIT`) as a balance between speed and
memory.

#### Key exchange groups

| Group | |
|---|---|
| X25519 | ✅ |
| NIST P-256 (secp256r1) | ✅ fast path |
| NIST P-384 (secp384r1) | ✅ fast path |
| NIST P-521 (secp521r1) | ✅ (generic math, slower) |
| Brainpool P-256/384/512 r1 | ❌ |

"Fast path" means wolfSSL's optimised fixed-size math (`sp_c32.c`). It makes
ECDHE and signature checks several times faster on an 806 MHz CPU.

#### Certificate signatures

| | |
|---|---|
| RSA PKCS#1 v1.5, 2048–4096 bits | ✅ |
| RSA-PSS | ✅ |
| ECDSA P-256, P-384 | ✅ |
| ECDSA P-521 | ✅ |
| SHA-256, SHA-384, SHA-512 | ✅ |
| SHA-1 | ✅ (for older chains; the other checks still apply) |
| SHA-224, MD5, DSA, Ed25519, Ed448 | ❌ |

### HTTP

- **HTTP/1.1** with any method: GET, POST, PUT, PATCH, DELETE, HEAD, ...
- **Custom request headers.** `Host`, `User-Agent`, `Connection` and
  `Content-Length` are added for you. The User-Agent can be set
  (default `CeHttps/1.0`).
- **Request bodies** of any type, with a `Content-Length` header added
  automatically. The .NET API has helpers for UTF-8 text and JSON.
- **Response bodies:** `Content-Length`, `Transfer-Encoding: chunked`, and
  read-until-close are all handled. `HEAD` requests work too.
- **Response headers**, either as raw lines or looked up by name
  (case-insensitive).
- **Redirects (.NET API)**:
  - 301, 302, 303, 307 and 308, up to 5 hops.
  - 307 and 308 keep the method and body; the others switch to GET, as
    browsers do.
  - Relative `Location` headers are resolved.
- **Response size limit** per request (default 8 MB), so a misbehaving server
  can't exhaust the device's memory.
- **Timings** for every request: DNS, connect, TLS handshake and response, in
  milliseconds, plus whether the session was resumed.

### Concurrency and control

- **Non-blocking.** Requests run on worker threads. You get the result by:
  - a callback, on the worker thread;
  - a window message posted to your UI thread (native);
  - a delegate on your UI thread via `Control.BeginInvoke` (.NET);
  - or the standard .NET `BeginSend`/`EndSend` pattern.
- **Blocking, if you want it.** `ch_request_run` / `Https.Send` on a thread of
  your own.
- **Thread-safe.** Every function can be called from any thread.
- **Concurrency limit.**
  - 4 requests on the network at once by default, adjustable from 1 to 16.
  - Extra requests queue until a slot is free.
  - This protects the device's limited CPU and sockets.
- **Whole-request timeout** per request (default 30 s). It covers DNS, connect,
  handshake, sending and receiving together, not each step separately.
- **Cancellation.** A cancelled request stops within about 250 ms while it is
  connecting, in the handshake, sending or receiving. DNS lookups are the
  exception (see below).
- **Clear errors.** Distinct codes for DNS, connect, TLS, I/O, timeout, cancel,
  too-large and malformed-HTTP failures. TLS failures also give wolfSSL's error
  code and a readable reason.

### Help with device problems

- **Clock checking and fixing.**
  - Certificates are date-checked, and these devices often lose the time when
    the backup battery runs flat.
  - `ClockSync.Sync()` (.NET) sets the clock over SNTP, using pool.ntp.org,
    time.google.com and time.windows.com.
  - `Https.ClockLooksWrong` tells you when the clock is the likely cause of a
    failure.
- **Automatic root reload after a clock fix.**
  - Roots are date-checked when they are loaded. With a wrong clock, valid
    roots get rejected and stay rejected.
  - When a request fails for that reason and the clock now looks right, CeHttps
    reloads the roots and retries once, by itself.
- **Diagnostics.**
  - `ch_root_stats` / `Https.RootStats`: how many roots loaded, were rejected,
    or were rejected because of their dates.
  - `ch_info` / `Https.Diagnostics`: a readable summary.
- **SHA-256 helper**, for checking downloads such as GitHub's release digests.

---

## What it doesn't do, and why

| Missing | Why |
|---|---|
| **TLS 1.0 / 1.1, SSLv3** | Deprecated (RFC 8996) and refused by modern servers. The device's own SChannel still speaks TLS 1.0 if you need it. |
| **3DES, RC4, static-RSA, DHE, DSS and anonymous cipher suites** | Broken, deprecated or without forward secrecy. Classic DH is also slow on this CPU, and ECDHE replaces it. Anonymous suites check no certificate at all. |
| **Brainpool curves** | Essentially unused on the public web and deprecated for TLS 1.3. Easy to add (`HAVE_ECC_BRAINPOOL`) if a specific server needs them. |
| **Turning off certificate checks** | The most common way HTTPS gets silently broken. For a self-signed or private server, add its CA to the PEM you pass to `ch_init`. |
| **`http://` (plain HTTP) URLs** | CeHttps is for HTTPS. A redirect to `http://` fails instead of quietly downgrading. Use the platform's own HTTP classes for plain HTTP. |
| **Revocation checking (OCSP, CRL)** | It would add a network round trip to every handshake and more memory and code. Browsers have largely moved away from live revocation checks. Expiry and short certificate lifetimes limit the risk. |
| **Certificate pinning API** | Not built in yet. Pass a PEM with only your own CA to `ch_init` for a similar effect. |
| **Client certificates (mutual TLS)** | No API yet; wolfSSL supports it, so it can be added if needed. |
| **HTTP/2, HTTP/3, WebSockets** | HTTP/1.1 is what these apps need and is far simpler. HTTP/2's multiplexing matters little at these request rates. Every HTTPS server still accepts HTTP/1.1. |
| **Keep-alive (connection reuse)** | Each request opens a new connection (`Connection: close`). This keeps the engine simple and robust on flaky Wi-Fi. TLS session resumption recovers most of the cost. |
| **gzip / deflate responses** | The request says `Accept-Encoding: identity`, so servers send plain bodies. Decompressing costs CPU and code on an 806 MHz device, and most API responses are small. |
| **Streaming uploads or downloads, progress events** | Bodies are held in memory whole: simpler and safe for API-sized data. The size limit protects memory. Large files need a streaming API that doesn't exist yet. |
| **HTTP proxies** | Not supported yet; requests connect to the server directly. |
| **IPv6** | IPv4 only. These devices' networks are effectively IPv4-only, and CE 5's IPv6 support is limited. |
| **Cookies, auth helpers, caching** | These belong in the app. Set `Cookie` or `Authorization` headers yourself. |
| **Cancelling or time-limiting a DNS lookup** | Lookups use CE's blocking `gethostbyname`, which can't be interrupted and isn't re-entrant, so lookups also run one at a time. A cancel or timeout takes effect as soon as the lookup returns. A thread-based resolver would fix this. |
| **Redirects in the native API** | The C API returns the 3xx response and leaves following it to you. The .NET API follows them. |
| **0-RTT early data, PSK, ALPN** | 0-RTT can be replayed by an attacker and is unsafe for most requests. PSK needs keys shared in advance. ALPN only matters for HTTP/2. |
| **Server mode** | CeHttps is a client library. |
| **Hardware crypto** | The PXA32x has none, so everything runs in portable C. |

---

## Files to ship with an app

| File | What | Needed by |
|---|---|---|
| `CeHttpsNative.dll` | The TLS and HTTP engine (native ARM) | Every app |
| `CeHttps.dll` | The .NET CF 3.5 wrapper | .NET apps (or compile its `.cs` files into your exe) |
| `cacert.pem` | Trusted root certificates (Mozilla's list, from https://curl.se/docs/caextract.html) | Every app; you pass its bytes to `ch_init` |

Put them next to your exe. A .NET app can also embed `CeHttpsNative.dll` and
`cacert.pem` as resources and write them out on first start, so it ships as a
single exe. Book Scout and App Store do this (see their `Embedded.cs`).

---

## .NET CF 3.5

Reference `CeHttps.dll` in your Smart Device project, and add
`CeHttpsNative.dll` and `cacert.pem` as **Content / Copy if newer**.

```csharp
using CeHttps;

// Once at startup, off the UI thread (loading the roots takes a few seconds):
ClockSync.Sync();     // optional: fix the device clock over NTP first
Https.Init();         // loads cacert.pem from the app folder

// GET; the callback runs on the UI thread of `this` (a Form):
Https.GetAsync("https://api.example.com/items", this,
    delegate(HttpsResponse r, HttpsException e) {
        if (e != null) { statusLabel.Text = "Failed: " + e.Message; return; }
        if (!r.IsSuccess) { statusLabel.Text = "HTTP " + r.Status; return; }
        resultBox.Text = r.Text;
    });

// POST JSON with a header and a timeout, and keep the option to cancel:
HttpsRequest req = new HttpsRequest("POST", "https://api.example.com/items")
    .AddHeader("Accept", "application/json")
    .SetJson("{\"name\":\"example\"}");
req.TimeoutMs = 15000;
HttpsOperation op = Https.SendAsync(req, this, OnPosted);
// ... op.Cancel();

void OnPosted(HttpsResponse r, HttpsException e) { /* same pattern as above */ }

// Classic async pattern, or blocking on a thread of your own:
IAsyncResult ar = Https.BeginSend(req, null, null);
HttpsResponse resp = Https.EndSend(ar);
HttpsResponse resp2 = Https.Send(req);       // blocks
```

### Reference

| Member | |
|---|---|
| `Https.Init()` / `Init(byte[] pem)` | Load the roots (from `cacert.pem`, or bytes you supply) |
| `Https.Reload()` | Reload the roots, e.g. after fixing the clock |
| `Https.Send(req)` | Blocking request |
| `Https.SendAsync(req, control, callback)` | Non-blocking; the callback runs on `control`'s UI thread (or a worker if `control` is null) |
| `Https.GetAsync(url, …)`, `Https.PostJsonAsync(url, json, …)` | Shortcuts |
| `Https.BeginSend` / `EndSend` | Standard .NET async pattern |
| `Https.UserAgent`, `Https.MaxConcurrent` | Settings |
| `Https.RootStats(...)`, `Https.Diagnostics`, `Https.ClockLooksWrong` | Diagnostics |
| `Https.Sha256Hex(bytes)` | SHA-256 as lowercase hex |
| `ClockSync.Sync()` | Set the clock over SNTP; returns a readable result |
| `HttpsRequest` | `Method`, `Url`, `Headers`, `Body`, `TimeoutMs`, `MaxResponseBytes`, `FollowRedirects`; `AddHeader`, `SetBody`, `SetJson` |
| `HttpsResponse` | `Status`, `IsSuccess`, `Body`, `Text`, `Header(name)`, `RawHeaders`, `Url` (after redirects), timings, `Resumed` |
| `HttpsOperation` | `Cancel()`, `Wait(ms)`, `IsCompleted`, `AsyncWaitHandle` |
| `HttpsException` | `Code`, `TlsCode`, `IsTimeout`, `IsCancelled`, `IsDnsOrNetwork`, `IsClockProblem` |

HTTP error statuses such as 404 or 500 are **not** exceptions: check
`r.Status` or `r.IsSuccess`. An `HttpsException` means no valid HTTP response
arrived at all.

---

## Native C / C++

Include `cehttps.h`, link `CeHttpsNative.lib`, and ship `CeHttpsNative.dll`.

```c
#include "cehttps.h"

ch_init(pemBytes, pemLen);                      /* once */

ch_request* r = ch_request_new("GET", "https://api.example.com/items");
ch_request_add_header(r, "Accept: application/json");
ch_request_start(r, NULL, NULL, hWnd, WM_APP + 1);   /* returns at once */

/* in your window procedure: */
case WM_APP + 1: {
    ch_request* r = (ch_request*)wParam;
    if (ch_result_code(r) == CH_OK)
        show(ch_response_status(r), ch_response_body(r), ch_response_body_len(r));
    else {
        char err[256]; ch_result_error(r, err, sizeof err); show_error(err);
    }
    ch_request_free(r);
    break;
}
```

Instead of a window message you can pass a callback, which runs on the
request's worker thread. Calling `ch_request_free` inside it is allowed.

### Reference

| Function | |
|---|---|
| `ch_init(pem, len)` | Load roots (call again to reload) |
| `ch_init_error`, `ch_root_stats`, `ch_info` | Why init failed; root counts; diagnostics |
| `ch_set_user_agent`, `ch_set_max_concurrent` | Settings |
| `ch_sha256` | SHA-256 helper |
| `ch_cleanup` | Free everything (no requests may be running) |
| `ch_request_new(method, url)` | Create a request (`https://host[:port]/path`) |
| `ch_request_add_header`, `ch_request_set_body` | Headers ("Name: value") and body |
| `ch_request_set_timeout`, `ch_request_set_max_response` | Limits |
| `ch_request_run` | Blocking |
| `ch_request_start(r, cb, user, hwnd, msg)` | Non-blocking |
| `ch_request_wait`, `ch_request_cancel`, `ch_request_state` | Control |
| `ch_request_free` | Free (cancels and waits if still running) |
| `ch_result_code`, `ch_result_tls_code`, `ch_result_error`, `ch_result_timing` | Outcome |
| `ch_response_status`, `ch_response_body`, `ch_response_body_len`, `ch_response_copy_body` | Response |
| `ch_response_headers`, `ch_response_header(name)` | Response headers |

### Result codes

| Code | Value | Meaning |
|---|---|---|
| `CH_OK` | 0 | A valid HTTP response arrived (any status) |
| `CH_E_ARGUMENT` | -1 | Bad parameter or URL (only `https://` is accepted) |
| `CH_E_NOT_READY` | -2 | `ch_init` wasn't called or failed |
| `CH_E_STATE` | -3 | The request was already started |
| `CH_E_MEMORY` | -4 | Out of memory |
| `CH_E_DNS` | -10 | Host name not found |
| `CH_E_CONNECT` | -11 | TCP connection failed |
| `CH_E_TLS` | -20 | Handshake or certificate check failed: see `ch_result_tls_code` |
| `CH_E_IO` | -30 | Sending or receiving failed |
| `CH_E_TIMEOUT` | -31 | The request's time limit passed |
| `CH_E_CANCELLED` | -32 | Cancelled |
| `CH_E_TOO_LARGE` | -33 | The response exceeded the size limit |
| `CH_E_HTTP` | -40 | Not a valid HTTP response |

---

## Building

You need **Visual Studio 2008 Professional** and the **Windows Mobile 6
Professional SDK**. Newer versions of Visual Studio can't load Smart Device
projects.

wolfSSL is a git submodule (`third_party/wolfssl`, pinned to
`v5.9.4-stable`), so clone with `--recursive`:

```
git clone --recursive https://github.com/oseart55/CeHttps.git
```

(Already cloned? Run `git submodule update --init`.)

Open `VS\CeHttps.sln` and build **Release**. It contains:

- **CeHttpsNative**: the native DLL. It compiles `native\cehttps.c` plus
  wolfSSL's sources, configured by `native\user_settings.h`.
- **CeHttps**: the .NET wrapper (`VS\CeHttps\*.cs`).
- **CeHttpsSample**: a small demo app (`VS\CeHttpsSample`).

The output lands in `VS\CeHttpsNative\Windows Mobile 6 Professional SDK (ARMV4I)\Release\`
(`CeHttpsNative.dll`, `CeHttpsNative.lib`) and `VS\CeHttps\bin\Release\CeHttps.dll`.
Ready-built files are attached to each GitHub release.

To build against a newer wolfSSL, check out its tag in `third_party/wolfssl`
and rebuild. If a release adds or renames source files, update the file list in
`CeHttpsNative.vcproj`.

Some settings in `user_settings.h` are needed for this platform. Keep them if
you change the file:

| Setting | Why |
|---|---|
| `WOLFSSL_USE_ALIGN`, `WOLFSSL_GENERAL_ALIGNMENT 4`, `XSTREAM_ALIGN` | The XScale faults on unaligned access. MSVC defines `_M_ARM`, not GCC's `__arm__`, so wolfSSL wouldn't turn these on by itself. |
| `SIZEOF_LONG 4`, `SIZEOF_LONG_LONG 8` | CE's `limits.h` lacks `ULLONG_MAX`, so wolfSSL can't detect the sizes. |
| `XVSNPRINTF _vsnprintf` | CE's C runtime only has the underscore version. |
| `windows.h` included early | Gives wolfSSL `SYSTEMTIME` for its CE clock code, and the Windows `min`/`max` macros. |
| `WOLFSSL_NO_ATOMICS` | VS2008's ARM compiler has no usable atomics; critical sections are used instead. |
| `WOLFSSL_SMALL_STACK` | Keeps big temporaries off CE's small thread stacks. |
| `WOLFSSL_NO_ASM` | Portable C; wolfSSL's ARM assembly targets newer ARM cores than the XScale. |

---

## Performance (MC55A, 806 MHz)

| | Typical |
|---|---|
| Loading `cacert.pem` (~120 roots) | A few seconds, once at startup |
| Full TLS 1.3 handshake | 0.3–0.5 s |
| Resumed handshake | Much faster: no certificate checks |
| Example: first lookup on openlibrary.org | DNS 122 ms, connect 103 ms, TLS 426 ms, reply 306 ms |

Several requests at once share one CPU core: the concurrency limit helps when a
batch of requests is queued.

---

## Notes for these devices

- **Clock.** Certificate checks need the right date. Call `ClockSync.Sync()` at
  startup, or install ClockSync to set the clock at every boot.
- **Root certificates.** Refresh `cacert.pem` about once a year, so new
  certificate authorities are trusted and retired ones dropped.
- **Memory.** Each running request holds its whole response in memory, up to
  its size limit. With four at once, budget for four responses.
- **Private servers.** Append your own CA certificate (PEM) to `cacert.pem`, or
  pass a PEM containing only it to trust just your servers.

## Security

CeHttps relies on wolfSSL for all cryptography and TLS protocol handling. The
code in `cehttps.c` covers networking, HTTP and threading. It never decides
whether a certificate is trusted. Verification is always on, uses the roots you
supply, and checks the host name.

It hasn't been independently audited. Report problems to the maintainers. Keep
wolfSSL up to date: rebuilding against a newer wolfSSL release picks up its
security fixes.

## Licence

CeHttps is free software under the **GNU General Public License v3** (see
`LICENSE`). It includes wolfSSL, which is GPLv3 as well, and the root
certificates are under the Mozilla Public License 2.0. See `NOTICE.md`.

In practice, if you distribute an app that uses CeHttps, that app must also be
released under the GPLv3, with its source available. For closed-source use you
would need a commercial licence from wolfSSL Inc., plus permission from the
CeHttps authors.

This is not legal advice.
