/* user_settings.h - wolfSSL build configuration for CeHttps.dll
 *
 * Target: Windows Embedded Handheld 6.5 (CE 5.2), ARMv5 (PXA32x), VS2008
 *         Smart Device project, "Windows Mobile 6 Professional SDK (ARMV4I)".
 *
 * Add WOLFSSL_USER_SETTINGS to the project's preprocessor definitions and put
 * this folder on the include path so wolfSSL picks this file up.
 */
#ifndef BOOKTLS_USER_SETTINGS_H
#define BOOKTLS_USER_SETTINGS_H

#ifndef _WIN32_WCE
    #error "This configuration is meant for Windows Mobile / Windows CE builds"
#endif

/* ---------------------------------------------------------------- platform */
#define WOLFSSL_NO_ASM          /* portable C everywhere (no ARMv5 asm paths) */
#define NO_FILESYSTEM           /* CA bundle is passed in as a memory buffer  */
#define NO_WRITEV
#define NO_MAIN_DRIVER
/* Multi-threaded: wolfSSL guards its shared state with Win32 critical
   sections. Reference counts use those too rather than compiler atomics,
   which VS2008's ARM compiler may not offer.                              */
#define WOLFSSL_NO_ATOMICS
#define WOLFSSL_SMALL_STACK     /* keep big temporaries off the 64 KB stack   */
#define WOLFSSL_IGNORE_FILE_WARN

/* The XScale (ARMv5) faults on unaligned 16/32-bit loads and stores.
 * wolfSSL only enables its byte-wise code paths for ARM when it sees GCC's
 * __arm__; Microsoft's compiler defines _M_ARM instead, so force them on. */
#define WOLFSSL_USE_ALIGN
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define XSTREAM_ALIGN

/* CE's limits.h has no ULLONG_MAX, so wolfSSL can't detect these itself. */
#define SIZEOF_LONG       4
#define SIZEOF_LONG_LONG  8

/* CE's CRT only has the underscore-prefixed version. */
#define XVSNPRINTF _vsnprintf

/* -------------------------------------------------------- windows.h / time
 * Pull in windows.h first (without the old winsock.h) so wolfSSL sees the
 * Windows min()/max() macros before it decides whether to define its own,
 * and so its built-in Windows CE clock code (windows_time) has SYSTEMTIME.
 * wolfSSL then uses its own gmtime and struct tm on CE.                    */
#define _WINSOCKAPI_
#include <windows.h>
#undef _WINSOCKAPI_

/* -------------------------------------------------------------- protocol */
#define WOLFSSL_TLS13
#define NO_OLD_TLS              /* TLS 1.2 + 1.3 only                         */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SNI                /* required by almost every modern host       */
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define WOLFSSL_ALT_CERT_CHAINS /* tolerate cross-signed chains               */
#define NO_PSK
#define HAVE_SESSION_TICKET     /* TLS 1.3 resumption: skip cert checks on repeat requests */
#define SMALL_SESSION_CACHE

/* ---------------------------------------------------------------- crypto */
#define WOLFSSL_SP_MATH_ALL     /* portable big-integer math                  */
/* Optimised fixed-size math (sp_c32.c) for the common key sizes: much faster
   ECDHE / ECDSA / RSA than the generic code on the 806 MHz XScale.         */
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_384
#define SP_INT_BITS 4096        /* RSA up to 4096 (some roots use it)         */
#define HAVE_ECC
#define ECC_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT
#define HAVE_CURVE25519
#define WC_RSA_BLINDING
#define WC_RSA_PSS              /* mandatory for TLS 1.3                      */
#define HAVE_HKDF
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define HAVE_CHACHA             /* ChaCha20-Poly1305 is fast without AES hw   */
#define HAVE_POLY1305
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

#define NO_DSA
#define NO_DH
#define NO_RC4
#define NO_MD4
#define NO_MD5                  /* not needed for TLS 1.2/1.3            */
#define NO_PWDBASED             /* no password-protected keys            */
#define NO_DES3
#define NO_RABBIT
#define NO_HC128

/* Uncomment while getting the first build working on-device */
/* #define DEBUG_WOLFSSL */

#endif /* BOOKTLS_USER_SETTINGS_H */
