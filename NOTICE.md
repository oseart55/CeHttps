# Third-party components

## wolfSSL

CeHttpsNative.dll is built from wolfSSL (https://www.wolfssl.com,
https://github.com/wolfSSL/wolfssl). Copyright (C) 2006-2026 wolfSSL Inc.
Licensed under the GNU General Public License v3 (see LICENSE). A commercial
licence is available from wolfSSL Inc.

## Root certificates (cacert.pem)

The CA bundle is extracted from Mozilla's root store by the curl project
(https://curl.se/docs/caextract.html). It is licensed under the Mozilla Public
License 2.0 (https://mozilla.org/MPL/2.0/). Its source is the Mozilla NSS
`certdata.txt` file.
