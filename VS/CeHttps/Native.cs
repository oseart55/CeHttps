// CeHttps - modern HTTPS for .NET Compact Framework 3.5. GPLv3 (see LICENSE).
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CeHttps
{
    /// <summary>P/Invoke declarations for CeHttpsNative.dll (see cehttps.h).</summary>
    internal static class Native
    {
        // Apps can ship the engine under another name by defining a symbol
        // (Book Scout defines CEHTTPS_AS_BOOKTLS, for its older auto-updater).
#if CEHTTPS_AS_BOOKTLS
        const string Dll = "BookTls.dll";
#else
        const string Dll = "CeHttpsNative.dll";
#endif

        public const int CH_OK = 0;
        public const int CH_E_TLS = -20;
        public const int ASN_NO_SIGNER_E = -188;

        [DllImport(Dll)] public static extern int ch_init(byte[] caPem, int caLen);
        [DllImport(Dll)] public static extern int ch_init_error(byte[] buf, int cap);
        [DllImport(Dll)] public static extern int ch_root_stats(out int loaded, out int rejected, out int dateRejected);
        [DllImport(Dll)] public static extern int ch_info(byte[] buf, int cap);
        [DllImport(Dll)] public static extern int ch_set_user_agent(byte[] userAgent);
        [DllImport(Dll)] public static extern int ch_set_max_concurrent(int count);
        [DllImport(Dll)] public static extern int ch_sha256(byte[] data, int len, byte[] out32);

        [DllImport(Dll)] public static extern IntPtr ch_request_new(byte[] method, byte[] url);
        [DllImport(Dll)] public static extern int ch_request_add_header(IntPtr r, byte[] line);
        [DllImport(Dll)] public static extern int ch_request_set_body(IntPtr r, byte[] body, int len);
        [DllImport(Dll)] public static extern int ch_request_set_timeout(IntPtr r, int ms);
        [DllImport(Dll)] public static extern int ch_request_set_max_response(IntPtr r, int bytes);
        [DllImport(Dll)] public static extern int ch_request_run(IntPtr r);
        [DllImport(Dll)] public static extern int ch_request_cancel(IntPtr r);
        [DllImport(Dll)] public static extern void ch_request_free(IntPtr r);

        [DllImport(Dll)] public static extern int ch_result_code(IntPtr r);
        [DllImport(Dll)] public static extern int ch_result_tls_code(IntPtr r);
        [DllImport(Dll)] public static extern int ch_result_error(IntPtr r, byte[] buf, int cap);
        [DllImport(Dll)] public static extern int ch_result_timing(IntPtr r, out int dnsMs, out int connectMs,
                                                                   out int tlsMs, out int responseMs, out int resumed);
        [DllImport(Dll)] public static extern int ch_response_status(IntPtr r);
        [DllImport(Dll)] public static extern int ch_response_body_len(IntPtr r);
        [DllImport(Dll)] public static extern int ch_response_copy_body(IntPtr r, byte[] buf, int cap);
        [DllImport(Dll)] public static extern int ch_response_headers(IntPtr r, byte[] buf, int cap);

        /// <summary>UTF-8, zero-terminated.</summary>
        public static byte[] Z(string s)
        {
            return Encoding.UTF8.GetBytes((s == null ? "" : s) + "\0");
        }

        public static string Str(byte[] b, int n)
        {
            if (n < 0) n = 0;
            if (n > b.Length) n = b.Length;
            int len = 0;
            while (len < n && b[len] != 0) len++;
            return Encoding.UTF8.GetString(b, 0, len);
        }
    }
}
