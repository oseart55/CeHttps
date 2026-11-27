// CeHttps - modern HTTPS for .NET Compact Framework 3.5. GPLv3 (see LICENSE).
using System;
using System.Collections.Generic;
using System.Text;

namespace CeHttps
{
    /// <summary>What to send.</summary>
    public class HttpsRequest
    {
        public string Method = "GET";
        public string Url = "";
        /// <summary>Extra header lines, "Name: value" each.</summary>
        public readonly List<string> Headers = new List<string>();
        public byte[] Body;
        /// <summary>Whole-request time limit per attempt (ms).</summary>
        public int TimeoutMs = 30000;
        /// <summary>Largest response body accepted.</summary>
        public int MaxResponseBytes = 8 * 1024 * 1024;
        /// <summary>Follow 301/302/303/307/308 redirects (up to 5).</summary>
        public bool FollowRedirects = true;

        public HttpsRequest() { }

        public HttpsRequest(string method, string url)
        {
            Method = method;
            Url = url;
        }

        public HttpsRequest AddHeader(string name, string value)
        {
            Headers.Add(name + ": " + value);
            return this;
        }

        /// <summary>Sets a UTF-8 body and its Content-Type.</summary>
        public HttpsRequest SetBody(string text, string contentType)
        {
            Body = Encoding.UTF8.GetBytes(text == null ? "" : text);
            if (contentType != null) AddHeader("Content-Type", contentType);
            return this;
        }

        public HttpsRequest SetJson(string json)
        {
            return SetBody(json, "application/json");
        }

        internal HttpsRequest CopyFor(string url, string method, bool keepBody)
        {
            HttpsRequest r = new HttpsRequest(method, url);
            r.Headers.AddRange(Headers);
            r.Body = keepBody ? Body : null;
            r.TimeoutMs = TimeoutMs;
            r.MaxResponseBytes = MaxResponseBytes;
            r.FollowRedirects = FollowRedirects;
            return r;
        }
    }

    /// <summary>What came back.</summary>
    public class HttpsResponse
    {
        /// <summary>HTTP status code (200, 404, ...).</summary>
        public int Status;
        public byte[] Body = new byte[0];
        /// <summary>Raw header lines, "Name: value\r\n" each.</summary>
        public string RawHeaders = "";
        /// <summary>The URL that finally answered (after redirects).</summary>
        public string Url = "";
        public int DnsMs, ConnectMs, TlsMs, ResponseMs;
        /// <summary>The TLS session was resumed (faster handshake).</summary>
        public bool Resumed;

        public bool IsSuccess { get { return Status >= 200 && Status < 300; } }

        /// <summary>The body decoded as UTF-8.</summary>
        public string Text { get { return Encoding.UTF8.GetString(Body, 0, Body.Length); } }

        /// <summary>A header's value (case-insensitive), or null.</summary>
        public string Header(string name)
        {
            string want = name.ToLower() + ":";
            foreach (string line in RawHeaders.Split('\n'))
            {
                string l = line.TrimEnd('\r');
                if (l.ToLower().StartsWith(want)) return l.Substring(want.Length).Trim();
            }
            return null;
        }

        public override string ToString()
        {
            return "HTTP " + Status + ", " + Body.Length + " bytes (DNS " + DnsMs + ", connect " + ConnectMs +
                   ", TLS " + TlsMs + (Resumed ? " resumed" : "") + ", response " + ResponseMs + " ms)";
        }
    }

    /// <summary>A request that failed before an HTTP status came back.</summary>
    public class HttpsException : Exception
    {
        /// <summary>CH_E_* code from cehttps.h.</summary>
        public readonly int Code;
        /// <summary>wolfSSL error code, if the TLS layer failed.</summary>
        public readonly int TlsCode;

        public HttpsException(string message, int code, int tlsCode) : base(message)
        {
            Code = code;
            TlsCode = tlsCode;
        }

        public bool IsTimeout { get { return Code == -31; } }
        public bool IsCancelled { get { return Code == -32; } }
        public bool IsDnsOrNetwork { get { return Code == -10 || Code == -11; } }
        /// <summary>The certificate check failed because the device clock is wrong.</summary>
        public bool IsClockProblem
        {
            get
            {
                if (TlsCode == -150 || TlsCode == -151) return true;   // cert not yet valid / expired
                int ok, bad, dateBad;
                Native.ch_root_stats(out ok, out bad, out dateBad);
                return TlsCode == Native.ASN_NO_SIGNER_E && dateBad > 0;
            }
        }
    }

    /// <summary>Result callback for SendAsync. Exactly one of response / error is non-null.</summary>
    public delegate void HttpsCallback(HttpsResponse response, HttpsException error);
}
