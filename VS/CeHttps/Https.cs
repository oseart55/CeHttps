// CeHttps - modern HTTPS for .NET Compact Framework 3.5. GPLv3 (see LICENSE).
using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace CeHttps
{
    /// <summary>
    /// Modern HTTPS (TLS 1.2 / 1.3) for .NET CF 3.5 on Windows Mobile / CE.
    ///
    /// <code>
    /// Https.Init();                                   // loads cacert.pem next to the exe
    ///
    /// // Non-blocking: the callback runs on the UI thread of `this` (a Form).
    /// Https.SendAsync(new HttpsRequest("GET", "https://example.com/"), this,
    ///     delegate(HttpsResponse r, HttpsException e) {
    ///         label.Text = e != null ? e.Message : r.Status + " " + r.Text;
    ///     });
    /// </code>
    ///
    /// Everything here is thread-safe, and every request runs off the calling
    /// thread unless you use the blocking <see cref="Send"/>.
    /// </summary>
    public static class Https
    {
        const int MaxRedirects = 5;
        static readonly object gate = new object();
        static byte[] roots;

        // ------------------------------------------------------------- setup

        /// <summary>Loads cacert.pem from the folder CeHttps.dll is in (normally the app folder).</summary>
        public static void Init()
        {
            string dir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().GetName().CodeBase);
            Init(ReadAll(Path.Combine(dir, "cacert.pem")));
        }

        /// <summary>Loads trusted root certificates (PEM bytes, e.g. curl's cacert.pem).</summary>
        public static void Init(byte[] caPem)
        {
            if (caPem == null || caPem.Length == 0) throw new ArgumentException("caPem");
            lock (gate) { roots = caPem; }
            int rc = Native.ch_init(caPem, caPem.Length);
            if (rc != Native.CH_OK) throw new HttpsException(InitError(), rc, 0);
        }

        /// <summary>Reloads the roots - call after fixing the device clock (requests also do this automatically).</summary>
        public static void Reload()
        {
            byte[] r;
            lock (gate) { r = roots; }
            if (r == null) throw new InvalidOperationException("Https.Init has not been called");
            int rc = Native.ch_init(r, r.Length);
            if (rc != Native.CH_OK) throw new HttpsException(InitError(), rc, 0);
        }

        public static bool IsReady
        {
            get { int ok, bad, dateBad; Native.ch_root_stats(out ok, out bad, out dateBad); return ok > 0; }
        }

        /// <summary>Default User-Agent header.</summary>
        public static string UserAgent
        {
            set { if (Native.ch_set_user_agent(Native.Z(value)) != Native.CH_OK) throw new ArgumentException("UserAgent"); }
        }

        /// <summary>How many requests may use the network at once (1-16, default 4).</summary>
        public static int MaxConcurrent
        {
            set { if (Native.ch_set_max_concurrent(value) != Native.CH_OK) throw new ArgumentOutOfRangeException("MaxConcurrent"); }
        }

        /// <summary>Roots loaded / rejected, and the TLS clock - for troubleshooting.</summary>
        public static string Diagnostics
        {
            get { byte[] b = new byte[512]; return Native.Str(b, Native.ch_info(b, b.Length)); }
        }

        /// <summary>Roots loaded / rejected by the last Init or Reload; dateRejected &gt; 0 usually means a wrong clock.</summary>
        public static void RootStats(out int loaded, out int rejected, out int dateRejected)
        {
            Native.ch_root_stats(out loaded, out rejected, out dateRejected);
        }

        /// <summary>True if root certificates were rejected as expired / not yet valid (wrong clock).</summary>
        public static bool ClockLooksWrong
        {
            get { int ok, bad, dateBad; Native.ch_root_stats(out ok, out bad, out dateBad); return dateBad > 0; }
        }

        /// <summary>Lower-case hex SHA-256.</summary>
        public static string Sha256Hex(byte[] data)
        {
            byte[] h = new byte[32];
            if (Native.ch_sha256(data, data.Length, h) != Native.CH_OK) throw new ArgumentException("data");
            StringBuilder sb = new StringBuilder(64);
            foreach (byte x in h) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        // ------------------------------------------------------------- blocking

        /// <summary>Sends the request on the calling thread. Throws HttpsException on failure.</summary>
        public static HttpsResponse Send(HttpsRequest request)
        {
            return Send(request, null);
        }

        // ------------------------------------------------------------- non-blocking

        /// <summary>
        /// Starts the request and returns at once. When it finishes, the callback
        /// runs on the UI thread of <paramref name="uiControl"/> (via BeginInvoke),
        /// or on a worker thread if uiControl is null.
        /// </summary>
        public static HttpsOperation SendAsync(HttpsRequest request, Control uiControl, HttpsCallback callback)
        {
            if (request == null) throw new ArgumentNullException("request");
            HttpsOperation op = new HttpsOperation(request, null, null);
            op.Start(uiControl, callback);
            return op;
        }

        public static HttpsOperation GetAsync(string url, Control uiControl, HttpsCallback callback)
        {
            return SendAsync(new HttpsRequest("GET", url), uiControl, callback);
        }

        public static HttpsOperation PostJsonAsync(string url, string json, Control uiControl, HttpsCallback callback)
        {
            return SendAsync(new HttpsRequest("POST", url).SetJson(json), uiControl, callback);
        }

        /// <summary>Classic async pattern: BeginSend ... EndSend. The callback runs on a worker thread.</summary>
        public static IAsyncResult BeginSend(HttpsRequest request, AsyncCallback callback, object state)
        {
            if (request == null) throw new ArgumentNullException("request");
            HttpsOperation op = new HttpsOperation(request, callback, state);
            op.Start(null, null);
            return op;
        }

        /// <summary>Waits for and returns the response (throws HttpsException on failure).</summary>
        public static HttpsResponse EndSend(IAsyncResult result)
        {
            HttpsOperation op = result as HttpsOperation;
            if (op == null) throw new ArgumentException("result");
            op.AsyncWaitHandle.WaitOne();
            if (op.Error != null) throw op.Error;
            return op.Response;
        }

        // ------------------------------------------------------------- core

        internal static HttpsResponse Send(HttpsRequest request, HttpsOperation op)
        {
            HttpsRequest current = request;
            for (int hop = 0; ; hop++)
            {
                HttpsResponse resp = SendOnce(current, op, true);
                int s = resp.Status;
                string location = resp.Header("Location");
                if (!request.FollowRedirects || location == null || location.Length == 0 ||
                    (s != 301 && s != 302 && s != 303 && s != 307 && s != 308))
                    return resp;
                if (hop >= MaxRedirects) throw new HttpsException("too many redirects", -40, 0);

                string next = Resolve(current.Url, location);
                bool keepMethod = s == 307 || s == 308 || current.Method == "GET" || current.Method == "HEAD";
                current = keepMethod ? current.CopyFor(next, current.Method, true)
                                     : current.CopyFor(next, "GET", false);
            }
        }

        // One request; reloads the roots once if they were rejected because of the clock.
        static HttpsResponse SendOnce(HttpsRequest q, HttpsOperation op, bool mayReload)
        {
            IntPtr r = Native.ch_request_new(Native.Z(q.Method), Native.Z(q.Url));
            if (r == IntPtr.Zero) throw new HttpsException("invalid request (only https:// URLs are supported): " + q.Url, -1, 0);
            try
            {
                foreach (string h in q.Headers)
                    if (Native.ch_request_add_header(r, Native.Z(h)) != Native.CH_OK)
                        throw new HttpsException("invalid header: " + h, -1, 0);
                if (q.Body != null && q.Body.Length > 0) Native.ch_request_set_body(r, q.Body, q.Body.Length);
                Native.ch_request_set_timeout(r, q.TimeoutMs);
                Native.ch_request_set_max_response(r, q.MaxResponseBytes);

                if (op != null && !op.Attach(r)) throw new HttpsException("cancelled", -32, 0);
                int rc;
                try { rc = Native.ch_request_run(r); }
                finally { if (op != null) op.Detach(); }

                if (rc != Native.CH_OK)
                {
                    int tls = Native.ch_result_tls_code(r);
                    byte[] e = new byte[256];
                    string msg = Native.Str(e, Native.ch_result_error(r, e, e.Length));
                    if (mayReload && tls == Native.ASN_NO_SIGNER_E && ClockLooksWrong)
                    {
                        // Roots were date-rejected when loaded; the clock may be right now.
                        try { Reload(); } catch (HttpsException) { }
                        if (!ClockLooksWrong) return SendOnce(q, op, false);
                    }
                    throw new HttpsException(msg, rc, tls);
                }

                HttpsResponse resp = new HttpsResponse();
                resp.Url = q.Url;
                resp.Status = Native.ch_response_status(r);
                int len = Native.ch_response_body_len(r);
                resp.Body = new byte[len];
                if (len > 0) Native.ch_response_copy_body(r, resp.Body, len);
                int hl = Native.ch_response_headers(r, null, 0);
                if (hl > 0)
                {
                    byte[] hb = new byte[hl + 1];
                    resp.RawHeaders = Native.Str(hb, Native.ch_response_headers(r, hb, hb.Length));
                }
                int dns, con, tlsMs, rsp, resumed;
                Native.ch_result_timing(r, out dns, out con, out tlsMs, out rsp, out resumed);
                resp.DnsMs = dns; resp.ConnectMs = con; resp.TlsMs = tlsMs; resp.ResponseMs = rsp;
                resp.Resumed = resumed != 0;
                return resp;
            }
            finally
            {
                Native.ch_request_free(r);
            }
        }

        static string Resolve(string baseUrl, string location)
        {
            if (location.StartsWith("https://") || location.StartsWith("http://")) return location;
            int schemeEnd = baseUrl.IndexOf("://");
            int pathStart = baseUrl.IndexOf('/', schemeEnd + 3);
            string origin = pathStart < 0 ? baseUrl : baseUrl.Substring(0, pathStart);
            if (location.StartsWith("/")) return origin + location;
            string dir = pathStart < 0 ? "/" : baseUrl.Substring(pathStart, baseUrl.LastIndexOf('/') - pathStart + 1);
            return origin + dir + location;
        }

        static string InitError()
        {
            byte[] b = new byte[256];
            return Native.Str(b, Native.ch_init_error(b, b.Length));
        }

        static byte[] ReadAll(string path)
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                byte[] data = new byte[(int)fs.Length];
                int read = 0;
                while (read < data.Length)
                {
                    int n = fs.Read(data, read, data.Length - read);
                    if (n <= 0) throw new IOException("unexpected end of " + path);
                    read += n;
                }
                return data;
            }
        }
    }

    /// <summary>
    /// A request in flight. Cancel() stops it (the callback then gets an
    /// HttpsException with IsCancelled). Also the IAsyncResult for BeginSend.
    /// </summary>
    public class HttpsOperation : IAsyncResult
    {
        readonly HttpsRequest request;
        readonly AsyncCallback asyncCallback;
        readonly object state;
        readonly ManualResetEvent done = new ManualResetEvent(false);
        readonly object gate = new object();
        IntPtr native = IntPtr.Zero;
        bool cancelled, completed;

        internal HttpsResponse Response;
        internal HttpsException Error;

        internal HttpsOperation(HttpsRequest request, AsyncCallback asyncCallback, object state)
        {
            this.request = request;
            this.asyncCallback = asyncCallback;
            this.state = state;
        }

        public object AsyncState { get { return state; } }
        public WaitHandle AsyncWaitHandle { get { return done; } }
        public bool CompletedSynchronously { get { return false; } }
        public bool IsCompleted { get { lock (gate) { return completed; } } }

        /// <summary>Stop the request. Safe to call at any time, from any thread.</summary>
        public void Cancel()
        {
            lock (gate)
            {
                cancelled = true;
                if (native != IntPtr.Zero) Native.ch_request_cancel(native);
            }
        }

        /// <summary>Block until finished (or timeoutMs passes). Returns true if finished.</summary>
        public bool Wait(int timeoutMs)
        {
            return done.WaitOne(timeoutMs, false);
        }

        // Called by Https on the worker thread around ch_request_run.
        internal bool Attach(IntPtr r)
        {
            lock (gate)
            {
                if (cancelled) return false;
                native = r;
                return true;
            }
        }

        internal void Detach()
        {
            lock (gate) { native = IntPtr.Zero; }
        }

        internal void Start(Control ui, HttpsCallback callback)
        {
            ThreadPool.QueueUserWorkItem(delegate(object unused)
            {
                try { Response = Https.Send(request, this); }
                catch (HttpsException e) { Error = e; }
                catch (Exception e) { Error = new HttpsException(e.Message, -4, 0); }

                lock (gate) { completed = true; }
                done.Set();

                if (asyncCallback != null)
                {
                    try { asyncCallback(this); } catch (Exception) { }
                }
                if (callback != null) Deliver(ui, callback);
            });
        }

        void Deliver(Control ui, HttpsCallback callback)
        {
            HttpsResponse r = Response;
            HttpsException e = Error;
            if (ui == null)
            {
                try { callback(r, e); } catch (Exception) { }
                return;
            }
            try
            {
                ui.BeginInvoke(callback, new object[] { r, e });
            }
            catch (ObjectDisposedException) { }     // form closed meanwhile
            catch (InvalidOperationException) { }   // no window handle any more
        }
    }
}
