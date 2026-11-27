// CeHttps - modern HTTPS for .NET Compact Framework 3.5. GPLv3 (see LICENSE).
using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace CeHttps
{
    /// <summary>
    /// Sets the device clock from an SNTP server (UDP port 123). Many Windows
    /// Mobile / CE images have no time service, and HTTPS certificate checks
    /// fail when the clock is wrong: call ClockSync.Sync() before Https.Init().
    /// </summary>
    public static class ClockSync
    {
        static readonly string[] Servers = { "pool.ntp.org", "time.google.com", "time.windows.com" };
        const int TimeoutMs = 3000;
        const double MaxDriftSeconds = 60;

        [StructLayout(LayoutKind.Sequential)]
        struct SYSTEMTIME
        {
            public ushort Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds;
        }

        [DllImport("coredll.dll", SetLastError = true)]
        static extern bool SetSystemTime(ref SYSTEMTIME st);

        /// <summary>
        /// Checks the clock against NTP and fixes it if it is off by more than a
        /// minute. Returns a short description of what happened; never throws.
        /// </summary>
        public static string Sync()
        {
            string lastError = "no reply";
            foreach (string server in Servers)
            {
                try
                {
                    DateTime utc = Query(server);
                    double drift = (utc - DateTime.UtcNow).TotalSeconds;
                    if (Math.Abs(drift) <= MaxDriftSeconds)
                        return "Clock OK (" + server + ")";

                    SetClock(utc);
                    return "Clock corrected by " + DescribeDrift(drift) + " (" + server + ")";
                }
                catch (Exception ex)
                {
                    lastError = server + ": " + ex.Message;
                }
            }
            return "Clock not checked - " + lastError;
        }

        static DateTime Query(string server)
        {
            IPAddress address = null;
            foreach (IPAddress a in Dns.GetHostEntry(server).AddressList)
                if (a.AddressFamily == AddressFamily.InterNetwork) { address = a; break; }
            if (address == null) throw new Exception("no IPv4 address");

            byte[] packet = new byte[48];
            packet[0] = 0x1B;  // LI = 0, version 3, mode 3 (client)

            using (Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
            {
                int sent = Environment.TickCount;
                s.SendTo(packet, new IPEndPoint(address, 123));
                if (!s.Poll(TimeoutMs * 1000, SelectMode.SelectRead))
                    throw new Exception("timed out");

                byte[] reply = new byte[48];
                int n = s.Receive(reply);
                int roundTripMs = Environment.TickCount - sent;

                return Parse(reply, n, roundTripMs);
            }
        }

        /// <summary>Validates an SNTP reply and returns its transmit time (UTC).</summary>
        public static DateTime Parse(byte[] reply, int length, int roundTripMs)
        {
            if (length < 48) throw new Exception("short reply");
            int mode = reply[0] & 0x07;
            int stratum = reply[1];
            if (mode != 4 && mode != 5) throw new Exception("not a server reply");
            if (stratum < 1 || stratum > 15) throw new Exception("server not synchronised");

            // Transmit timestamp: seconds and fraction since 1900-01-01, big-endian.
            ulong seconds  = ((ulong)reply[40] << 24) | ((ulong)reply[41] << 16) | ((ulong)reply[42] << 8) | reply[43];
            ulong fraction = ((ulong)reply[44] << 24) | ((ulong)reply[45] << 16) | ((ulong)reply[46] << 8) | reply[47];
            if (seconds == 0) throw new Exception("empty timestamp");

            double ms = seconds * 1000.0 + fraction * 1000.0 / 4294967296.0 + roundTripMs / 2.0;
            DateTime utc = new DateTime(1900, 1, 1, 0, 0, 0).AddMilliseconds(ms);
            if (utc.Year < 2025 || utc.Year > 2099) throw new Exception("implausible time " + utc.ToString("yyyy-MM-dd"));
            return utc;
        }

        static void SetClock(DateTime utc)
        {
            SYSTEMTIME st = new SYSTEMTIME();
            st.Year = (ushort)utc.Year;
            st.Month = (ushort)utc.Month;
            st.DayOfWeek = (ushort)utc.DayOfWeek;
            st.Day = (ushort)utc.Day;
            st.Hour = (ushort)utc.Hour;
            st.Minute = (ushort)utc.Minute;
            st.Second = (ushort)utc.Second;
            st.Milliseconds = (ushort)utc.Millisecond;
            if (!SetSystemTime(ref st))
                throw new Exception("SetSystemTime failed (" + Marshal.GetLastWin32Error() + ")");
        }

        static string DescribeDrift(double seconds)
        {
            double a = Math.Abs(seconds);
            string amount;
            if (a < 3600) amount = ((int)(a / 60)) + " min";
            else if (a < 172800) amount = ((int)(a / 3600)) + " h";
            else amount = ((int)(a / 86400)) + " days";
            return amount + (seconds > 0 ? " (was slow)" : " (was fast)");
        }
    }
}
