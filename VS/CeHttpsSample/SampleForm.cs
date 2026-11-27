// CeHttps sample - GPLv3 (see LICENSE).
using System;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;
using CeHttps;

namespace CeHttpsSample
{
    /// <summary>
    /// Minimal demo: type an https:// URL, press GET. Everything runs in the
    /// background; results come back on the UI thread.
    /// </summary>
    public class SampleForm : Form
    {
        TextBox url, output;
        Button go;
        MenuItem cancel;
        HttpsOperation running;

        public SampleForm()
        {
            Text = "CeHttps sample";
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;

            output = new TextBox();
            output.Multiline = true;
            output.ReadOnly = true;
            output.ScrollBars = ScrollBars.Vertical;
            output.Dock = DockStyle.Fill;

            Panel row = new Panel();
            row.Dock = DockStyle.Top;
            row.Height = 26;
            go = new Button();
            go.Text = "GET";
            go.Dock = DockStyle.Right;
            go.Width = 50;
            go.Enabled = false;
            go.Click += delegate { Get(); };
            url = new TextBox();
            url.Dock = DockStyle.Fill;
            url.Text = "https://www.howsmyssl.com/a/check";
            row.Controls.Add(url);
            row.Controls.Add(go);

            Controls.Add(output);
            Controls.Add(row);

            MainMenu menu = new MainMenu();
            MenuItem exit = new MenuItem();
            exit.Text = "Exit";
            exit.Click += delegate { Close(); };
            cancel = new MenuItem();
            cancel.Text = "Cancel";
            cancel.Enabled = false;
            cancel.Click += delegate { if (running != null) running.Cancel(); };
            menu.MenuItems.Add(exit);
            menu.MenuItems.Add(cancel);
            Menu = menu;

            Load += delegate { Start(); };
        }

        // Clock + roots take a few seconds: do them off the UI thread.
        void Start()
        {
            output.Text = "Setting clock and loading certificates...";
            ThreadPool.QueueUserWorkItem(delegate(object unused)
            {
                string clock = ClockSync.Sync();
                string result;
                try
                {
                    Https.Init();                          // cacert.pem next to the exe
                    Https.UserAgent = "CeHttpsSample/1.0";
                    result = "Ready.\r\n" + clock + "\r\n" + Https.Diagnostics;
                }
                catch (HttpsException e)
                {
                    result = "Init failed: " + e.Message + "\r\n" + clock;
                }
                BeginInvoke(new MethodInvoker(delegate
                {
                    output.Text = result;
                    go.Enabled = Https.IsReady;
                }));
            });
        }

        void Get()
        {
            go.Enabled = false;
            cancel.Enabled = true;
            output.Text = "Requesting " + url.Text + " ...";

            HttpsRequest req = new HttpsRequest("GET", url.Text);
            req.AddHeader("Accept", "application/json, text/html");
            req.TimeoutMs = 20000;

            running = Https.SendAsync(req, this, delegate(HttpsResponse r, HttpsException e)
            {
                // Runs on the UI thread.
                running = null;
                go.Enabled = true;
                cancel.Enabled = false;
                if (e != null)
                {
                    output.Text = (e.IsCancelled ? "Cancelled." :
                                   e.IsClockProblem ? "Clock problem: " + e.Message :
                                   "Failed: " + e.Message);
                    return;
                }
                string text = r.Text;
                if (text.Length > 3000) text = text.Substring(0, 3000) + "\r\n...";
                output.Text = r + "\r\nContent-Type: " + r.Header("Content-Type") + "\r\n\r\n" + text;
            });
        }
    }

    public delegate void MethodInvoker();

    static class Program
    {
        [MTAThread]
        static void Main()
        {
            Application.Run(new SampleForm());
        }
    }
}
