using System.Drawing;
using AgileDeob.Core;
using AgileDeob.Util;

namespace AgileDeob.Gui;

/// <summary>
/// Drag-and-drop front end: drop a .dll/.exe onto the window (or onto the app
/// icon in Explorer, which passes the path as an argument) and it writes a
/// cleaned copy next to the original and streams the log into the window.
/// </summary>
public sealed class MainForm : Form
{
    private readonly RichTextBox _log;
    private readonly Label _dropHint;
    private readonly CheckBox _dynamicChk;
    private bool _busy;

    public MainForm(string[] args)
    {
        Text = "agile-deob — drop a .NET assembly to deobfuscate";
        MinimumSize = new Size(640, 440);
        Size = new Size(760, 520);
        StartPosition = FormStartPosition.CenterScreen;
        AllowDrop = true;
        BackColor = Color.FromArgb(24, 24, 28);

        _dropHint = new Label
        {
            Dock = DockStyle.Top,
            Height = 90,
            Text = "⇩  Drop a .dll or .exe here",
            TextAlign = ContentAlignment.MiddleCenter,
            Font = new Font("Segoe UI", 16f, FontStyle.Bold),
            ForeColor = Color.Gainsboro,
            BackColor = Color.FromArgb(40, 40, 48),
            AllowDrop = true,
        };

        _dynamicChk = new CheckBox
        {
            Dock = DockStyle.Top,
            Height = 34,
            Padding = new Padding(12, 6, 0, 0),
            Text = "Run the file's own string decrypter in-process (--dynamic). " +
                   "⚠ EXECUTES THE FILE — only for samples you trust / in a VM.",
            ForeColor = Color.Khaki,
            BackColor = Color.FromArgb(24, 24, 28),
        };

        _log = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            BackColor = Color.FromArgb(16, 16, 20),
            ForeColor = Color.Gainsboro,
            Font = new Font("Consolas", 9.5f),
            BorderStyle = BorderStyle.None,
            WordWrap = false,
            AllowDrop = true,
        };

        // Order of docking matters: Fill first, then the Top bars stack above it.
        Controls.Add(_log);
        Controls.Add(_dynamicChk);
        Controls.Add(_dropHint);

        foreach (Control c in new Control[] { this, _dropHint, _log })
        {
            c.DragEnter += OnDragEnter;
            c.DragDrop += OnDragDrop;
        }

        Append(LogLevel.Info, "Ready. Drop a protected .NET assembly onto this window.");
        Append(LogLevel.Info, "Output is written next to the input as <name>-cleaned<ext>.");

        // Launched with a file (dragged onto the .exe icon)? Process it.
        string[] files = args.Where(File.Exists).ToArray();
        if (files.Length > 0)
            BeginInvoke(() => _ = ProcessAll(files));
    }

    private void OnDragEnter(object? sender, DragEventArgs e)
    {
        if (!_busy && e.Data?.GetDataPresent(DataFormats.FileDrop) == true)
            e.Effect = DragDropEffects.Copy;
        else
            e.Effect = DragDropEffects.None;
    }

    private async void OnDragDrop(object? sender, DragEventArgs e)
    {
        if (_busy)
            return;
        if (e.Data?.GetData(DataFormats.FileDrop) is not string[] files || files.Length == 0)
            return;

        await ProcessAll(files);
    }

    private async Task ProcessAll(string[] files)
    {
        _busy = true;
        _dropHint.Text = "Working…";
        // Read UI state here, on the UI thread, before going to a worker.
        bool dynamic = _dynamicChk.Checked;
        try
        {
            foreach (string file in files)
                await Task.Run(() => ProcessOne(file, dynamic));
        }
        finally
        {
            _busy = false;
            _dropHint.Text = "⇩  Drop a .dll or .exe here";
        }
    }

    private void ProcessOne(string path, bool dynamic)
    {
        Append(LogLevel.Info, new string('─', 60));
        Append(LogLevel.Info, $"Input: {path}");

        var log = new Logger(LogLevel.Info)
        {
            // Marshal every log line back onto the UI thread.
            Sink = (level, line) => Append(level, line),
        };

        var options = new DeobOptions
        {
            InputPath = path,
            AllowDynamic = dynamic,
            // A drag-drop user expects it to try regardless of the detector's
            // confidence; the log still reports what was detected.
            Force = true,
        };

        try
        {
            int code = new Deobfuscator(options, log).Run();
            if (code == 0)
                Append(LogLevel.Info, $"Done → {options.ResolveOutputPath()}");
            else
                Append(LogLevel.Warn, $"Finished with exit code {code}.");
        }
        catch (Exception ex)
        {
            Append(LogLevel.Error, $"Unhandled error: {ex.Message}");
        }
    }

    private void Append(LogLevel level, string line)
    {
        if (_log.InvokeRequired)
        {
            _log.BeginInvoke(() => Append(level, line));
            return;
        }

        _log.SelectionStart = _log.TextLength;
        _log.SelectionLength = 0;
        _log.SelectionColor = level switch
        {
            LogLevel.Error => Color.Salmon,
            LogLevel.Warn => Color.Khaki,
            LogLevel.Debug => Color.Gray,
            _ => Color.Gainsboro,
        };
        _log.AppendText(line + Environment.NewLine);
        _log.SelectionColor = _log.ForeColor;
        _log.ScrollToCaret();
    }
}
