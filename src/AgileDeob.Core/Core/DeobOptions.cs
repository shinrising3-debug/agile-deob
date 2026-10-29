using AgileDeob.Util;

namespace AgileDeob.Core;

/// <summary>Parsed command-line options.</summary>
public sealed class DeobOptions
{
    public string InputPath { get; set; } = "";
    public string? OutputPath { get; set; }

    /// <summary>
    /// Allow executing code from the target assembly in-process (reflection
    /// invoke of the string decrypter). This is the only reliable way to
    /// recover Agile.NET strings, but it RUNS UNTRUSTED CODE. Off by default.
    /// </summary>
    public bool AllowDynamic { get; set; }

    /// <summary>Detect and report only; never write an output file.</summary>
    public bool DetectOnly { get; set; }

    /// <summary>Keep going even if detection says this isn't Agile.NET.</summary>
    public bool Force { get; set; }

    public LogLevel LogLevel { get; set; } = LogLevel.Info;

    public string ResolveOutputPath()
    {
        if (!string.IsNullOrEmpty(OutputPath))
            return OutputPath!;

        string dir = Path.GetDirectoryName(Path.GetFullPath(InputPath)) ?? ".";
        string name = Path.GetFileNameWithoutExtension(InputPath);
        string ext = Path.GetExtension(InputPath);
        return Path.Combine(dir, $"{name}-cleaned{ext}");
    }
}
