using AgileDeob.Util;
using dnlib.DotNet;

namespace AgileDeob.Core;

/// <summary>
/// Shared state threaded through every pass: the loaded module, the options,
/// the logger, and a running tally of what each pass changed.
/// </summary>
public sealed class DeobContext
{
    public required ModuleDefMD Module { get; init; }
    public required DeobOptions Options { get; init; }
    public required Logger Log { get; init; }

    /// <summary>Per-pass change counters, printed in the final summary.</summary>
    public Dictionary<string, int> Stats { get; } = new();

    /// <summary>What the detector decided about this assembly.</summary>
    public DetectionResult Detection { get; set; } = DetectionResult.None;

    public void Count(string key, int n = 1)
    {
        Stats.TryGetValue(key, out int cur);
        Stats[key] = cur + n;
    }

    public bool Changed => Stats.Values.Any(v => v > 0);
}

/// <summary>Outcome of the Agile.NET detector.</summary>
public sealed class DetectionResult
{
    public bool IsAgile { get; init; }
    public string? Version { get; init; }
    public List<string> Markers { get; } = new();

    public static DetectionResult None => new() { IsAgile = false };
}
