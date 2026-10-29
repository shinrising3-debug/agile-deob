using AgileDeob.Core;

namespace AgileDeob.Passes;

/// <summary>
/// A single cleanup stage. Passes run in order; each mutates the module in the
/// context and records what it changed via <see cref="DeobContext.Count"/>.
/// </summary>
public interface IDeobfuscatorPass
{
    /// <summary>Short name shown in logs and the summary (e.g. "strings").</summary>
    string Name { get; }

    /// <summary>One-line description of what the pass does.</summary>
    string Description { get; }

    void Execute(DeobContext ctx);
}
