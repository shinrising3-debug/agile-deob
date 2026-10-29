using AgileDeob.Core;
using AgileDeob.Util;
using dnlib.DotNet;

namespace AgileDeob.Passes;

/// <summary>
/// Final tidy-up. Removes obfuscator-injected attributes that have no meaning
/// once the protections are stripped, so decompilers show clean output.
///
/// Conservative by design: it only removes custom attributes whose declaring
/// type name matches known Agile.NET/obfuscator markers. It does NOT delete the
/// proxy forwarder bodies left behind by <see cref="ProxyCallPass"/> yet —
/// removing a method means proving no remaining references, which belongs behind
/// a reference-count check (see README → "Dead-code removal").
/// </summary>
public sealed class CleanupPass : IDeobfuscatorPass
{
    public string Name => "cleanup";
    public string Description => "remove obfuscator attributes and markers";

    private static readonly string[] AttributeMarkers =
    {
        "SecureTeam",
        "CliSecure",
        "Agile",
        "Obfuscat", // ObfuscationAttribute et al.
    };

    public void Execute(DeobContext ctx)
    {
        int removed = 0;
        removed += StripAttributes(ctx.Module.CustomAttributes);
        removed += StripAttributes(ctx.Module.Assembly?.CustomAttributes);

        foreach (TypeDef type in ctx.Module.GetTypes())
        {
            removed += StripAttributes(type.CustomAttributes);
            foreach (MethodDef m in type.Methods)
                removed += StripAttributes(m.CustomAttributes);
            foreach (FieldDef f in type.Fields)
                removed += StripAttributes(f.CustomAttributes);
        }

        ctx.Count("attributes-removed", removed);
        if (removed > 0)
            ctx.Log.Good($"removed {removed} obfuscator attribute(s)");
    }

    private static int StripAttributes(IList<CustomAttribute>? attrs)
    {
        if (attrs is null || attrs.Count == 0)
            return 0;

        int removed = 0;
        for (int i = attrs.Count - 1; i >= 0; i--)
        {
            string full = attrs[i].TypeFullName ?? "";
            if (AttributeMarkers.Any(m => full.Contains(m, StringComparison.OrdinalIgnoreCase)))
            {
                attrs.RemoveAt(i);
                removed++;
            }
        }

        return removed;
    }
}
