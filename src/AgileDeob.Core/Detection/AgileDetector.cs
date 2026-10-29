using AgileDeob.Core;
using AgileDeob.Util;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AgileDeob.Detection;

/// <summary>
/// Heuristic detector for Agile.NET (SecureTeam, formerly CliSecure) protected
/// assemblies.
///
/// NOTE: These are *heuristics* chosen to be readable, not the exact fingerprint
/// de4dot ships. Agile.NET has mutated across many versions; a production tool
/// pins version-specific markers. For a CTF/learning tool, scoring a handful of
/// structural signals is good enough and teaches what the protection looks like.
/// </summary>
public sealed class AgileDetector
{
    private readonly Logger _log;

    public AgileDetector(Logger log) => _log = log;

    public DetectionResult Detect(ModuleDefMD module)
    {
        var markers = new List<string>();

        if (HasEncryptedResources(module, out int encResCount))
            markers.Add($"encrypted-resources({encResCount})");

        if (FindStringDecrypterCandidate(module) is { } decrypter)
            markers.Add($"string-decrypter({decrypter.FullName})");

        if (HasModuleCctorInitializer(module))
            markers.Add("module-cctor-initializer");

        if (HasProxyDelegateFields(module, out int proxyCount))
            markers.Add($"proxy-delegate-fields({proxyCount})");

        foreach (string m in markers)
            _log.Debug($"marker: {m}");

        // Two or more independent structural signals -> treat as Agile.NET.
        bool isAgile = markers.Count >= 2;

        var result = new DetectionResult
        {
            IsAgile = isAgile,
            Version = isAgile ? GuessVersion(module) : null,
        };
        result.Markers.AddRange(markers);
        return result;
    }

    /// <summary>
    /// Agile.NET encrypts embedded resources; the payload is not a valid
    /// managed resource stream. We flag embedded resources whose first bytes
    /// are not the .NET resource magic and that are not obviously images/text.
    /// </summary>
    private static bool HasEncryptedResources(ModuleDefMD module, out int count)
    {
        count = 0;
        foreach (Resource res in module.Resources)
        {
            if (res is not EmbeddedResource emb)
                continue;

            byte[] data = emb.CreateReader().ToArray();
            if (data.Length < 4)
                continue;

            // .NET resource manager streams start with 0xBEEFCACE.
            uint magic = BitConverter.ToUInt32(data, 0);
            bool looksManaged = magic == 0xBEEFCACE;
            if (!looksManaged && LooksHighEntropy(data))
                count++;
        }

        return count > 0;
    }

    /// <summary>
    /// Classic Agile.NET string decrypter shape: a static method returning
    /// string, taking an int (token/index), reading from a byte[] field.
    /// </summary>
    public static MethodDef? FindStringDecrypterCandidate(ModuleDefMD module)
    {
        foreach (TypeDef type in module.GetTypes())
        {
            foreach (MethodDef method in type.Methods)
            {
                if (!method.IsStatic || !method.HasBody)
                    continue;
                if (method.ReturnType?.FullName != "System.String")
                    continue;
                if (method.Parameters.Count == 0)
                    continue;
                // First param is the token/index selector.
                string p0 = method.Parameters[0].Type?.FullName ?? "";
                if (p0 is not ("System.Int32" or "System.UInt32"))
                    continue;

                if (BodyTouchesByteArrayField(method))
                    return method;
            }
        }

        return null;
    }

    private static bool BodyTouchesByteArrayField(MethodDef method)
    {
        bool readsByteArrayField = false;
        bool doesStringWork = false;

        foreach (Instruction instr in method.Body.Instructions)
        {
            if (instr.OpCode.Code is Code.Ldsfld or Code.Ldfld &&
                instr.Operand is IField f &&
                f.FieldSig?.Type?.FullName == "System.Byte[]")
            {
                readsByteArrayField = true;
            }

            if (instr.OpCode.Code is Code.Xor or Code.Newobj or Code.Call &&
                instr.Operand is IMethod m &&
                m.DeclaringType?.FullName is "System.String" or "System.Text.Encoding")
            {
                doesStringWork = true;
            }
        }

        return readsByteArrayField && doesStringWork;
    }

    /// <summary>
    /// Agile.NET wires up decryption in the module/global type's static
    /// constructor (&lt;Module&gt;::.cctor), which reads its encrypted
    /// resources and installs runtime hooks.
    /// </summary>
    private static bool HasModuleCctorInitializer(ModuleDefMD module)
    {
        MethodDef? cctor = module.GlobalType?.FindStaticConstructor();
        if (cctor is null || !cctor.HasBody)
            return false;

        foreach (Instruction instr in cctor.Body.Instructions)
        {
            if (instr.OpCode.Code == Code.Call &&
                instr.Operand is IMethod m &&
                m.Name is "GetManifestResourceStream" or "GetExecutingAssembly")
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Proxy-call obfuscation leaves behind many static delegate-typed fields
    /// that get lazily initialized and invoked in place of direct calls.
    /// </summary>
    private static bool HasProxyDelegateFields(ModuleDefMD module, out int count)
    {
        count = 0;
        foreach (TypeDef type in module.GetTypes())
        {
            foreach (FieldDef field in type.Fields)
            {
                if (!field.IsStatic)
                    continue;
                // TryGetTypeDef resolves in-module types (where Agile.NET emits
                // its proxy delegate types); null for external refs, which we
                // don't care about here.
                TypeDef? ft = field.FieldSig?.Type?.TryGetTypeDef();
                if (ft is not null && ft.IsDelegate)
                    count++;
            }
        }

        // A handful of delegates is normal; a flood of them is a signal.
        return count >= 8;
    }

    private static string? GuessVersion(ModuleDefMD module)
    {
        // Placeholder: real version fingerprinting keys off the exact shape of
        // the decrypter / runtime stub, which differs per Agile.NET release.
        return "unknown";
    }

    /// <summary>Shannon-entropy rough check — encrypted blobs look near-random.</summary>
    private static bool LooksHighEntropy(byte[] data)
    {
        Span<int> freq = stackalloc int[256];
        int sample = Math.Min(data.Length, 4096);
        for (int i = 0; i < sample; i++)
            freq[data[i]]++;

        double entropy = 0;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0)
                continue;
            double p = (double)freq[i] / sample;
            entropy -= p * Math.Log2(p);
        }

        // 8 bits/byte is max; encrypted/compressed data sits above ~7.2.
        return entropy > 7.2;
    }
}
