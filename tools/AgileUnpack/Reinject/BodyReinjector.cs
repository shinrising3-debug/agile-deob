using AgileDeob.Util;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace AgileDeob.Reinject;

/// <summary>
/// Writes real method bodies (captured at runtime by the IL dumper) back over
/// the on-disk stubs, producing a normal, statically-analysable assembly.
///
/// This is the "second half" of unpacking an Agile.NET native-method-encryption
/// assembly: the dumper (a JIT hook) records each method's decrypted IL as it is
/// compiled; this re-injector parses that IL against the target module and
/// replaces <c>method.Body</c>. Because the dumped IL came from this exact
/// module, every metadata token in it already resolves here.
/// </summary>
public sealed class BodyReinjector
{
    private readonly Logger _log;

    // A StandAloneSig token (table 0x11) we hand to dnlib's body reader so it can
    // bind ldloc/stloc operands to the captured locals during parsing.
    private const uint LocalSigSentinel = 0x11FFFFFF;

    public BodyReinjector(Logger log) => _log = log;

    public int Run(string inputPath, string dumpPath, string? outputPath)
    {
        if (!File.Exists(inputPath)) { _log.Error($"input not found: {inputPath}"); return 2; }
        if (!File.Exists(dumpPath)) { _log.Error($"dump not found: {dumpPath}"); return 2; }

        IReadOnlyList<MethodDump> dumps;
        try { dumps = DumpReader.Read(dumpPath); }
        catch (Exception ex) { _log.Error($"bad dump: {ex.Message}"); return 2; }
        _log.Info($"dump: {dumps.Count} method bodies");

        ModuleDefMD module;
        try { module = ModuleDefMD.Load(inputPath); }
        catch (Exception ex) { _log.Error($"load failed: {ex.Message}"); return 2; }

        // A process-wide JIT dump holds methods from many modules, whose tokens
        // collide. Pick the scope whose tokens best match THIS module's methods.
        IReadOnlyList<MethodDump> scoped = SelectBestScope(module, dumps);

        int injected = 0, notFound = 0, failed = 0;
        foreach (MethodDump d in scoped)
        {
            if (module.ResolveToken(d.Token, default) is not MethodDef method)
            {
                notFound++;
                _log.Debug($"token 0x{d.Token:X8} not a MethodDef in this module");
                continue;
            }

            try
            {
                method.Body = BuildBody(module, method, d);
                injected++;
                _log.Debug($"injected {method.FullName} ({d.Il.Length} IL bytes)");
            }
            catch (Exception ex)
            {
                failed++;
                _log.Warn($"failed to inject {method.FullName}: {ex.Message}");
            }
        }

        _log.Good($"injected {injected}, not-found {notFound}, failed {failed}");

        string outPath = outputPath ?? DefaultOutput(inputPath);
        try
        {
            var opts = new ModuleWriterOptions(module)
            {
                MetadataOptions = { Flags = MetadataFlags.PreserveAll },
            };
            module.Write(outPath, opts);
            _log.Good($"wrote {outPath}");
            return 0;
        }
        catch (Exception ex)
        {
            _log.Error($"write failed: {ex.Message}");
            return 3;
        }
    }

    /// <summary>
    /// Group the dump by its per-record module handle and keep only the group
    /// whose MethodDef tokens most often resolve in the target module. This
    /// filters out framework methods the process-wide JIT hook also captured.
    /// </summary>
    private IReadOnlyList<MethodDump> SelectBestScope(ModuleDefMD module, IReadOnlyList<MethodDump> dumps)
    {
        var byScope = dumps.GroupBy(d => d.Scope).ToList();
        if (byScope.Count <= 1)
            return dumps;

        ulong bestScope = 0;
        int bestMatches = -1;
        foreach (var g in byScope)
        {
            int matches = g.Count(d => module.ResolveToken(d.Token, default) is MethodDef);
            _log.Debug($"scope 0x{g.Key:X} : {g.Count()} methods, {matches} resolve here");
            if (matches > bestMatches)
            {
                bestMatches = matches;
                bestScope = g.Key;
            }
        }

        var chosen = dumps.Where(d => d.Scope == bestScope).ToList();
        _log.Info($"selected module scope 0x{bestScope:X} ({chosen.Count} methods, {bestMatches} resolvable) " +
                  $"out of {byScope.Count} scopes in dump");
        return chosen;
    }

    public static CilBody BuildBody(ModuleDefMD module, MethodDef method, MethodDump d)
    {
        // CorILMethod flags: fat format (0x3) + optional InitLocals (0x10).
        ushort flags = (ushort)(0x3 | (d.InitLocals ? 0x10 : 0));

        CilBody body;
        if (d.LocalSig.Length > 0 &&
            SignatureReader.ReadSig(module, d.LocalSig) is LocalSig localSig)
        {
            var resolver = new LocalSigResolver(module, LocalSigSentinel, localSig);
            body = MethodBodyReader.CreateCilBody(
                resolver, d.Il, Array.Empty<byte>(), method.Parameters,
                flags, d.MaxStack, (uint)d.Il.Length, LocalSigSentinel);
        }
        else
        {
            body = MethodBodyReader.CreateCilBody(
                module, d.Il, Array.Empty<byte>(), method.Parameters,
                flags, d.MaxStack, (uint)d.Il.Length, 0);
        }

        body.InitLocals = d.InitLocals;
        body.MaxStack = d.MaxStack;

        if (d.Handlers.Length > 0)
            AddHandlers(module, body, d);

        body.OptimizeMacros();
        Validate(body);   // throw on a malformed body so Run skips just this method
        return body;
    }

    /// <summary>
    /// Reject a rebuilt body that would fail to write (e.g. an unresolved token
    /// operand, or an exception region with a missing boundary). Throwing here
    /// lets <see cref="Run"/> keep the method's original stub and carry on,
    /// instead of one bad capture aborting the whole output.
    /// </summary>
    private static void Validate(CilBody body)
    {
        foreach (Instruction instr in body.Instructions)
        {
            if (instr.OpCode.OperandType != dnlib.DotNet.Emit.OperandType.InlineNone &&
                instr.Operand is null)
            {
                throw new InvalidOperationException(
                    $"unresolved operand for {instr.OpCode} (token not in this module?)");
            }
        }

        foreach (ExceptionHandler eh in body.ExceptionHandlers)
        {
            if (eh.TryStart is null || eh.HandlerStart is null)
                throw new InvalidOperationException("exception handler missing a required boundary");
            if (eh.HandlerType == ExceptionHandlerType.Catch && eh.CatchType is null)
                throw new InvalidOperationException("catch clause missing its exception type");
        }
    }

    /// <summary>Rebuild exception handlers by mapping IL offsets to instructions.</summary>
    private static void AddHandlers(ModuleDefMD module, CilBody body, MethodDump d)
    {
        var byOffset = new Dictionary<uint, Instruction>();
        foreach (Instruction instr in body.Instructions)
            byOffset[instr.Offset] = instr;

        Instruction? At(uint off) => byOffset.TryGetValue(off, out var i) ? i : null;

        foreach (ExceptionClause c in d.Handlers)
        {
            var eh = new ExceptionHandler((ExceptionHandlerType)c.Flags)
            {
                TryStart = At(c.TryOffset),
                TryEnd = At(c.TryOffset + c.TryLength),       // exclusive end (null => end of method)
                HandlerStart = At(c.HandlerOffset),
                HandlerEnd = At(c.HandlerOffset + c.HandlerLength),
            };

            switch ((ExceptionHandlerType)c.Flags)
            {
                case ExceptionHandlerType.Catch:
                    eh.CatchType = module.ResolveToken(c.ClassTokenOrFilterOffset, default) as ITypeDefOrRef;
                    break;
                case ExceptionHandlerType.Filter:
                    eh.FilterStart = At(c.ClassTokenOrFilterOffset);
                    break;
            }

            body.ExceptionHandlers.Add(eh);
        }
    }

    private static string DefaultOutput(string input)
    {
        string dir = Path.GetDirectoryName(Path.GetFullPath(input)) ?? ".";
        string name = Path.GetFileNameWithoutExtension(input);
        string ext = Path.GetExtension(input);
        return Path.Combine(dir, $"{name}-restored{ext}");
    }
}

/// <summary>
/// Delegates all token/string resolution to the module, except the one sentinel
/// StandAloneSig token, for which it returns the captured local signature. This
/// lets dnlib's body reader bind local-variable operands while parsing.
/// </summary>
internal sealed class LocalSigResolver : IInstructionOperandResolver
{
    private readonly ModuleDefMD _module;
    private readonly uint _sentinel;
    private readonly StandAloneSig _localsSig;

    public LocalSigResolver(ModuleDefMD module, uint sentinel, LocalSig localSig)
    {
        _module = module;
        _sentinel = sentinel;
        _localsSig = new StandAloneSigUser(localSig);
    }

    public IMDTokenProvider ResolveToken(uint token, GenericParamContext gpContext)
        => token == _sentinel ? _localsSig : _module.ResolveToken(token, gpContext);

    public string ReadUserString(uint token) => _module.ReadUserString(token);
}
