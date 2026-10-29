using AgileDeob.Detection;
using AgileDeob.Passes;
using AgileDeob.Util;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

namespace AgileDeob.Core;

/// <summary>
/// Top-level driver: load → detect → run passes → write.
/// </summary>
public sealed class Deobfuscator
{
    private readonly DeobOptions _options;
    private readonly Logger _log;

    private readonly IDeobfuscatorPass[] _passes =
    {
        new StringDecryptPass(),
        new ProxyCallPass(),
        new ControlFlowPass(),
        new CleanupPass(),
    };

    public Deobfuscator(DeobOptions options, Logger log)
    {
        _options = options;
        _log = log;
    }

    public int Run()
    {
        if (!File.Exists(_options.InputPath))
        {
            _log.Error($"input not found: {_options.InputPath}");
            return 2;
        }

        _log.Info($"loading {_options.InputPath}");
        ModuleDefMD module;
        try
        {
            module = ModuleDefMD.Load(_options.InputPath);
        }
        catch (Exception ex)
        {
            _log.Error($"failed to load module: {ex.Message}");
            return 2;
        }

        var ctx = new DeobContext { Module = module, Options = _options, Log = _log };

        // --- Detection ---
        ctx.Detection = new AgileDetector(_log).Detect(module);
        if (ctx.Detection.IsAgile)
            _log.Good($"detected Agile.NET (version: {ctx.Detection.Version}) — " +
                      $"{ctx.Detection.Markers.Count} marker(s)");
        else
            _log.Warn("Agile.NET not confidently detected");

        if (_options.DetectOnly)
        {
            foreach (string m in ctx.Detection.Markers)
                _log.Info($"  marker: {m}");
            return ctx.Detection.IsAgile ? 0 : 1;
        }

        if (!ctx.Detection.IsAgile && !_options.Force)
        {
            _log.Error("not Agile.NET; refusing to rewrite (use --force to override)");
            return 1;
        }

        // --- Passes ---
        foreach (IDeobfuscatorPass pass in _passes)
        {
            _log.Info($"=== pass: {pass.Name} — {pass.Description}");
            try
            {
                pass.Execute(ctx);
            }
            catch (Exception ex)
            {
                _log.Error($"pass '{pass.Name}' failed: {ex.Message}");
                _log.Debug(ex.ToString());
            }
        }

        PrintSummary(ctx);

        if (!ctx.Changed)
        {
            _log.Warn("nothing changed; not writing an output file");
            return 0;
        }

        // --- Write ---
        string outPath = _options.ResolveOutputPath();
        try
        {
            WriteModule(module, outPath);
            _log.Good($"wrote cleaned assembly: {outPath}");
            return 0;
        }
        catch (Exception ex)
        {
            _log.Error($"failed to write output: {ex.Message}");
            _log.Debug(ex.ToString());
            return 3;
        }
    }

    private static void WriteModule(ModuleDefMD module, string outPath)
    {
        // Preserve mixed-mode/native data where present; fall back to managed.
        if (module.IsILOnly)
        {
            var opts = new ModuleWriterOptions(module)
            {
                MetadataOptions = { Flags = MetadataFlags.PreserveAll },
            };
            module.Write(outPath, opts);
        }
        else
        {
            var opts = new NativeModuleWriterOptions(module, optimizeImageSize: true)
            {
                MetadataOptions = { Flags = MetadataFlags.PreserveAll },
            };
            module.NativeWrite(outPath, opts);
        }
    }

    private void PrintSummary(DeobContext ctx)
    {
        _log.Info("--- summary ---");
        if (ctx.Stats.Count == 0)
        {
            _log.Info("  (no changes)");
            return;
        }

        foreach (var kv in ctx.Stats.OrderBy(k => k.Key))
            _log.Info($"  {kv.Key,-24} {kv.Value}");
    }
}
