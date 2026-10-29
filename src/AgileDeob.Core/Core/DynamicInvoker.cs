using System.Reflection;
using AgileDeob.Util;
using dnlib.DotNet;

namespace AgileDeob.Core;

/// <summary>
/// Loads the target assembly into THIS process and resolves a dnlib
/// <see cref="MethodDef"/> to a reflection <see cref="MethodInfo"/> so the real
/// string decrypter can be invoked.
///
/// ⚠ SECURITY: This executes code from the target assembly. Agile.NET decrypter
/// stubs can run module/type initializers with side effects. Only enable this
/// (via --dynamic) against samples you are comfortable running, ideally inside a
/// throwaway VM/container. This is the same trade-off de4dot makes.
/// </summary>
public sealed class DynamicInvoker : IDisposable
{
    private readonly Logger _log;
    private readonly Assembly _asm;

    private DynamicInvoker(Logger log, Assembly asm)
    {
        _log = log;
        _asm = asm;
    }

    public static DynamicInvoker Load(string path, Logger log)
    {
        // LoadFile keeps it isolated from the already-loaded dnlib copy.
        Assembly asm = Assembly.LoadFile(Path.GetFullPath(path));
        log.Warn("dynamic mode: target assembly loaded into this process");
        return new DynamicInvoker(log, asm);
    }

    /// <summary>
    /// Resolves a dnlib method to a callable delegate of shape (int) -> string,
    /// matching the common Agile.NET decrypter signature.
    /// </summary>
    public Func<int, string?>? GetStringDecrypter(MethodDef method)
    {
        try
        {
            int token = (int)method.MDToken.Raw;
            MethodBase? resolved = _asm.ManifestModule.ResolveMethod(token);
            if (resolved is not MethodInfo mi)
            {
                _log.Warn($"could not resolve decrypter token 0x{token:X8} via reflection");
                return null;
            }

            return key =>
            {
                try
                {
                    object? result = mi.Invoke(null, new object[] { key });
                    return result as string;
                }
                catch (TargetInvocationException tie)
                {
                    _log.Debug($"decrypter threw for key {key}: {tie.InnerException?.Message}");
                    return null;
                }
            };
        }
        catch (Exception ex)
        {
            _log.Warn($"dynamic decrypter setup failed: {ex.Message}");
            return null;
        }
    }

    public void Dispose()
    {
        // Assemblies loaded via LoadFile into the default context cannot be
        // unloaded; nothing to free. A production tool would use a collectible
        // AssemblyLoadContext here.
    }
}
