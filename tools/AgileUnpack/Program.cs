using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using AgileDeob.Reinject;
using AgileDeob.Util;

namespace AgileUnpack
{
    // Standalone unpacker for Agile.NET native method encryption.
    //
    //   AgileUnpack <target.dll> [--refs <dir>] [-o <out.dll>] [--idx <file>]
    //
    // It installs the native JIT hook, loads the target, runs its module
    // initializer (so Agile's own runtime + JIT hook activate), then force-JITs
    // every method — which makes Agile decrypt each one — and the hook captures
    // the real IL. Finally it re-injects the captured bodies and writes a clean
    // DLL. No NinjaTrader session required; references are resolved from --refs
    // (your NinjaTrader\bin folder) so types load.
    internal static class Program
    {
        [DllImport("dumper.dll")] static extern int  Dumper_IsReady();
        [DllImport("dumper.dll")] static extern void Dumper_SetToken(uint tok);
        [DllImport("dumper.dll")] static extern void Dumper_Flush();
        [DllImport("dumper.dll")] static extern void Dumper_Stats(out uint seen, out uint written, out uint skippedEH);

        static string _refsDir;

        static int Main(string[] args)
        {
            string target = null, outPath = null, idx = null, refs = null;
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--refs": refs = args[++i]; break;
                    case "-o": case "--output": outPath = args[++i]; break;
                    case "--idx": idx = args[++i]; break;
                    default: target ??= args[i]; break;
                }
            }
            if (target == null)
            {
                Console.WriteLine("usage: AgileUnpack <target.dll> [--refs <NinjaTrader\\bin>] [-o <out.dll>] [--idx <file>]");
                return 2;
            }
            target = Path.GetFullPath(target);
            outPath ??= Path.Combine(Path.GetDirectoryName(target), Path.GetFileNameWithoutExtension(target) + "-restored.dll");
            _refsDir = refs != null ? Path.GetFullPath(refs) : Path.GetDirectoryName(target);
            string ildump = Path.Combine(Path.GetDirectoryName(target), "agileunpack.ildump");

            Environment.SetEnvironmentVariable("ILDUMP_OUT", ildump);
            Environment.SetEnvironmentVariable("ILDUMP_LOG", Path.ChangeExtension(ildump, ".log"));
            if (idx != null) Environment.SetEnvironmentVariable("ILDUMP_IDX", Path.GetFullPath(idx));

            Console.WriteLine($"[*] target : {target}");
            Console.WriteLine($"[*] refs   : {_refsDir}");
            Console.WriteLine($"[*] output : {outPath}");

            // 1. Install the native JIT hook BEFORE the target (and its Agile
            //    runtime) touch the JIT.
            if (Dumper_IsReady() == 0) { /* forces LoadLibrary + DllMain */ }
            for (int i = 0; i < 100 && Dumper_IsReady() == 0; i++) System.Threading.Thread.Sleep(50);
            Console.WriteLine(Dumper_IsReady() != 0 ? "[+] JIT hook ready" : "[!] JIT hook NOT ready (continuing anyway)");

            // 2. Resolve NinjaTrader.* and friends from the refs dir.
            AppDomain.CurrentDomain.AssemblyResolve += OnResolve;

            // 3. Load the target and run its module initializer (activates Agile RT).
            Assembly asm;
            try { asm = Assembly.LoadFrom(target); }
            catch (Exception ex) { Console.WriteLine($"[!] load failed: {ex.Message}"); return 1; }

            try { RuntimeHelpers.RunModuleConstructor(asm.ManifestModule.ModuleHandle); }
            catch (Exception ex) { Console.WriteLine($"[!] module initializer threw: {ex.Message}"); }

            // 4. Force-JIT every method so Agile decrypts it; feed each token to the hook.
            Type[] types = SafeGetTypes(asm);
            int tried = 0, jitted = 0, failed = 0;
            const BindingFlags F = BindingFlags.Instance | BindingFlags.Static |
                                   BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
            foreach (var t in types)
            {
                if (t == null || t.ContainsGenericParameters) continue;
                MethodBase[] members;
                try { members = t.GetMethods(F).Cast<MethodBase>().Concat(t.GetConstructors(F)).ToArray(); }
                catch { continue; }
                foreach (var m in members)
                {
                    if (m.IsAbstract || m.ContainsGenericParameters) continue;
                    tried++;
                    try
                    {
                        Dumper_SetToken((uint)m.MetadataToken);
                        RuntimeHelpers.PrepareMethod(m.MethodHandle);
                        jitted++;
                    }
                    catch { failed++; }
                }
            }

            Dumper_Flush();
            Dumper_Stats(out uint seen, out uint written, out uint skippedEH);
            Console.WriteLine($"[+] force-JIT: tried={tried} ok={jitted} failed={failed}");
            Console.WriteLine($"[+] captured : seen={seen} written={written} skipped-for-EH={skippedEH}");

            if (written == 0)
            {
                Console.WriteLine("[!] nothing captured — see the .log next to the target. Likely the");
                Console.WriteLine("    Agile runtime didn't initialize (missing refs?) or blocked the hook.");
                return 1;
            }

            // 5. Re-inject captured bodies -> clean DLL.
            int rc = new BodyReinjector(new Logger(LogLevel.Info)).Run(target, ildump, outPath);
            if (rc == 0) Console.WriteLine($"[+] DONE -> {outPath}  (open in dnSpy)");
            return rc;
        }

        static Assembly OnResolve(object sender, ResolveEventArgs e)
        {
            string name = new AssemblyName(e.Name).Name + ".dll";
            foreach (var dir in new[] { _refsDir })
            {
                if (dir == null) continue;
                string p = Path.Combine(dir, name);
                if (File.Exists(p))
                {
                    try { return Assembly.LoadFrom(p); } catch { }
                }
            }
            return null;
        }

        static Type[] SafeGetTypes(Assembly asm)
        {
            try { return asm.GetTypes(); }
            catch (ReflectionTypeLoadException ex)
            {
                Console.WriteLine($"[!] {ex.LoaderExceptions.Length} type(s) failed to load (missing refs?); continuing with the rest.");
                return ex.Types.Where(t => t != null).ToArray();
            }
        }
    }
}
