using AgileDeob.Core;
using AgileDeob.Detection;
using AgileDeob.Util;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AgileDeob.Passes;

/// <summary>
/// Recovers encrypted string literals.
///
/// Agile.NET replaces <c>ldstr "secret"</c> with <c>ldc.i4 &lt;key&gt; ; call
/// string Decrypter(int)</c>. This pass:
///   1. locates the decrypter method (heuristically),
///   2. (in --dynamic mode) invokes it per key to recover the plaintext,
///   3. rewrites each call site back into a plain <c>ldstr</c>.
///
/// Without --dynamic we can't know the plaintext, so we only locate and report
/// the call sites. Static emulation of the decrypter is a natural next step and
/// is sketched in the README.
/// </summary>
public sealed class StringDecryptPass : IDeobfuscatorPass
{
    public string Name => "strings";
    public string Description => "decrypt and inline Agile.NET string literals";

    public void Execute(DeobContext ctx)
    {
        MethodDef? decrypter = AgileDetector.FindStringDecrypterCandidate(ctx.Module);
        if (decrypter is null)
        {
            ctx.Log.Debug("no string decrypter candidate found; skipping");
            return;
        }

        ctx.Log.Info($"string decrypter candidate: {decrypter.FullName}");

        Func<int, string?>? decrypt = null;
        DynamicInvoker? invoker = null;
        if (ctx.Options.AllowDynamic)
        {
            invoker = DynamicInvoker.Load(ctx.Options.InputPath, ctx.Log);
            decrypt = invoker.GetStringDecrypter(decrypter);
        }

        using (invoker)
        {
            int sites = 0, inlined = 0;

            foreach (TypeDef type in ctx.Module.GetTypes())
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody)
                        continue;

                    IList<Instruction> instrs = method.Body.Instructions;
                    for (int i = 0; i + 1 < instrs.Count; i++)
                    {
                        Instruction ldc = instrs[i];
                        Instruction call = instrs[i + 1];

                        if (!ldc.IsLdcI4() || !call.IsCall())
                            continue;
                        if (call.ResolveCalledMethod() != decrypter)
                            continue;

                        sites++;
                        int key = ldc.GetLdcI4Value();

                        if (decrypt is null)
                        {
                            ctx.Log.Debug($"  {method.Name}: call site key={key} (needs --dynamic to resolve)");
                            continue;
                        }

                        string? plain = decrypt(key);
                        if (plain is null)
                            continue;

                        // ldc.i4 key  -> nop
                        // call decrypt -> ldstr plain
                        ldc.Nop();
                        call.OpCode = OpCodes.Ldstr;
                        call.Operand = plain;
                        inlined++;
                        ctx.Log.Debug($"  {method.Name}: key={key} -> \"{Truncate(plain)}\"");
                    }
                }
            }

            ctx.Count("string-call-sites", sites);
            ctx.Count("strings-inlined", inlined);

            if (inlined > 0)
                ctx.Log.Good($"inlined {inlined}/{sites} encrypted strings");
            else if (sites > 0)
                ctx.Log.Warn($"found {sites} string call sites; re-run with --dynamic to decrypt");
        }
    }

    private static string Truncate(string s, int max = 48) =>
        s.Length <= max ? s : s[..max] + "…";
}
