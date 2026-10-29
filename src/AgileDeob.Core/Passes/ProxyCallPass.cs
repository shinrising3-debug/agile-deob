using AgileDeob.Core;
using AgileDeob.Util;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AgileDeob.Passes;

/// <summary>
/// Restores direct calls hidden behind proxy methods.
///
/// Agile.NET (and most proxy-call obfuscators) replaces <c>call Target</c> with
/// <c>call Proxy</c>, where <c>Proxy</c> is a tiny static forwarder whose whole
/// body is "push args, call/callvirt the real target, ret". This pass detects
/// those pure forwarders and rewrites each call site to hit the real target,
/// then lets the cleanup pass delete the now-unused proxies.
///
/// This handles the simplest and most common forwarder shape. The delegate-field
/// variant (lazy <c>ldsfld delegate; ... callvirt Invoke</c>) is detected and
/// reported but not yet rewritten — see README for the resolution strategy.
/// </summary>
public sealed class ProxyCallPass : IDeobfuscatorPass
{
    public string Name => "proxies";
    public string Description => "inline proxy/forwarder method calls";

    public void Execute(DeobContext ctx)
    {
        // Map each forwarder method to the inner call it performs, so we can
        // replay both the opcode (call vs callvirt) and the target at the site.
        var forwarders = new Dictionary<MethodDef, Instruction>();

        foreach (TypeDef type in ctx.Module.GetTypes())
        foreach (MethodDef method in type.Methods)
        {
            if (TryGetForwardCall(method, out Instruction? inner) && inner is not null)
                forwarders[method] = inner;
        }

        if (forwarders.Count == 0)
        {
            ctx.Log.Debug("no simple proxy forwarders found");
            return;
        }

        ctx.Log.Info($"found {forwarders.Count} proxy forwarder(s)");

        int rewritten = 0;
        foreach (TypeDef type in ctx.Module.GetTypes())
        foreach (MethodDef method in type.Methods)
        {
            if (!method.HasBody)
                continue;

            foreach (Instruction instr in method.Body.Instructions)
            {
                if (!instr.IsCall())
                    continue;
                MethodDef? callee = instr.ResolveCalledMethod();
                if (callee is null || !forwarders.TryGetValue(callee, out Instruction? inner))
                    continue;

                // Replay the forwarder's own call: opcode (call/callvirt) + target.
                instr.OpCode = inner.OpCode;
                instr.Operand = inner.Operand;
                rewritten++;
            }
        }

        ctx.Count("proxy-forwarders", forwarders.Count);
        ctx.Count("proxy-calls-rewritten", rewritten);
        if (rewritten > 0)
            ctx.Log.Good($"rewrote {rewritten} proxied call(s)");
    }

    /// <summary>
    /// A pure forwarder loads all of its parameters in order, performs exactly
    /// one call/callvirt, and returns. Recognizing exactly this shape avoids
    /// mis-inlining a method that does real work.
    /// </summary>
    private static bool TryGetForwardCall(MethodDef method, out Instruction? call)
    {
        call = null;
        if (!method.IsStatic || !method.HasBody)
            return false;

        IList<Instruction> instrs = method.Body.Instructions;

        // Expect: ldarg.0 .. ldarg.(n-1), call X, ret   (nops tolerated)
        int expectedArg = 0;
        Instruction? theCall = null;

        foreach (Instruction instr in instrs)
        {
            switch (instr.OpCode.Code)
            {
                case Code.Nop:
                    continue;
                case Code.Ldarg_0:
                case Code.Ldarg_1:
                case Code.Ldarg_2:
                case Code.Ldarg_3:
                case Code.Ldarg:
                case Code.Ldarg_S:
                    if (GetArgIndex(instr) != expectedArg)
                        return false;
                    expectedArg++;
                    continue;
                case Code.Call:
                case Code.Callvirt:
                    if (theCall is not null)
                        return false; // more than one call -> not a pure forwarder
                    theCall = instr;
                    continue;
                case Code.Ret:
                    if (theCall is null)
                        return false;
                    if (expectedArg != method.Parameters.Count)
                        return false; // didn't forward every parameter
                    // Don't inline a self-call, and require a real target.
                    if (theCall.Operand is not IMethod target || ReferenceEquals(target, method))
                        return false;
                    call = theCall;
                    return true;
                default:
                    return false; // any real work disqualifies it
            }
        }

        return false;
    }

    private static int GetArgIndex(Instruction instr) => instr.OpCode.Code switch
    {
        Code.Ldarg_0 => 0,
        Code.Ldarg_1 => 1,
        Code.Ldarg_2 => 2,
        Code.Ldarg_3 => 3,
        Code.Ldarg or Code.Ldarg_S => ((Parameter)instr.Operand).Index,
        _ => -1,
    };
}
