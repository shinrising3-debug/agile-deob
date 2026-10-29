using AgileDeob.Core;
using AgileDeob.Util;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AgileDeob.Passes;

/// <summary>
/// Control-flow cleanup.
///
/// This pass currently does the SAFE, local peephole part:
///   • strip redundant nops,
///   • fold <c>br</c>/<c>br.s</c> that jump to the immediately following
///     instruction,
///   • collapse a <c>switch</c> whose selector is a compile-time-constant
///     <c>ldc.i4</c> into a single unconditional branch (a common residue once
///     the state variable is constant-folded).
///
/// The HARD part — reversing Agile.NET's switch-dispatch flattening, where a
/// single loop + state variable drives a switch over the real basic blocks — is
/// intentionally left as a documented skeleton (<see cref="RecoverFlattenedDispatch"/>).
/// Doing it properly means building a basic-block graph, tracking the state
/// variable, and relinking blocks in original order; that's the de4dot "blocks"
/// framework. See README → "Control-flow recovery" for the plan.
/// </summary>
public sealed class ControlFlowPass : IDeobfuscatorPass
{
    public string Name => "cflow";
    public string Description => "peephole control-flow cleanup (dispatch recovery stubbed)";

    public void Execute(DeobContext ctx)
    {
        int removedNops = 0, foldedBranches = 0, collapsedSwitches = 0;

        foreach (TypeDef type in ctx.Module.GetTypes())
        foreach (MethodDef method in type.Methods)
        {
            if (!method.HasBody)
                continue;

            CilBody body = method.Body;
            body.SimplifyMacros(method.Parameters); // normalize for easier matching

            collapsedSwitches += CollapseConstantSwitches(body);
            foldedBranches += FoldBranchToNext(body);

            // RecoverFlattenedDispatch(ctx, method);  // <- not yet implemented

            removedNops += StripNops(body);

            body.OptimizeMacros(); // re-compact (ldc.i4 -> ldc.i4.s, etc.)
            body.OptimizeBranches();
        }

        ctx.Count("nops-removed", removedNops);
        ctx.Count("branches-folded", foldedBranches);
        ctx.Count("switches-collapsed", collapsedSwitches);

        if (removedNops + foldedBranches + collapsedSwitches > 0)
            ctx.Log.Good(
                $"cflow: -{removedNops} nops, {foldedBranches} branches folded, " +
                $"{collapsedSwitches} switches collapsed");
    }

    /// <summary>switch(constant) -> br targets[constant] (or fallthrough).</summary>
    private static int CollapseConstantSwitches(CilBody body)
    {
        int count = 0;
        IList<Instruction> instrs = body.Instructions;
        for (int i = 1; i < instrs.Count; i++)
        {
            if (instrs[i].OpCode.Code != Code.Switch)
                continue;
            Instruction prev = instrs[i - 1];
            if (!prev.IsLdcI4())
                continue;

            var targets = (Instruction[])instrs[i].Operand;
            int sel = prev.GetLdcI4Value();

            prev.Nop();
            if (sel >= 0 && sel < targets.Length)
            {
                instrs[i].OpCode = OpCodes.Br;
                instrs[i].Operand = targets[sel];
            }
            else
            {
                // Out of range falls through; drop the switch.
                instrs[i].Nop();
            }

            count++;
        }

        return count;
    }

    /// <summary>Unconditional branch to the very next instruction is a no-op.</summary>
    private static int FoldBranchToNext(CilBody body)
    {
        int count = 0;
        IList<Instruction> instrs = body.Instructions;
        for (int i = 0; i + 1 < instrs.Count; i++)
        {
            Instruction cur = instrs[i];
            if (cur.OpCode.Code is Code.Br or Code.Br_S &&
                ReferenceEquals(cur.Operand, instrs[i + 1]))
            {
                cur.Nop();
                count++;
            }
        }

        return count;
    }

    private static int StripNops(CilBody body)
    {
        IList<Instruction> instrs = body.Instructions;
        int before = instrs.Count;

        // Build a map from each nop to its successor so branch targets survive.
        var nops = instrs.Where(i => i.OpCode.Code == Code.Nop).ToHashSet();
        if (nops.Count == 0)
            return 0;

        Instruction? NextNonNop(int from)
        {
            for (int j = from; j < instrs.Count; j++)
                if (!nops.Contains(instrs[j]))
                    return instrs[j];
            return null;
        }

        // Redirect any branch/target pointing at a nop to the next real instr.
        for (int i = 0; i < instrs.Count; i++)
        {
            if (instrs[i].Operand is Instruction target && nops.Contains(target))
            {
                int idx = instrs.IndexOf(target);
                instrs[i].Operand = NextNonNop(idx) ?? target;
            }
            else if (instrs[i].Operand is Instruction[] switchTargets)
            {
                for (int t = 0; t < switchTargets.Length; t++)
                {
                    if (nops.Contains(switchTargets[t]))
                    {
                        int idx = instrs.IndexOf(switchTargets[t]);
                        switchTargets[t] = NextNonNop(idx) ?? switchTargets[t];
                    }
                }
            }
        }

        // Fix exception-handler boundaries that landed on a nop, then remove.
        foreach (ExceptionHandler eh in body.ExceptionHandlers)
        {
            eh.TryStart = SkipNop(eh.TryStart, nops, instrs);
            eh.TryEnd = SkipNop(eh.TryEnd, nops, instrs);
            eh.HandlerStart = SkipNop(eh.HandlerStart, nops, instrs);
            eh.HandlerEnd = SkipNop(eh.HandlerEnd, nops, instrs);
            eh.FilterStart = SkipNop(eh.FilterStart, nops, instrs);
        }

        for (int i = instrs.Count - 1; i >= 0; i--)
        {
            if (nops.Contains(instrs[i]))
                instrs.RemoveAt(i);
        }

        body.UpdateInstructionOffsets();
        return before - instrs.Count;
    }

    private static Instruction? SkipNop(Instruction? instr, HashSet<Instruction> nops, IList<Instruction> instrs)
    {
        if (instr is null || !nops.Contains(instr))
            return instr;
        int idx = instrs.IndexOf(instr);
        for (int j = idx; j < instrs.Count; j++)
            if (!nops.Contains(instrs[j]))
                return instrs[j];
        return instr;
    }

    /// <summary>
    /// TODO: reverse switch-dispatch flattening.
    ///
    /// Sketch of the real algorithm (de4dot "blocks" style):
    ///   1. Split the method body into basic blocks.
    ///   2. Identify the dispatcher: the block containing the state-variable
    ///      load + switch that routes to every real block.
    ///   3. For each real block, determine the constant it assigns to the state
    ///      variable before branching back to the dispatcher — that encodes the
    ///      successor.
    ///   4. Rebuild a normal CFG by linking blocks per those constants, drop the
    ///      dispatcher and the state variable, and re-emit in topological order.
    ///
    /// Left unimplemented on purpose: it needs a proper block/graph abstraction
    /// and careful handling of exception regions. The peephole passes above are
    /// enough to clean up constant-folded residue on many CTF samples.
    /// </summary>
    private static void RecoverFlattenedDispatch(DeobContext ctx, MethodDef method)
        => throw new NotImplementedException();
}
