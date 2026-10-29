using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AgileDeob.Util;

/// <summary>
/// Small IL helpers. dnlib already exposes a lot of this, but having named
/// helpers keeps the pass code readable.
/// </summary>
public static class InstructionExtensions
{
    /// <summary>True for any ldc.i4 / ldc.i4.s / ldc.i4.0..8 / ldc.i4.m1.</summary>
    public static bool IsLdcI4(this Instruction instr)
    {
        switch (instr.OpCode.Code)
        {
            case Code.Ldc_I4_M1:
            case Code.Ldc_I4_0:
            case Code.Ldc_I4_1:
            case Code.Ldc_I4_2:
            case Code.Ldc_I4_3:
            case Code.Ldc_I4_4:
            case Code.Ldc_I4_5:
            case Code.Ldc_I4_6:
            case Code.Ldc_I4_7:
            case Code.Ldc_I4_8:
            case Code.Ldc_I4_S:
            case Code.Ldc_I4:
                return true;
            default:
                return false;
        }
    }

    /// <summary>Reads the int32 value of any ldc.i4 form.</summary>
    public static int GetLdcI4Value(this Instruction instr)
    {
        switch (instr.OpCode.Code)
        {
            case Code.Ldc_I4_M1: return -1;
            case Code.Ldc_I4_0: return 0;
            case Code.Ldc_I4_1: return 1;
            case Code.Ldc_I4_2: return 2;
            case Code.Ldc_I4_3: return 3;
            case Code.Ldc_I4_4: return 4;
            case Code.Ldc_I4_5: return 5;
            case Code.Ldc_I4_6: return 6;
            case Code.Ldc_I4_7: return 7;
            case Code.Ldc_I4_8: return 8;
            case Code.Ldc_I4_S: return (sbyte)instr.Operand;
            case Code.Ldc_I4: return (int)instr.Operand;
            default:
                throw new InvalidOperationException($"not an ldc.i4: {instr.OpCode}");
        }
    }

    /// <summary>Turns an instruction into a no-op in place (preserves branch targets).</summary>
    public static void Nop(this Instruction instr)
    {
        instr.OpCode = OpCodes.Nop;
        instr.Operand = null;
    }

    /// <summary>Is this a direct or virtual method call?</summary>
    public static bool IsCall(this Instruction instr) =>
        instr.OpCode.Code is Code.Call or Code.Callvirt;

    /// <summary>
    /// Resolves the called method to an in-module <see cref="MethodDef"/>, or
    /// null for external/MemberRef calls.
    ///
    /// We intentionally only match MethodDef operands (and generic calls whose
    /// MethodSpec points at a MethodDef): the decrypter and proxy forwarders we
    /// rewrite are always defined in this module, so dnlib hands us the real
    /// MethodDef instance and reference-equality against module methods holds.
    /// Resolving MemberRefs to other assemblies would be both unnecessary and
    /// risky for rewriting.
    /// </summary>
    public static MethodDef? ResolveCalledMethod(this Instruction instr)
    {
        if (!instr.IsCall())
            return null;

        return instr.Operand switch
        {
            MethodDef md => md,
            MethodSpec { Method: MethodDef md2 } => md2,
            _ => null,
        };
    }
}
