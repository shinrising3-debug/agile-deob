namespace AgileDeob.Reinject;

/// <summary>
/// One method's real body, as captured at JIT time by the IL dumper.
/// </summary>
public sealed class MethodDump
{
    public uint Token { get; init; }          // 0x06xxxxxx MethodDef token
    public ulong Scope { get; init; }         // JIT module handle: identifies the owning module within the run
    public ushort MaxStack { get; init; }
    public bool InitLocals { get; init; }
    public byte[] Il { get; init; } = Array.Empty<byte>();
    public byte[] LocalSig { get; init; } = Array.Empty<byte>(); // raw StandAloneSig LocalSig blob (may be empty)
    public ExceptionClause[] Handlers { get; init; } = Array.Empty<ExceptionClause>();
}

/// <summary>A raw exception-handling clause, offsets in IL bytes.</summary>
public sealed class ExceptionClause
{
    public uint Flags { get; init; }          // 0=catch 1=filter 2=finally 4=fault
    public uint TryOffset { get; init; }
    public uint TryLength { get; init; }
    public uint HandlerOffset { get; init; }
    public uint HandlerLength { get; init; }
    public uint ClassTokenOrFilterOffset { get; init; }
}

/// <summary>
/// Reader for the <c>.ildump</c> container the dumper writes.
///
/// Format (little-endian):
///   char[8]  "ILDUMP02"
///   u32      methodCount
///   methodCount × record:
///     u32 token
///     u64 scope           (JIT module handle; module identity within the run)
///     u16 maxStack
///     u16 flags           (bit0 = initLocals)
///     u32 ilSize
///     u32 localSigLen
///     u32 ehCount
///     u8[ilSize]      il
///     u8[localSigLen] localSig
///     ehCount × { u32 flags, tryOff, tryLen, handlerOff, handlerLen, classTokOrFilterOff }
/// </summary>
public static class DumpReader
{
    public const string Magic = "ILDUMP02";

    public static IReadOnlyList<MethodDump> Read(string path)
    {
        using var fs = File.OpenRead(path);
        using var r = new BinaryReader(fs);

        byte[] magic = r.ReadBytes(8);
        if (System.Text.Encoding.ASCII.GetString(magic) != Magic)
            throw new InvalidDataException($"not an {Magic} dump: {path}");

        uint count = r.ReadUInt32();
        var list = new List<MethodDump>((int)Math.Min(count, 1 << 20));

        for (uint i = 0; i < count; i++)
        {
            uint token = r.ReadUInt32();
            ulong scope = r.ReadUInt64();
            ushort maxStack = r.ReadUInt16();
            ushort flags = r.ReadUInt16();
            uint ilSize = r.ReadUInt32();
            uint localSigLen = r.ReadUInt32();
            uint ehCount = r.ReadUInt32();

            byte[] il = r.ReadBytes((int)ilSize);
            byte[] localSig = r.ReadBytes((int)localSigLen);

            var handlers = new ExceptionClause[ehCount];
            for (uint h = 0; h < ehCount; h++)
            {
                handlers[h] = new ExceptionClause
                {
                    Flags = r.ReadUInt32(),
                    TryOffset = r.ReadUInt32(),
                    TryLength = r.ReadUInt32(),
                    HandlerOffset = r.ReadUInt32(),
                    HandlerLength = r.ReadUInt32(),
                    ClassTokenOrFilterOffset = r.ReadUInt32(),
                };
            }

            list.Add(new MethodDump
            {
                Token = token,
                Scope = scope,
                MaxStack = maxStack,
                InitLocals = (flags & 1) != 0,
                Il = il,
                LocalSig = localSig,
                Handlers = handlers,
            });
        }

        return list;
    }
}
