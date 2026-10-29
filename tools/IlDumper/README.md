# IlDumper — runtime IL capture for Agile.NET native method encryption

When an assembly uses Agile.NET's **native** runtime (`AgileDotNetRT`), the real
method IL is never on disk — it's decrypted at JIT time by native code. The only
way to recover it is to capture it **as the process runs**. IlDumper does that by
hooking the JIT; `agile-deob reinject` then writes the captured bodies back over
the on-disk stubs.

```
NinjaTrader (running the protected indicator)
        │  IlDumper.dll hooks ICorJitCompiler::compileMethod
        ▼
   out.ildump  ──►  agile-deob reinject target.dll --bodies out.ildump
                        ▼
                   target-restored.dll   (open in dnSpy — real methods)
```

> ⚠️ **Status: reference implementation, not yet validated.** It was written
> without a Windows/.NET build+test loop. Two vtable indices are runtime-specific
> and **must be set** (see *Tuning*) before it can produce a usable dump. Treat
> the first run as a bring-up exercise, not a one-click tool.

---

## Why this (and not de4dot / a static tool)

Static tools rewrite IL on disk. Here **~89% of method bodies are stubs** and the
real IL exists only inside the running process. No amount of static analysis can
recover it — you have to be there when the JIT compiles each method. That's the
whole reason de4dot can't touch this target.

---

## Build

Open an **x64 Native Tools Command Prompt for VS** (so you build 64-bit, matching
NinjaTrader 8), then:

```bat
cd tools\IlDumper
build.bat
```

Produces `dumper.dll` and `inject.exe`.

---

## Tuning (required)

`corjit_min.h` has two indices into the `ICorJitInfo` vtable that depend on your
exact `clr.dll` / `clrjit.dll` build:

```c
#define IDX_getMethodDefFromMethod 0   // token lookup — REQUIRED
#define IDX_getEHinfo              0   // exception-handler lookup — needed for try/catch
```

With them left at `0`, the dumper runs safely but records **no tokens** (so
`reinject` finds zero matches) and **no exception handlers**. You must find the
right indices for your runtime. Options, easiest first:

1. **Ask me.** Tell me your exact .NET Framework build (run
   `[System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription`
   in PowerShell, and note the `clr.dll` file version). I'll map the indices.
2. **Symbols/WinDbg.** With the Microsoft symbol server, the `ICorJitInfo`
   vtable layout is recoverable; `getMethodDefFromMethod` and `getEHinfo` are the
   slots to count.
3. **Cross-reference open source.** The method order in `ICorJitInfo` matches
   `corjit.h` / `ICorJitInfo` for the matching CLR version on GitHub.

Rebuild after editing the header.

---

## Run

```bat
REM 1. choose where the dump goes
set ILDUMP_OUT=C:\work\lume.ildump

REM 2. start NinjaTrader (from the SAME shell so it inherits ILDUMP_OUT)
"C:\Program Files\NinjaTrader 8\bin\NinjaTrader.exe"

REM 3. inject the dumper
inject.exe NinjaTrader.exe dumper.dll

REM 4. in NinjaTrader, add the protected indicator to a chart and USE it:
REM    change parameters, let bars update, open its settings — every code path
REM    you exercise gets JIT-compiled and therefore dumped.

REM 5. close NinjaTrader cleanly (so the final flush writes), then:
agile-deob reinject "C:\...\Lume....dll" --bodies C:\work\lume.ildump -o Restored.dll
```

Only methods that actually **execute** get JIT'd and dumped. Exercise as many
features as you can to maximise coverage; methods never hit will stay stubs in
the restored assembly.

---

## Caveats & honesty

- **It runs the target.** You're executing the licensed indicator and its native
  anti-tamper. Do it on a machine you're comfortable with; a VM/snapshot is wise.
- **Anti-tamper may notice the hook.** Agile.NET's RT can checksum the JIT
  path. If it detects the hook it may refuse to run or wipe IL. If dumps come up
  empty even with correct indices, this is the likely cause and the next problem
  to solve (hook later, or hook `getJit` instead of the vtable slot).
- **x64 only**, matching NinjaTrader 8's 64-bit CLR. The struct layouts in
  `corjit_min.h` assume x64 .NET Framework 4.x.
- **Coverage = what you run.** This is dynamic unpacking, so it's inherently
  partial. Generics instantiated at runtime may dump per-instantiation.

When you have a build running, send me what the first dump looks like (how many
methods, whether `reinject` matches a scope) and we'll iterate from real output.
