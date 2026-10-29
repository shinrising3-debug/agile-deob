# agile-deob

An **Agile.NET** (SecureTeam, formerly *CliSecure*) deobfuscator with a
**drag-and-drop Windows GUI**, built on [dnlib](https://github.com/0xd4d/dnlib) —
the metadata/IL library behind [de4dot](https://github.com/de4dot/de4dot) and
dnSpy.

Built as a **reverse-engineering / CTF learning tool**. Use it on binaries you
have the right to analyze (your own builds, CTF challenges, malware samples in a
lab).

> **Drop a `.dll`/`.exe` onto the window (or onto the `.exe` icon) → it writes a
> cleaned `<name>-cleaned.<ext>` next to the original and shows the log.**

---

## ⚠ Status — read this first

Agile.NET ships in several strengths. **Which one you're facing decides whether a
static tool can help at all**, so the detector tells you, and the toolset has two
tracks.

### Track A — static (managed obfuscation)
For string encryption / proxy calls / control-flow / junk attributes, where the
real IL is on disk:

| Protection | Pass | Status |
|---|---|---|
| String encryption | `strings` | ✅ finds sites; ✅ decrypts & inlines in `--dynamic` mode |
| Proxy / forwarder calls | `proxies` | ✅ pure static forwarders inlined; ⏳ delegate-field variant detected only |
| Control-flow flattening | `cflow` | 🟡 peephole cleanup; ⏳ dispatch recovery not implemented |
| Junk attributes | `cleanup` | ✅ removed |

### Track B — dynamic (native method encryption)
Agile.NET's strongest mode (`AgileDotNetRT`) **replaces every method body on disk
with a stub** and decrypts the real IL at JIT time in native code. **No static
tool — this one, de4dot, anything — can recover it**, because the code isn't in
the file. You must capture it at runtime and write it back:

```
tools/IlDumper  (JIT-hook, captures decrypted IL while the app runs)
      │   out.ildump
      ▼
agile-deob reinject target.dll --bodies out.ildump   →   target-restored.dll
```

The detector reports which track applies (`agile-deob <file> --detect`). If it
says **native method encryption**, Track A is irrelevant — go straight to
[Native method encryption](#native-method-encryption).

---

## Build

Requires the **.NET 8 SDK**. The GUI is **Windows-only** (WinForms); the core and
CLI are cross-platform.

```bash
# Everything (on Windows):
dotnet build -c Release

# The drag-and-drop GUI (Windows only):
dotnet build -c Release src/AgileDeob.Gui
#   → src/AgileDeob.Gui/bin/Release/net8.0-windows/agile-deob-gui.exe

# The CLI (any OS):
dotnet build -c Release src/AgileDeob.Cli
#   → src/AgileDeob.Cli/bin/Release/net8.0/agile-deob
```

> This was scaffolded in a Linux container with no .NET SDK, so it has **not been
> compiled or run**. Build on Windows and report errors — the code targets the
> dnlib 4.4.0 API.

---

## Usage

### GUI (`agile-deob-gui.exe`)
Launch it and drag a file onto the window, or drag a file straight onto the
`.exe` in Explorer. Tick **--dynamic** only if you accept that it *runs the
target's code* to recover strings (do it in a VM).

### CLI (`agile-deob`)
```
agile-deob <input.dll|exe> [options]        deobfuscate / detect
  -o, --output <path>   Output path (default: <input>-cleaned.<ext>)
      --detect          Only detect & report; don't rewrite
      --dynamic         Invoke the target's string decrypter (RUNS THE FILE)
      --force           Rewrite even if Agile.NET isn't detected
  -v, --verbose         Debug logging

agile-deob reinject <input> --bodies <f>    re-inject runtime-dumped IL
  --bodies <file>       .ildump produced by tools/IlDumper (required)
  -o, --output <path>   Output path (default: <input>-restored.<ext>)
```

---

## Native method encryption

If `--detect` reports **native method encryption** (`AgileDotNetRT` + mostly stub
bodies), the real IL is not in the file and the static passes can't help. Recover
it in three steps:

1. **Dump at runtime.** Build `tools/IlDumper`, inject it into the host process
   (e.g. NinjaTrader), and exercise the code so every method JITs. It writes an
   `.ildump` of the decrypted bodies. See [`tools/IlDumper/README.md`](tools/IlDumper/README.md)
   — note the two runtime-specific vtable indices you must set first.
2. **Re-inject.** `agile-deob reinject target.dll --bodies out.ildump -o Restored.dll`
   parses each captured body against the module and replaces the stub. It
   auto-selects the right module scope from a process-wide dump (many modules'
   methods share token values, so each record carries its JIT module handle).
3. **Read.** Open `Restored.dll` in dnSpy/ILSpy — the real methods are back (for
   every code path you exercised in step 1).

Coverage equals what you ran: methods never executed stay stubs. This is dynamic
unpacking, so it's inherently partial — but it's the only thing that works
against native method encryption.

---

## Architecture

```
AgileDeob.sln
├─ src/
│  ├─ AgileDeob.Core/        class library — all the logic (cross-platform)
│  │   ├─ Core/              options, context, the Deobfuscator driver, dynamic invoker
│  │   ├─ Detection/         Agile.NET fingerprinting (incl. native-RT / stub detection)
│  │   ├─ Passes/            StringDecrypt · ProxyCall · ControlFlow · Cleanup
│  │   ├─ Reinject/          .ildump reader + body re-injector (Track B)
│  │   └─ Util/              logger, IL helpers
│  ├─ AgileDeob.Cli/         console front end (net8.0): deobfuscate + reinject
│  └─ AgileDeob.Gui/         WinForms drag-and-drop front end (net8.0-windows)
└─ tools/
   └─ IlDumper/             native JIT-hook IL dumper + injector (C++, Windows x64)
```

Both front ends call the same `Deobfuscator` in the core. Passes run in order and
record what they changed; the GUI captures the log via `Logger.Sink`. Add a pass
by implementing `IDeobfuscatorPass` and registering it in `Deobfuscator._passes`.

---

## Roadmap (the real work)

1. **Control-flow recovery** — reverse switch-dispatch flattening (basic-block
   graph + state-variable tracking; the de4dot "blocks" approach). Biggest win.
2. **Delegate-field proxy calls** — resolve lazy `ldsfld delegate; … Invoke`.
3. **Static string decryption** — a small IL emulator so `--dynamic` isn't needed.
4. **Dead-code removal** — drop now-unused forwarders/helper types safely.
5. **Resource / native-stub stripping.**

---

## Credits

Stands on **de4dot** (its `AgileDotNet` module is the reference) and
**dnlib/dnSpy** by 0xd4d. If you need a proven tool today, try de4dot first; this
repo exists to build and understand one.
