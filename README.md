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

This is honest about what works. The easy/mechanical parts are wired up; the
hard part (reversing control-flow flattening) is **not finished**, so on a
heavily-protected assembly a decompiler will still show mangled method bodies.

| Agile.NET protection | Pass | Status |
|---|---|---|
| String encryption | `strings` | ✅ finds sites; ✅ decrypts & inlines **in `--dynamic` mode** |
| Proxy / forwarder calls | `proxies` | ✅ pure static forwarders inlined; ⏳ delegate-field variant detected only |
| Control-flow flattening | `cflow` | 🟡 peephole cleanup only; ⏳ **dispatch recovery not implemented** |
| Encrypted resources / native stub | (detector) | 🔎 detected, not stripped |
| Junk attributes | `cleanup` | ✅ removed |

**Making this actually beat de4dot on a specific sample requires tuning the
passes to that sample's exact protection.** If a particular DLL isn't cleaning
up, the protection shape in *that file* is what the next passes have to target.

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
agile-deob <input.dll|exe> [options]
  -o, --output <path>   Output path (default: <input>-cleaned.<ext>)
      --detect          Only detect & report; don't rewrite
      --dynamic         Invoke the target's string decrypter (RUNS THE FILE)
      --force           Rewrite even if Agile.NET isn't detected
  -v, --verbose         Debug logging
```

---

## Architecture

```
AgileDeob.sln
└─ src/
   ├─ AgileDeob.Core/        class library — all the logic (cross-platform)
   │   ├─ Core/              options, context, the Deobfuscator driver, dynamic invoker
   │   ├─ Detection/         heuristic Agile.NET fingerprinting
   │   ├─ Passes/            StringDecrypt · ProxyCall · ControlFlow · Cleanup
   │   └─ Util/              logger, IL helpers
   ├─ AgileDeob.Cli/         console front end (net8.0)
   └─ AgileDeob.Gui/         WinForms drag-and-drop front end (net8.0-windows)
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
