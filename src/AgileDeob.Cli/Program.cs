using AgileDeob.Core;
using AgileDeob.Reinject;
using AgileDeob.Util;

const string Usage = """
  agile-deob — an Agile.NET (SecureTeam / CliSecure) deobfuscator
  for CTF and reverse-engineering practice.

  USAGE:
    agile-deob <input.dll|exe> [options]       deobfuscate / detect
    agile-deob reinject <input> --bodies <f>   re-inject dumped method IL

  DEOBFUSCATE OPTIONS:
    -o, --output <path>   Output path (default: <input>-cleaned.<ext>)
        --detect          Only detect & report; do not rewrite
        --dynamic         Invoke the target's string decrypter in-process to
                          recover plaintext. RUNS UNTRUSTED CODE — use a VM.
        --force           Rewrite even if Agile.NET isn't detected
    -v, --verbose         Debug logging
    -h, --help            This help

  REINJECT OPTIONS (for native-method-encryption targets):
    --bodies <file>       .ildump produced by the JIT dumper (required)
    -o, --output <path>   Output path (default: <input>-restored.<ext>)
    -v, --verbose         Debug logging

  EXAMPLES:
    agile-deob Protected.exe --detect
    agile-deob reinject Protected.dll --bodies Protected.ildump -o Restored.dll
  """;

var log = new Logger();

// ---- subcommand: reinject ----
if (args.Length > 0 && args[0] == "reinject")
    return RunReinject(args[1..], log);

// ---- default: deobfuscate / detect ----
var options = new DeobOptions();
var positionals = new List<string>();
for (int i = 0; i < args.Length; i++)
{
    string a = args[i];
    switch (a)
    {
        case "-h" or "--help":
            Console.WriteLine(Usage);
            return 0;
        case "-o" or "--output":
            if (++i >= args.Length) { log.Error("--output needs a value"); return 2; }
            options.OutputPath = args[i];
            break;
        case "--detect": options.DetectOnly = true; break;
        case "--dynamic": options.AllowDynamic = true; break;
        case "--force": options.Force = true; break;
        case "-v" or "--verbose": options.LogLevel = LogLevel.Debug; break;
        default:
            if (a.StartsWith('-')) { log.Error($"unknown option: {a}"); return 2; }
            positionals.Add(a);
            break;
    }
}

if (positionals.Count != 1)
{
    Console.WriteLine(Usage);
    return positionals.Count == 0 ? 0 : 2;
}

options.InputPath = positionals[0];
log.Level = options.LogLevel;
return new Deobfuscator(options, log).Run();

// ---- local functions ----
static int RunReinject(string[] args, Logger log)
{
    string? input = null, bodies = null, output = null;
    for (int i = 0; i < args.Length; i++)
    {
        string a = args[i];
        switch (a)
        {
            case "--bodies":
                if (++i >= args.Length) { log.Error("--bodies needs a value"); return 2; }
                bodies = args[i];
                break;
            case "-o" or "--output":
                if (++i >= args.Length) { log.Error("--output needs a value"); return 2; }
                output = args[i];
                break;
            case "-v" or "--verbose":
                log.Level = LogLevel.Debug;
                break;
            default:
                if (a.StartsWith('-')) { log.Error($"unknown option: {a}"); return 2; }
                if (input is null) input = a;
                else { log.Error($"unexpected argument: {a}"); return 2; }
                break;
        }
    }

    if (input is null || bodies is null)
    {
        log.Error("usage: agile-deob reinject <input> --bodies <file.ildump> [-o <out>]");
        return 2;
    }

    return new BodyReinjector(log).Run(input, bodies, output);
}
