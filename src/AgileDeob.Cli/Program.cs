using AgileDeob.Core;
using AgileDeob.Util;

const string Usage = """
  agile-deob — an Agile.NET (SecureTeam / CliSecure) deobfuscator
  for CTF and reverse-engineering practice.

  USAGE:
    agile-deob <input.dll|exe> [options]

  OPTIONS:
    -o, --output <path>   Output path (default: <input>-cleaned.<ext>)
        --detect          Only detect & report; do not rewrite
        --dynamic         Invoke the target's string decrypter in-process to
                          recover plaintext. RUNS UNTRUSTED CODE — use a VM.
        --force           Rewrite even if Agile.NET isn't detected
    -v, --verbose         Debug logging
    -h, --help            This help

  EXAMPLES:
    agile-deob Protected.exe --detect
    agile-deob Protected.exe --dynamic -o Clean.exe
  """;

var options = new DeobOptions();
var log = new Logger();

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
        case "--detect":
            options.DetectOnly = true;
            break;
        case "--dynamic":
            options.AllowDynamic = true;
            break;
        case "--force":
            options.Force = true;
            break;
        case "-v" or "--verbose":
            options.LogLevel = LogLevel.Debug;
            break;
        default:
            if (a.StartsWith('-'))
            {
                log.Error($"unknown option: {a}");
                return 2;
            }
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
