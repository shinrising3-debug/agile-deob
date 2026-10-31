// net48 compatibility shims so the shared Reinject sources (written for net8)
// compile here unchanged.

// `init` accessors need this type, which net48's BCL lacks.
namespace System.Runtime.CompilerServices
{
    internal static class IsExternalInit { }
}

// Minimal logger matching AgileDeob.Util.Logger's surface used by BodyReinjector.
namespace AgileDeob.Util
{
    public enum LogLevel { Error = 0, Warn = 1, Info = 2, Debug = 3 }

    public sealed class Logger
    {
        public LogLevel Level { get; set; } = LogLevel.Info;
        public Logger(LogLevel level = LogLevel.Info) => Level = level;
        public void Error(string m) => System.Console.WriteLine("[!!] " + m);
        public void Warn(string m) => System.Console.WriteLine("[ !] " + m);
        public void Info(string m) => System.Console.WriteLine("[  ] " + m);
        public void Good(string m) => System.Console.WriteLine("[ +] " + m);
        public void Debug(string m) { if (Level >= LogLevel.Debug) System.Console.WriteLine("[ .] " + m); }
    }
}
