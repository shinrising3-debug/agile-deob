namespace AgileDeob.Util;

public enum LogLevel
{
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

/// <summary>
/// Dead-simple leveled logger. Writes to the console by default, but a UI can
/// supply <see cref="Sink"/> to capture lines (e.g. into a text box). No
/// dependencies on purpose so the tool stays easy to read.
/// </summary>
public sealed class Logger
{
    public LogLevel Level { get; set; } = LogLevel.Info;

    /// <summary>
    /// If set, formatted lines go here instead of the console (colors dropped).
    /// </summary>
    public Action<LogLevel, string>? Sink { get; set; }

    public Logger(LogLevel level = LogLevel.Info) => Level = level;

    public void Error(string msg) => Write(LogLevel.Error, "!!", ConsoleColor.Red, msg);
    public void Warn(string msg) => Write(LogLevel.Warn, " !", ConsoleColor.Yellow, msg);
    public void Info(string msg) => Write(LogLevel.Info, "  ", ConsoleColor.Gray, msg);
    public void Good(string msg) => Write(LogLevel.Info, " +", ConsoleColor.Green, msg);
    public void Debug(string msg) => Write(LogLevel.Debug, " .", ConsoleColor.DarkGray, msg);

    private void Write(LogLevel level, string tag, ConsoleColor color, string msg)
    {
        if (level > Level)
            return;

        string line = $"[{tag}] {msg}";

        if (Sink is not null)
        {
            Sink(level, line);
            return;
        }

        ConsoleColor prev = Console.ForegroundColor;
        try
        {
            Console.ForegroundColor = color;
            Console.WriteLine(line);
        }
        finally
        {
            Console.ForegroundColor = prev;
        }
    }
}
