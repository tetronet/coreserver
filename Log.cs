using System.Diagnostics;

namespace CoreServer;

static class Log
{
    // Calls to this method, INCLUDING building the message, are removed by the compiler
    // unless DEBUG_LOG is defined (see CoreServer.csproj). So it costs nothing in production.
    [Conditional("DEBUG_LOG")]
    public static void Debug(string text) => Console.WriteLine(text);

    public static void Info(string text) => Console.WriteLine(text);

    public static void Error(string text) => Console.Error.WriteLine(text);
}
