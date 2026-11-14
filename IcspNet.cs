using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace CoreServer;

// One "wires" entry from config.json: "host", "host:port", "[ipv6]" or "[ipv6]:port".
sealed record Wire(string Name, string Host, int Port, int Index)
{
    public const int DefaultPort = 6336; // standard ICSP-over-TCP port

    public override string ToString() => Host.Contains(':') ? $"[{Host}]:{Port}" : $"{Host}:{Port}";

    public static Wire? Parse(string text, int index)
    {
        text = text.Trim();
        string host;
        string? port = null;
        if (text.StartsWith('['))
        {
            int close = text.IndexOf(']');
            if (close < 0) return null;
            host = text[1..close];
            string rest = text[(close + 1)..];
            if (rest.Length > 0)
            {
                if (rest[0] != ':') return null;
                port = rest[1..];
            }
        }
        else
        {
            int colon = text.IndexOf(':');
            bool hostPort = colon >= 0 && colon == text.LastIndexOf(':'); // more colons = bare IPv6
            host = hostPort ? text[..colon] : text;
            if (hostPort) port = text[(colon + 1)..];
        }
        int number = DefaultPort;
        if (port != null && !int.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out number)) return null;
        if (host.Length == 0 || host.Contains(' ') || number is < 1 or > 65535) return null;
        return new Wire(text, host, number, index);
    }
}

// The ICSP network side: dials every wire (and redials when it drops), accepts neighbors on
// icsp_port (only from the IPs of the wires), and keeps one connection per neighbor core server.
static class IcspNet
{
    static readonly Lock gate = new();
    static readonly Dictionary<string, IcspLink> bound = [];      // neighbor address -> its one link
    static readonly IPAddress[][] wireIps = new IPAddress[Config.Wires.Length][];
    static long lastResolveAll, lastRefusalLog;

    public static bool Enabled => Config.Wires.Length > 0;

    public static void Start(CancellationToken stopping)
    {
        if (!Enabled) return;
        for (int i = 0; i < wireIps.Length; i++) wireIps[i] = [];
        foreach (var wire in Config.Wires) _ = DialLoopAsync(wire, stopping);
        if (Config.IcspPort != 0) _ = ListenAsync(stopping);
        _ = Routes.RunAsync(stopping);
        Log.Info($"ICSP: core server {Config.LocalAddress}, {Config.Wires.Length} wire(s)" +
                 (Config.IcspPort != 0 ? $", listening on port {Config.IcspPort}" : ", not listening"));
    }

    // === one link per neighbor ===
    // Two core servers that list each other get two TCP connections. Both sides keep the same one:
    // the connection dialed by the server with the smaller address (ordinal string compare).
    // Returns false if `link` lost (it is closed then); a losing older link is closed here.
    public static bool TryBind(IcspLink link, string neighbor)
    {
        IcspLink? loser;
        lock (gate)
        {
            if (!bound.TryGetValue(neighbor, out var other) || other.IsClosed)
            {
                bound[neighbor] = link;
                return true;
            }
            bool weDialFirst = string.CompareOrdinal(Config.LocalAddress, neighbor) < 0;
            bool keepNew = link.Dialed != other.Dialed && link.Dialed == weDialFirst;
            if (keepNew)
            {
                bound[neighbor] = link;
                loser = other;
                loser.DuplicateOf = link;
            }
            else
            {
                loser = link;
                loser.DuplicateOf = other;
            }
        }
        loser.Close($"duplicate connection to core server {neighbor}");
        return loser != link;
    }

    public static void Unbind(IcspLink link)
    {
        string? neighbor = link.Neighbor;
        if (neighbor == null) return;
        lock (gate)
        {
            if (bound.TryGetValue(neighbor, out var current) && current == link) bound.Remove(neighbor);
        }
    }

    public static IcspLink[] ReadyLinks()
    {
        lock (gate)
        {
            return bound.Values.Where(l => l.Ready).ToArray();
        }
    }

    // === outgoing ===
    static async Task DialLoopAsync(Wire wire, CancellationToken stopping)
    {
        bool reported = false; // log the first failure in a row, not every retry
        while (!stopping.IsCancellationRequested)
        {
            IcspLink? link = null;
            Socket? socket = null;
            try
            {
                var ips = await ResolveAsync(wire, stopping);
                socket = NewSocket();
                using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(stopping))
                {
                    timeout.CancelAfter(Config.IcspTimeoutMs);
                    await socket.ConnectAsync(ips, wire.Port, timeout.Token);
                }
                link = new IcspLink(socket, dialed: true, wire.ToString(), [Config.WireKeys[wire.Index]]);
                await link.RunAsync();
                if (link.WasReady) reported = false;
                else if (link.DuplicateOf == null && !reported)
                {
                    reported = true;
                    Log.Info($"ICSP: {wire} accepted the connection but never introduced itself (does it have our IP in its wires and the same key in seckeys?)");
                }
            }
            catch (Exception e) when (!stopping.IsCancellationRequested)
            {
                socket?.Dispose();
                if (!reported) Log.Info($"ICSP: can't connect to {wire}: {(e is OperationCanceledException ? "timeout" : e.Message)}");
                reported = true;
            }
            catch (OperationCanceledException)
            {
                socket?.Dispose();
                break;
            }
            try
            {
                // the neighbor is connected the other way round: wait until that connection drops
                if (link?.DuplicateOf is { } winner) await winner.Closed.WaitAsync(stopping);
                await Task.Delay(Config.IcspReconnectMs, stopping);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    static async Task<IPAddress[]> ResolveAsync(Wire wire, CancellationToken stopping)
    {
        var ips = IPAddress.TryParse(wire.Host, out var ip) ? [ip] : await Dns.GetHostAddressesAsync(wire.Host, stopping);
        ips = ips.Select(Normalize).ToArray();
        Volatile.Write(ref wireIps[wire.Index], ips);
        if (ips.Length == 0) throw new SocketException((int)SocketError.HostNotFound);
        return ips;
    }

    static IPAddress Normalize(IPAddress ip) => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;

    static Socket NewSocket()
    {
        // an IPv6 socket in dual mode reaches IPv4 addresses too
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true }; // frames are batched by the link
        socket.SendBufferSize = Config.SocketSendBufferBytes;
        return socket;
    }

    // === incoming ===
    static async Task ListenAsync(CancellationToken stopping)
    {
        Socket listener;
        try
        {
            listener = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp) { DualMode = true };
            listener.Bind(new IPEndPoint(IPAddress.IPv6Any, Config.IcspPort));
        }
        catch (SocketException)
        {
            // no IPv6 on this machine
            listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Any, Config.IcspPort));
        }
        listener.SendBufferSize = Config.SocketSendBufferBytes; // accepted sockets inherit it
        listener.Listen(64);
        using (listener)
        {
            while (!stopping.IsCancellationRequested)
            {
                Socket socket;
                try
                {
                    socket = await listener.AcceptAsync(stopping);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException e)
                {
                    Log.Debug($"ICSP: accept failed: {e.Message}");
                    continue;
                }
                _ = HandleIncomingAsync(socket, stopping);
            }
        }
    }

    static async Task HandleIncomingAsync(Socket socket, CancellationToken stopping)
    {
        try
        {
            var remote = (IPEndPoint)socket.RemoteEndPoint!;
            var ip = Normalize(remote.Address);
            byte[][] keys = await KeysForAsync(ip, stopping);
            if (keys.Length == 0)
            {
                long now = Environment.TickCount64;
                if (now - Volatile.Read(ref lastRefusalLog) > 60_000)
                {
                    Volatile.Write(ref lastRefusalLog, now);
                    Log.Info($"ICSP: refused connection from {ip}: not one of the wires (logged at most once a minute)");
                }
                socket.Dispose();
                return;
            }
            socket.NoDelay = true;
            await new IcspLink(socket, dialed: false, new IPEndPoint(ip, remote.Port).ToString(), keys).RunAsync();
        }
        catch (Exception e)
        {
            Log.Debug($"ICSP: incoming connection failed: {e.Message}");
            socket.Dispose();
        }
    }

    // Only the wires' IPs may connect; returns the keys of the wires on that IP (none = refused).
    // An unknown IP triggers a fresh DNS lookup of all wires (at most every 30 s), in case a
    // neighbor's address changed.
    static async Task<byte[][]> KeysForAsync(IPAddress ip, CancellationToken stopping)
    {
        var keys = KeysFor(ip);
        if (keys.Length > 0) return keys;
        long now = Environment.TickCount64;
        long last = Volatile.Read(ref lastResolveAll);
        if (now - last < 30_000 || Interlocked.CompareExchange(ref lastResolveAll, now, last) != last) return keys;
        foreach (var wire in Config.Wires)
        {
            try { await ResolveAsync(wire, stopping); }
            catch (Exception e) when (e is SocketException or OperationCanceledException) { /* keep the old list */ }
        }
        return KeysFor(ip);
    }

    static byte[][] KeysFor(IPAddress ip)
    {
        var keys = new List<byte[]>();
        for (int i = 0; i < wireIps.Length; i++)
        {
            if (Volatile.Read(ref wireIps[i]).Contains(ip)) keys.Add(Config.WireKeys[i]);
        }
        return keys.ToArray();
    }
}
