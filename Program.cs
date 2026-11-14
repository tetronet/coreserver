using System.Net;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets;
using CoreServer;

try
{
    Config.Load(args);
}
catch (ConfigException e)
{
    Log.Error($"Bad configuration: {e.Message}");
    return 1;
}

if (Math.Pow(10, Config.SmlaLength) < Config.MaxClients)
{
    Log.Error($"WARNING: only {Math.Pow(10, Config.SmlaLength)} slave addresses exist but MaxClients is {Config.MaxClients}");
}

if (Config.UseTls)
{
    try
    {
        Tls.Load();
    }
    catch (Exception e)
    {
        Log.Error($"Cannot read TLS certificate files: {e.Message}");
        return 1;
    }
    Tls.ReloadOnSighup();
}

var builder = WebApplication.CreateSlimBuilder(args);
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(2));
// Small kernel send buffers (accepted sockets inherit them from the listener): otherwise the OS
// auto-grows them to megabytes, the send loop never sees backpressure and a slow peer's packets
// wait there for seconds, out of reach of MaxQueueDelayMs.
// NOTE: don't set UnsafePreferInlineScheduling. Tested: a client that floods without pause then keeps
// the I/O thread busy, other clients miss their pings and get dropped (and big TLS packets got 2.5x slower).
builder.WebHost.UseSockets(o => o.CreateBoundListenSocket = endpoint =>
{
    var socket = SocketTransportOptions.CreateDefaultBoundListenSocket(endpoint);
    socket.SendBufferSize = Config.SocketSendBufferBytes;
    return socket;
});
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.AddServerHeader = false;
    kestrel.Limits.MaxResponseBufferSize = Config.SocketSendBufferBytes;
    kestrel.ListenAnyIP(Config.Port, listen =>
    {
        listen.Protocols = HttpProtocols.Http1; // WebSocket over plain HTTP/1.1 upgrade, as before
        if (Config.UseTls)
        {
            listen.UseHttps(new TlsHandshakeCallbackOptions
            {
                OnConnection = _ => ValueTask.FromResult(Tls.Options),
            });
        }
    });
});

var app = builder.Build();
var stopping = app.Lifetime.ApplicationStopping;
IcspNet.Start(stopping);

// the WebSocket gets a BatchingStream under it, so the send loop can write many messages at once
app.Use((context, next) =>
{
    var upgrade = context.Features.Get<IHttpUpgradeFeature>();
    if (upgrade is { IsUpgradableRequest: true })
        context.Features.Set<IHttpUpgradeFeature>(new BatchingStream.UpgradeFeature(upgrade, context.Features));
    return next(context);
});

// raw WebSocket, no compression; dead connections are dropped after missing one ping
app.UseWebSockets(new WebSocketOptions
{
    KeepAliveInterval = Config.Heartbeat,
    KeepAliveTimeout = Config.Heartbeat,
});

// every path accepts the WebSocket upgrade
app.Run(async context =>
{
    if (!context.WebSockets.IsWebSocketRequest)
    {
        context.Response.StatusCode = StatusCodes.Status426UpgradeRequired;
        return;
    }

    var ip = context.Connection.RemoteIpAddress ?? IPAddress.None;
    if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();

    // like the old server: accept the first subprotocol the client offers, if any
    var requested = context.WebSockets.WebSocketRequestedProtocols;
    using var ws = await context.WebSockets.AcceptWebSocketAsync(
        new WebSocketAcceptContext { SubProtocol = requested.Count > 0 ? requested[0] : null });

    if (!Registry.TryConnect(ip))
    {
        Log.Debug($"Connection refused (too many clients): {ip}");
        try { await ws.CloseOutputAsync((System.Net.WebSockets.WebSocketCloseStatus)1013, "Try again later", CancellationToken.None); }
        catch { /* client is gone already */ }
        return;
    }

    try
    {
        await new Peer(ws, ip, context.Features.Get<BatchingStream>()).RunAsync(stopping);
    }
    finally
    {
        Registry.Disconnect(ip);
    }
});

Log.Info($"Core server {Config.LocalAddress} listening on port {Config.Port} ({(Config.UseTls ? "wss" : "ws")}), config: {Config.Path}");
await app.RunAsync();
return 0;
