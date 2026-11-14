using System.Buffers;
using System.Net;
using System.Net.WebSockets;
using System.Text;

namespace CoreServer;

// One connected device: receive loop, registration and its own send queue.
sealed class Peer(WebSocket ws, IPAddress ip, BatchingStream? stream)
{
    readonly SendQueue queue = new();

    public string? Address { get; private set; }
    public int Slot { get; private set; } // index in Registry, valid once Address is set
    // pre-encoded JSON used to stamp package_info.from: "7-850" and ,"from":"7-850"
    public byte[] FromValue { get; private set; } = [];
    public byte[] FromProperty { get; private set; } = [];
    public string? DeviceType { get; private set; }

    public bool IsOpen => ws.State == WebSocketState.Open;

    public async Task RunAsync(CancellationToken stopping)
    {
        var sending = queue.RunAsync(ws, stream);
        _ = DropIfUnregisteredAsync();
        Send(Protocol.GetAddr);
        try
        {
            await ReceiveLoopAsync(stopping);
        }
        catch (Exception e)
        {
            Log.Debug($"Socket error: {e.Message}");
        }
        finally
        {
            Log.Debug($"Disconnected address: {Address} ({ip})");
            Registry.Release(this);
            queue.Close();
            await sending;
            if (ws.State == WebSocketState.CloseReceived)
            {
                try { await ws.CloseOutputAsync(ws.CloseStatus ?? WebSocketCloseStatus.NormalClosure, null, CancellationToken.None); }
                catch { /* closing anyway */ }
            }
            ws.Abort();
        }
    }

    async Task ReceiveLoopAsync(CancellationToken stopping)
    {
        // size of the previous message: the next buffer starts that big, so a stream of big
        // packets doesn't regrow 16 -> 32 -> 64 -> 128 KB (copying every time) for each packet
        int expected = Config.ReceiveBufferBytes;
        while (true)
        {
            // Zero-byte read: waits for the next message WITHOUT holding a buffer, so an idle
            // peer pins no memory. Returns once a frame header has arrived (pings are answered inside).
            var result = await ws.ReceiveAsync(Memory<byte>.Empty, stopping);
            if (result.MessageType == WebSocketMessageType.Close) return;

            byte[] buffer = ArrayPool<byte>.Shared.Rent(expected);
            bool bufferTaken = false;
            try
            {
                // A message longer than the buffer arrives in several reads (EndOfMessage = false),
                // so keep reading into a bigger buffer. (An empty message is already complete here.)
                int length = 0;
                while (!result.EndOfMessage)
                {
                    if (length == buffer.Length) buffer = Grow(buffer, length);
                    result = await ws.ReceiveAsync(buffer.AsMemory(length), stopping);
                    if (result.MessageType == WebSocketMessageType.Close) return;
                    length += result.Count;
                    if (length > Config.MaxPayloadBytes) return;
                }
                expected = Math.Max(length, Config.ReceiveBufferBytes);

                // the protocol is text-only
                if (result.MessageType == WebSocketMessageType.Text)
                {
                    try
                    {
                        // true = the buffer itself was forwarded (zero-copy) and now belongs to a send queue
                        bufferTaken = Protocol.Dispatch(this, buffer, length);
                    }
                    catch (Exception e)
                    {
                        // a bad packet must never take the server down
                        Log.Debug($"Failed to process message: {e}");
                    }
                }
            }
            finally
            {
                if (!bufferTaken) ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }

    static byte[] Grow(byte[] buffer, int length)
    {
        byte[] bigger = ArrayPool<byte>.Shared.Rent(buffer.Length * 2);
        buffer.AsSpan(0, length).CopyTo(bigger);
        ArrayPool<byte>.Shared.Return(buffer);
        return bigger;
    }

    // A socket that never introduces itself is dropped.
    async Task DropIfUnregisteredAsync()
    {
        await Task.Delay(Config.RegistrationTimeoutMs);
        if (Address == null && IsOpen)
        {
            Log.Debug($"Registration timeout, dropping socket ({ip})");
            ws.Abort();
        }
    }

    // === sending ===
    // Control messages: a peer that doesn't read them is disconnected.
    public void Send(Outgoing message)
    {
        if (!queue.TryEnqueueControl(message))
        {
            Log.Debug($"Peer {Address} is not reading, terminating");
            ws.Abort();
        }
    }

    public bool CanAcceptPacket(int length) => IsOpen && queue.HasRoom(length);

    // Data packets: dropped when this peer's queue is full. Takes ownership of the buffer.
    public bool SendPacket(Outgoing packet)
    {
        if (IsOpen && queue.TryEnqueue(packet)) return true;
        packet.Release();
        return false;
    }

    // === handlers ===
    public void OnDeviceType(ReadOnlySpan<byte> data)
    {
        string? type = Protocol.IsString(data, "address-machine"u8) ? "address-machine"
                     : Protocol.IsString(data, "modem"u8) ? "modem"
                     : null;
        if (type == null)
        {
            Send(Protocol.InvalidDeviceType);
            return;
        }
        DeviceType = type;
        Log.Debug($"A new {type} has recently connected!");
    }

    // "get-device-type" is only requested after a SUCCESSFUL registration.
    public void OnSelfAddr(string? addr)
    {
        if (Address != null)
        {
            // one socket = one address, otherwise a client could flood the registry
            Send(Protocol.InvalidAddr);
            return;
        }

        if (addr is "0" or "")
        {
            string? address = Registry.TryAllocate(this);
            if (address == null)
            {
                Send(Protocol.NoFreeAddr);
                return;
            }
            Log.Debug($"SMLAed address for the device: {address}");
            Send(Protocol.SetModemLocalAddress(address));
        }
        else
        {
            var blocks = addr is { Length: <= 64 } ? Addresses.Parse(addr) : null;
            string? address = blocks != null && Addresses.IsSlave(blocks) ? string.Join('-', blocks) : null;
            if (address == null ||  !Registry.TryClaim(this, address))
            {
                Send(Protocol.InvalidAddr);
                return;
            }
            Send(Protocol.AddrOk);
        }

        Send(Protocol.GetDeviceType);
    }

    // called by Registry only
    public void SetAddress(string address, int slot)
    {
        Slot = slot;
        FromValue = Encoding.UTF8.GetBytes($"\"{address}\"");
        FromProperty = Encoding.UTF8.GetBytes($",\"from\":\"{address}\"");
        Address = address;
    }
}
