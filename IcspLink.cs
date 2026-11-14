using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace CoreServer;

// One ICSP connection to a neighbor core server: dialed by us (a "wires" entry) or accepted on icsp_port.
// A new object per TCP connection. It is "ready" (routes may use it) once the neighbor answered
// WhoAreYou with ImThis, and stops being ready forever when the connection closes.
//
// Sending: control frames (ImThis, keep-alives, routes) always go before data, so a link full of
// packets still answers keep-alives in time. Data is dropped when the queue is full or a packet
// waited longer than max_queue_delay_ms, like on WebSocket peers. Frames are sent in batches
// (one syscall for many small packets).
//
// Everything on the socket is encrypted (CableEncryption.cs). keys = the keys this connection may
// use: one for a dialed wire; for an accepted one, every wire on that IP, and the first record that
// decrypts picks the key (we send nothing until then).
sealed class IcspLink(Socket socket, bool dialed, string name, byte[][] keys)
{
    const int ReceiveBufferBytes = 256 * 1024;   // several big Transmit frames per read (there are few links)
    const int MaxBufferedFrame = 4 * 1024 * 1024; // bigger frames are skipped unread (unknown type, absurd size)
    const int SendBatchBytes = 256 * 1024;
    const int MaxControlBacklog = 10000;          // control frames a neighbor lets pile up before it's dropped

    readonly CancellationTokenSource cts = new();
    readonly TaskCompletionSource closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    readonly ConcurrentQueue<Outgoing> control = new();
    readonly ConcurrentQueue<(Outgoing Message, long Enqueued)> data = new();
    readonly SemaphoreSlim wake = new(0);
    int wakePending, controlCount, closing;
    long queuedBytes;
    long lastHeard;   // Environment.TickCount64 of the last received bytes
    volatile string? neighbor;
    // our salt goes out first; each direction has its own cipher (null = key or salt not known yet)
    readonly byte[] sendSalt = CableEncryption.NewSalt();
    CableCipher? receiveCipher;
    volatile CableCipher? sendCipher;
    static long lastSecurityLog;

    public bool Dialed { get; } = dialed;   // we connected to it (otherwise it connected to us)
    public string Name { get; } = name;     // remote endpoint, for logs
    public string? Neighbor => neighbor;    // its network address, from ImThis
    public bool Ready => neighbor != null && Volatile.Read(ref closing) == 0;
    public bool IsClosed => Volatile.Read(ref closing) != 0;
    public bool WasReady { get; private set; } // the neighbor introduced itself at some point
    public Task Closed => closed.Task;
    // set when this connection was closed because another one to the same neighbor wins
    public IcspLink? DuplicateOf { get; set; }
    // what the advertise loop has told this neighbor (Routes only)
    public readonly Routes.AdvertisedSet Advertised = new();

    public async Task RunAsync()
    {
        Log.Debug($"ICSP: connected to {Name}");
        Volatile.Write(ref lastHeard, Environment.TickCount64);
        if (keys.Length == 1) sendCipher = new CableCipher(keys[0], sendSalt);
        var sending = SendLoopAsync();
        var timer = KeepAliveLoopAsync();
        SendControl(Outgoing.Fixed(Icsp.WhoAreYouFrame));
        string why = "closed by the neighbor";
        try
        {
            await ReceiveLoopAsync();
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException or InvalidDataException)
        {
            why = e.Message;
        }
        catch (Exception e)
        {
            Log.Error($"ICSP: {Name}: {e}");
            why = "internal error";
        }
        finally
        {
            Close(why);
            await Task.WhenAll(sending, timer);
            DrainQueues();
            receiveCipher?.Dispose();
            sendCipher?.Dispose();
            closed.TrySetResult();
        }
    }

    // Safe to call from anywhere, any number of times.
    public void Close(string why)
    {
        if (Interlocked.Exchange(ref closing, 1) != 0) return;
        if (neighbor != null) Log.Info($"ICSP: link to core server {neighbor} ({Name}) is down: {why}");
        else Log.Debug($"ICSP: {Name} closed before introducing itself: {why}");
        Routes.LinkDown(this);
        IcspNet.Unbind(this);
        cts.Cancel();
        try { socket.Shutdown(SocketShutdown.Both); } catch { /* already gone */ }
        socket.Dispose();
        wake.Release();
    }

    // === receiving ===
    async Task ReceiveLoopAsync()
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(ReceiveBufferBytes);
        int start = 0, end = 0;
        long skip = 0;      // bytes of an oversized record still to throw away
        long body = -1;     // body size of the record at `start` once its length block is decrypted
        byte[]? salt = null; // the neighbor's salt, remembered once its first record proves it genuine
        try
        {
            while (true)
            {
                // handle every complete record in the buffer
                while (true)
                {
                    int available = end - start;
                    if (skip > 0)
                    {
                        int k = (int)Math.Min(skip, available);
                        skip -= k;
                        start += k;
                        if (skip > 0) break;
                        continue;
                    }
                    if (receiveCipher == null)
                    {
                        // the stream starts with the neighbor's salt; with several possible keys,
                        // its first length block tells which one it uses
                        int need = CableEncryption.SaltBytes + (keys.Length > 1 ? CableEncryption.LengthBlock : 0);
                        if (available < need) break;
                        salt = buffer.AsSpan(start, CableEncryption.SaltBytes).ToArray();
                        receiveCipher = keys.Length == 1 ? new CableCipher(keys[0], salt)
                                      : PickKey(salt, buffer.AsSpan(start + CableEncryption.SaltBytes, CableEncryption.LengthBlock))
                                        ?? throw SecurityProblem("can't decrypt: the key in seckeys differs from the other side's, or the data was changed on the way");
                        start += CableEncryption.SaltBytes;
                        continue;
                    }
                    if (body < 0)
                    {
                        if (available < CableEncryption.LengthBlock) break;
                        if (!receiveCipher.OpenLength(buffer.AsSpan(start, CableEncryption.LengthBlock), out uint length))
                            throw SecurityProblem("can't decrypt: the key in seckeys differs from the other side's, or the data was changed on the way");
                        if (salt != null)
                        {
                            if (!CableEncryption.Remember(salt))
                                throw SecurityProblem("this encrypted stream was seen before: someone replays a recorded connection or sends ours back");
                            salt = null;
                        }
                        if (length < Icsp.HeaderBytes) throw new InvalidDataException($"record of {length} bytes is too short");
                        body = length;
                        if (CableEncryption.Overhead + body > MaxBufferedFrame)
                        {
                            Log.Debug($"ICSP: {Name}: skipping a {body}-byte record");
                            receiveCipher.SkipBody();
                            skip = CableEncryption.Overhead + body;
                            body = -1;
                            continue;
                        }
                    }
                    long total = CableEncryption.Overhead + body;
                    if (available < total)
                    {
                        if (total > buffer.Length)
                        {
                            buffer = Grow(buffer, start, end, (int)total);
                            start = 0;
                            end = available;
                        }
                        else if (buffer.Length - start < total)
                        {
                            Compact(buffer, ref start, ref end);
                        }
                        break;
                    }
                    var record = buffer.AsSpan(start + CableEncryption.LengthBlock, (int)body + CableEncryption.TagBytes);
                    if (!receiveCipher.OpenBody(record))
                        throw SecurityProblem("can't decrypt: the data was changed on the way");
                    HandleBody(record[..(int)body]);
                    start += (int)total;
                    body = -1;
                }

                if (start == end)
                {
                    start = end = 0;
                    if (buffer.Length > 4 * ReceiveBufferBytes)
                    {
                        // a huge frame is done, don't keep its buffer forever
                        ArrayPool<byte>.Shared.Return(buffer);
                        buffer = ArrayPool<byte>.Shared.Rent(ReceiveBufferBytes);
                    }
                }
                else if (end == buffer.Length)
                {
                    Compact(buffer, ref start, ref end);
                }

                int n = await socket.ReceiveAsync(buffer.AsMemory(end), SocketFlags.None, cts.Token);
                if (n == 0) return; // closed by the neighbor
                end += n;
                Volatile.Write(ref lastHeard, Environment.TickCount64);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    static void Compact(byte[] buffer, ref int start, ref int end)
    {
        buffer.AsSpan(start, end - start).CopyTo(buffer);
        end -= start;
        start = 0;
    }

    // moves the unread part buffer[start..end) to the beginning of a bigger buffer
    static byte[] Grow(byte[] buffer, int start, int end, int needed)
    {
        byte[] bigger = ArrayPool<byte>.Shared.Rent(Math.Max(needed, buffer.Length * 2));
        buffer.AsSpan(start, end - start).CopyTo(bigger);
        ArrayPool<byte>.Shared.Return(buffer);
        return bigger;
    }

    // decrypted body: one ICSP packet, then padding
    void HandleBody(ReadOnlySpan<byte> plain)
    {
        uint length = BinaryPrimitives.ReadUInt32BigEndian(plain);
        if (length == 0 || 4L + length > plain.Length)
            throw new InvalidDataException("a record must start with a whole ICSP packet");
        Handle(plain[..(4 + (int)length)]);
    }

    // logged at most once a minute (a wrong key on a wire would otherwise repeat on every redial)
    InvalidDataException SecurityProblem(string text)
    {
        long now = Environment.TickCount64;
        if (now - Volatile.Read(ref lastSecurityLog) > 60_000)
        {
            Volatile.Write(ref lastSecurityLog, now);
            Log.Info($"ICSP: {Name}: {text} (logged at most once a minute)");
        }
        return new InvalidDataException(text);
    }

    // first record on an accepted connection: try the key of every wire on its IP on a copy of
    // the length block; the matching key also becomes our sending key
    CableCipher? PickKey(byte[] salt, ReadOnlySpan<byte> lengthBlock)
    {
        Span<byte> copy = stackalloc byte[CableEncryption.LengthBlock];
        foreach (byte[] key in keys)
        {
            lengthBlock.CopyTo(copy);
            using (var trial = new CableCipher(key, salt))
            {
                if (!trial.OpenLength(copy, out _)) continue;
            }
            sendCipher = new CableCipher(key, sendSalt);
            Wake(); // whatever waited for the key can go now
            return new CableCipher(key, salt);
        }
        return null;
    }

    void Handle(ReadOnlySpan<byte> frame)
    {
        var body = frame[Icsp.HeaderBytes..];
        switch (frame[4])
        {
            case Icsp.Transmit:
                IcspBridge.OnTransmit(this, frame);
                break;
            case Icsp.NewRoutes:
                Routes.OnNewRoutes(this, body);
                break;
            case Icsp.WhoAreYou:
                SendControl(Outgoing.Fixed(Icsp.ImThisFrame));
                break;
            case Icsp.ImThis:
                if (body.Length >= Icsp.AddressBytes) OnImThis(body[..Icsp.AddressBytes]);
                break;
            case Icsp.KeepAlive:
                SendControl(Outgoing.Fixed(Icsp.KeepAliveResultFrame));
                break;
            case Icsp.KeepAliveResult:
                break; // any received byte already counts as "alive"
            case Icsp.Error:
                OnError(body);
                break;
            case Icsp.Die:
                Close("Die received");
                break;
            default:
                break; // unknown packets are ignored, the connection stays open
        }
    }

    void OnImThis(ReadOnlySpan<byte> encoded)
    {
        Span<char> digits = stackalloc char[Icsp.MaxNetworkDigits];
        int n = Icsp.DecodeAddress(encoded, digits);
        if (n < 0)
        {
            Log.Debug($"ICSP: {Name}: broken address in ImThis");
            return;
        }
        if (digits[..n].SequenceEqual(neighbor)) return; // nothing new
        string address = new(digits[..n]);
        if (address == Config.LocalAddress)
        {
            Close("it has our own address (connected to ourselves?)");
            return;
        }
        if (neighbor != null)
        {
            // the cable now leads to another core server: forget everything learned from the old one
            Log.Info($"ICSP: {Name} is now core server {address} (was {neighbor})");
            Routes.LinkDown(this);
            IcspNet.Unbind(this);
            neighbor = null;
            Advertised.Clear();
        }
        if (!IcspNet.TryBind(this, address)) return; // a duplicate, already closed
        neighbor = address;
        WasReady = true;
        Log.Info($"ICSP: link to core server {address} ({Name}) is up");
        Routes.LinkUp(this);
    }

    void OnError(ReadOnlySpan<byte> body)
    {
        if (body.Length < 4) return;
        long length = BinaryPrimitives.ReadUInt32BigEndian(body);
        if (body.Length < 4 + length + 1) return;
        string text = System.Text.Encoding.UTF8.GetString(body.Slice(4, (int)Math.Min(length, 1000)));
        byte critical = body[4 + (int)length];
        if (critical is not (Icsp.False or Icsp.True)) return;
        Log.Info($"ICSP: {Name} reports {(critical == Icsp.True ? "a CRITICAL" : "an")} error: {text}");
        if (critical == Icsp.True) Close("critical error from the neighbor");
    }

    // === keep-alive ===
    async Task KeepAliveLoopAsync()
    {
        long connectedAt = Environment.TickCount64;
        int interval = Config.IcspKeepAliveIntervalMs;
        try
        {
            while (true)
            {
                // a random pause, 0.5..1.5 x icsp_keepalive_interval_ms: no steady beat on the wire to recognize
                await Task.Delay(interval / 2 + Random.Shared.Next(interval + 1), cts.Token);
                long now = Environment.TickCount64;
                if (now - Volatile.Read(ref lastHeard) > Config.IcspTimeoutMs)
                {
                    Close("no answer to keep-alives");
                    return;
                }
                if (neighbor == null)
                {
                    if (now - connectedAt > Config.IcspTimeoutMs)
                    {
                        Close("no answer to WhoAreYou");
                        return;
                    }
                    SendControl(Outgoing.Fixed(Icsp.WhoAreYouFrame));
                }
                else
                {
                    SendControl(Outgoing.Fixed(Icsp.KeepAliveFrame));
                }
            }
        }
        catch (OperationCanceledException) { /* closed */ }
    }

    // === sending ===
    public void SendControl(Outgoing frame)
    {
        if (IsClosed) return;
        if (Interlocked.Increment(ref controlCount) > MaxControlBacklog)
        {
            Interlocked.Decrement(ref controlCount);
            Close("not reading");
            return;
        }
        control.Enqueue(frame);
        Wake();
    }

    public bool CanAcceptPacket(int length) =>
        Ready
        && Volatile.Read(ref queuedBytes) + length <= Config.IcspMaxSendQueueBytes
        && Volatile.Read(ref SendQueue.TotalQueuedBytes) + length <= Config.MaxTotalQueuedBytes;

    // Data packets (Transmit frames). Takes ownership of the buffer; dropped when the queue is full.
    public void SendPacket(Outgoing m)
    {
        if (!Ready)
        {
            m.Release();
            return;
        }
        bool over = Interlocked.Add(ref queuedBytes, m.Cost) > Config.IcspMaxSendQueueBytes;
        over |= Interlocked.Add(ref SendQueue.TotalQueuedBytes, m.Cost) > Config.MaxTotalQueuedBytes;
        if (over)
        {
            Uncount(m);
            m.Release();
            Log.Debug($"ICSP: send queue to {Name} is full, packet dropped");
            return;
        }
        data.Enqueue((m, Stopwatch.GetTimestamp()));
        Wake();
        if (IsClosed) DrainQueues(); // raced with Close: nobody else will free it
    }

    void Wake()
    {
        if (Interlocked.Exchange(ref wakePending, 1) == 0) wake.Release();
    }

    void Uncount(Outgoing m)
    {
        Interlocked.Add(ref queuedBytes, -m.Cost);
        Interlocked.Add(ref SendQueue.TotalQueuedBytes, -m.Cost);
    }

    async Task SendLoopAsync()
    {
        var batch = new List<Outgoing>();
        byte[] output = ArrayPool<byte>.Shared.Rent(2 * SendBatchBytes); // the encrypted batch
        bool saltSent = false;
        try
        {
            while (true)
            {
                await wake.WaitAsync(cts.Token);
                Volatile.Write(ref wakePending, 0);
                var cipher = sendCipher;
                if (cipher == null) continue; // accepted connection, key not known yet: queues wait
                while (true)
                {
                    int bytes = 0;
                    while (bytes < SendBatchBytes && control.TryDequeue(out var c))
                    {
                        Interlocked.Decrement(ref controlCount);
                        batch.Add(c);
                        bytes += c.Length;
                    }
                    while (bytes < SendBatchBytes && data.TryDequeue(out var item))
                    {
                        Uncount(item.Message);
                        // stale: sending it would only delay everything behind it
                        if (Stopwatch.GetElapsedTime(item.Enqueued).TotalMilliseconds > Config.MaxQueueDelayMs)
                        {
                            item.Message.Release();
                            continue;
                        }
                        batch.Add(item.Message);
                        bytes += item.Message.Length;
                    }
                    if (batch.Count == 0) break;

                    int length = 0;
                    try
                    {
                        int needed = CableEncryption.SaltBytes + bytes
                                   + batch.Count * (CableEncryption.Overhead + CableEncryption.MaxPadding);
                        if (output.Length < needed)
                        {
                            ArrayPool<byte>.Shared.Return(output);
                            output = ArrayPool<byte>.Shared.Rent(needed);
                        }
                        if (!saltSent)
                        {
                            sendSalt.CopyTo(output, 0); // our direction starts with our salt
                            length = CableEncryption.SaltBytes;
                            saltSent = true;
                        }
                        foreach (var m in batch)
                        {
                            var frame = m.Buffer.AsSpan(0, m.Length);
                            length += cipher.Seal(frame, CableEncryption.Padding(frame.Length), output.AsSpan(length));
                        }
                    }
                    finally
                    {
                        foreach (var m in batch) m.Release();
                        batch.Clear();
                    }
                    int sent = await socket.SendAsync(output.AsMemory(0, length), SocketFlags.None);
                    if (sent != length) throw new SocketException((int)SocketError.ConnectionAborted);
                }
            }
        }
        catch (Exception e)
        {
            if (e is not (SocketException or ObjectDisposedException or OperationCanceledException))
                Log.Error($"ICSP: {Name}: send loop: {e}");
            Close("send failed");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(output);
        }
    }

    void DrainQueues()
    {
        while (control.TryDequeue(out var c))
        {
            Interlocked.Decrement(ref controlCount);
            c.Release();
        }
        while (data.TryDequeue(out var item))
        {
            Uncount(item.Message);
            item.Message.Release();
        }
    }
}
