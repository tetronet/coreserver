using System.Buffers;
using System.Diagnostics;
using System.Net.WebSockets;
using System.Threading.Channels;

namespace CoreServer;

// One finished, serialized message waiting to be sent.
// Pooled buffers go back to ArrayPool after sending, so forwarding allocates nothing per packet.
readonly record struct Outgoing(byte[] Buffer, int Length, bool Pooled)
{
    public static Outgoing Fixed(byte[] bytes) => new(bytes, bytes.Length, false);

    // Memory this message really holds while queued: a pooled buffer is usually bigger than the message.
    // (Fixed buffers are shared static arrays, so only their length counts.)
    public int Cost => Pooled ? Buffer.Length : Length;

    public void Release()
    {
        if (Pooled) ArrayPool<byte>.Shared.Return(Buffer);
    }
}

// Per-peer bounded send queue + the loop that writes it to the socket.
// Exactly one send is in flight at a time; while it waits for the peer (TCP backpressure),
// new packets pile up here until a limit is hit and further ones are dropped.
sealed class SendQueue
{
    // bytes in ALL queues together (WebSocket peers and ICSP links), see max_total_queued_bytes
    public static long TotalQueuedBytes;

    // Enqueued = Stopwatch timestamp, used to drop data packets that waited too long.
    readonly record struct Item(Outgoing Message, long Enqueued, bool Control);

    readonly Channel<Item> channel =
        Channel.CreateUnbounded<Item>(new UnboundedChannelOptions { SingleReader = true });
    int packets;
    long bytes;
    volatile bool closed;

    // Data packets: dropped (false) when any limit is hit.
    public bool TryEnqueue(Outgoing m)
    {
        bool overLimit = Interlocked.Increment(ref packets) > Config.MaxSendQueuePackets;
        overLimit |= Interlocked.Add(ref bytes, m.Cost) > Config.MaxSendQueueBytes;
        overLimit |= Interlocked.Add(ref TotalQueuedBytes, m.Cost) > Config.MaxTotalQueuedBytes;
        if (overLimit || !channel.Writer.TryWrite(new Item(m, Stopwatch.GetTimestamp(), false)))
        {
            Uncount(m);
            return false;
        }
        return true;
    }

    // Cheap pre-check, so a packet that would be dropped anyway isn't copied first.
    public bool HasRoom(int length) =>
        Volatile.Read(ref packets) < Config.MaxSendQueuePackets
        && Volatile.Read(ref bytes) + length <= Config.MaxSendQueueBytes
        && Volatile.Read(ref TotalQueuedBytes) + length <= Config.MaxTotalQueuedBytes;

    // Control messages ignore the limits. False means the peer isn't reading and must be kicked.
    public bool TryEnqueueControl(Outgoing m)
    {
        if (Volatile.Read(ref bytes) > Config.MaxControlBacklogBytes) return false;
        Interlocked.Increment(ref packets);
        Interlocked.Add(ref bytes, m.Cost);
        Interlocked.Add(ref TotalQueuedBytes, m.Cost);
        if (!channel.Writer.TryWrite(new Item(m, 0, true))) Uncount(m); // already closed, nothing to kick
        return true;
    }

    // Stops sending; whatever is still queued is thrown away.
    public void Close()
    {
        closed = true;
        channel.Writer.TryComplete();
    }

    // Only small messages are batched: for bigger ones the copy into the batch costs more than the
    // saved flush (measured: 16 KB messages got 10-17% slower when batched, 200 B ones 7-15% faster).
    const int BatchMaxMessage = 4 * 1024;

    // batch = the stream under ws (null: every message is written and flushed on its own)
    public async Task RunAsync(WebSocket ws, BatchingStream? batch)
    {
        var reader = channel.Reader;
        using var stuck = new CancellationTokenSource();
        bool healthy = true;
        try
        {
            while (healthy && !closed && await reader.WaitToReadAsync())
            {
                while (!closed && reader.TryRead(out var item))
                {
                    if (!TakeFresh(item)) continue;
                    // a send that the peer doesn't take within StuckKickMs aborts the socket
                    stuck.CancelAfter(Config.StuckKickMs);
                    if (batch == null || item.Message.Length > BatchMaxMessage || !reader.TryPeek(out var next) || next.Message.Length > BatchMaxMessage)
                    {
                        // a lone or big message: written straight through, no extra copy
                        await SendAsync(ws, item.Message, stuck.Token);
                    }
                    else
                    {
                        // More is waiting: frame everything that is queued now (up to about one socket send
                        // buffer) into one write. While batching, ws.SendAsync only copies the frame and
                        // completes at once; the real network write is EndBatchAsync.
                        batch.BeginBatch();
                        try
                        {
                            int bytes = item.Message.Length;
                            await SendAsync(ws, item.Message, stuck.Token);
                            while (bytes < Config.SocketSendBufferBytes && !closed
                                   && reader.TryPeek(out next) && next.Message.Length <= BatchMaxMessage
                                   && reader.TryRead(out item))
                            {
                                if (!TakeFresh(item)) continue;
                                bytes += item.Message.Length;
                                await SendAsync(ws, item.Message, stuck.Token);
                            }
                        }
                        finally
                        {
                            await batch.EndBatchAsync(stuck.Token);
                        }
                    }
                    if (!stuck.TryReset()) { healthy = false; break; } // timer fired right after the send
                }
            }
        }
        catch (Exception e)
        {
            Log.Debug($"Send loop ended: {e.Message}");
            healthy = false;
        }
        finally
        {
            Close();
            while (reader.TryRead(out var item))
            {
                Uncount(item.Message);
                item.Message.Release();
            }
        }
        if (!healthy)
        {
            Log.Debug("Peer is stuck or its socket failed, kicking it");
            ws.Abort();
        }
    }

    // Takes a dequeued item off the counters. False (and released) for a stale data packet:
    // head drop, sending it would only add latency for everything behind it (keeps ping bounded under overload).
    bool TakeFresh(Item item)
    {
        Uncount(item.Message);
        if (!item.Control && Stopwatch.GetElapsedTime(item.Enqueued).TotalMilliseconds > Config.MaxQueueDelayMs)
        {
            item.Message.Release();
            return false;
        }
        return true;
    }

    static async ValueTask SendAsync(WebSocket ws, Outgoing m, CancellationToken token)
    {
        try
        {
            await ws.SendAsync(m.Buffer.AsMemory(0, m.Length), WebSocketMessageType.Text, true, token);
        }
        finally
        {
            m.Release();
        }
    }

    void Uncount(Outgoing m)
    {
        Interlocked.Decrement(ref packets);
        Interlocked.Add(ref bytes, -m.Cost);
        Interlocked.Add(ref TotalQueuedBytes, -m.Cost);
    }
}
