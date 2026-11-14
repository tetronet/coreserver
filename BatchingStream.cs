using System.Buffers;
using Microsoft.AspNetCore.Http.Features;

namespace CoreServer;

// The stream under a peer's WebSocket. Normally a pass-through, but between BeginBatch and
// EndBatchAsync writes are only collected, then go to Kestrel as ONE write + flush:
// one syscall (and with TLS one encryption call) for a whole run of queued messages,
// instead of one per message. Same idea as IcspLink's batched sends.
//
// Concurrency: ManagedWebSocket holds its own send lock for the whole duration of a WriteAsync,
// so writes never overlap each other. The only thing that can overlap is EndBatchAsync (called by
// the send loop, outside that lock) with a ping/pong/close written by the WebSocket itself;
// `gate` keeps those in order on the inner stream, `sync` guards the buffer and the flag.
sealed class BatchingStream(Stream inner) : Stream
{
    readonly Lock sync = new();
    readonly SemaphoreSlim gate = new(1, 1);
    bool batching;
    byte[]? buffer;   // rented only while a batch holds data, so an idle peer pins nothing
    int count;

    public void BeginBatch()
    {
        lock (sync) batching = true;
    }

    // Sends what was collected and goes back to pass-through mode.
    public async ValueTask EndBatchAsync(CancellationToken token)
    {
        await gate.WaitAsync(token);
        try
        {
            byte[]? data;
            int length;
            lock (sync)
            {
                batching = false;
                data = buffer;
                length = count;
                buffer = null;
                count = 0;
            }
            if (data == null) return;
            try
            {
                if (length > 0) await inner.WriteAsync(data.AsMemory(0, length), token);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(data);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> source, CancellationToken token = default)
    {
        lock (sync)
        {
            if (batching)
            {
                Append(source.Span);
                return ValueTask.CompletedTask;
            }
        }
        return WriteThroughAsync(source, token);
    }

    async ValueTask WriteThroughAsync(ReadOnlyMemory<byte> source, CancellationToken token)
    {
        await gate.WaitAsync(token);
        try { await inner.WriteAsync(source, token); }
        finally { gate.Release(); }
    }

    // under sync
    void Append(ReadOnlySpan<byte> data)
    {
        if (buffer == null || buffer.Length - count < data.Length)
        {
            var bigger = ArrayPool<byte>.Shared.Rent(Math.Max(count + data.Length, Math.Max(16384, (buffer?.Length ?? 0) * 2)));
            if (buffer != null)
            {
                buffer.AsSpan(0, count).CopyTo(bigger);
                ArrayPool<byte>.Shared.Return(buffer);
            }
            buffer = bigger;
        }
        data.CopyTo(buffer.AsSpan(count));
        count += data.Length;
    }

    public override Task WriteAsync(byte[] source, int offset, int length, CancellationToken token) =>
        WriteAsync(source.AsMemory(offset, length), token).AsTask();

    // the batch is flushed by EndBatchAsync; Kestrel's stream flushes every write by itself
    public override Task FlushAsync(CancellationToken token)
    {
        lock (sync)
        {
            if (batching) return Task.CompletedTask;
        }
        return inner.FlushAsync(token);
    }

    public override ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken token = default) =>
        inner.ReadAsync(destination, token);

    public override Task<int> ReadAsync(byte[] destination, int offset, int length, CancellationToken token) =>
        inner.ReadAsync(destination, offset, length, token);

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override int Read(byte[] b, int o, int c) => throw new NotSupportedException(); // async only
    public override void Write(byte[] b, int o, int c) => throw new NotSupportedException();
    public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
    public override void SetLength(long v) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            inner.Dispose();
            lock (sync)
            {
                if (buffer != null) ArrayPool<byte>.Shared.Return(buffer);
                buffer = null;
                count = 0;
            }
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        await inner.DisposeAsync();
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    // Placed in front of UseWebSockets: the WebSocket middleware then builds its WebSocket on top of
    // a BatchingStream (handshake, pings and close handling stay the framework's own).
    // The stream is published as a feature so the request handler can reach it.
    public sealed class UpgradeFeature(IHttpUpgradeFeature innerFeature, IFeatureCollection features) : IHttpUpgradeFeature
    {
        public bool IsUpgradableRequest => innerFeature.IsUpgradableRequest;

        public async Task<Stream> UpgradeAsync()
        {
            var stream = new BatchingStream(await innerFeature.UpgradeAsync());
            features.Set(stream);
            return stream;
        }
    }
}
