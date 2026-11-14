using System.Buffers.Binary;

namespace CoreServer;

// The ICSP routing table: which link leads to which network (the first address block).
//
// Every route belongs to the link it was learned on. Sources of routes:
//   - ImThis on a link: the neighbor itself, "direct" (distance 0, lives as long as the link)
//   - NewRoutes from a neighbor: whatever it knows, with its distance and TTL
// Our own address is never in the table; it is advertised separately with distance 0.
//
// Lookups (every packet to another network) are lock-free over a snapshot; changes go under one lock
// and wake the advertise loop, which sends each neighbor what changed for it (split horizon:
// a route is never advertised back to the link it came from).
static class Routes
{
    public readonly record struct Key(string Prefix, bool Wildcard);

    sealed class Route(Key key, IcspLink link)
    {
        public readonly Key Key = key;
        public readonly IcspLink Link = link;
        public ushort Distance;
        public long ExpiresAt;   // Environment.TickCount64 in ms
        public bool Direct;      // the neighbor itself, from ImThis: doesn't expire while the link is up
    }

    static readonly Lock gate = new();
    static readonly List<Route> table = [];  // insertion order = "the routing map's order" for ties
    static Route[] snapshot = [];

    static readonly SemaphoreSlim changed = new(0);
    static int changePending;

    // === lookup ===
    // network = the first block of the receiver address. Most specific route first (exact beats a
    // wildcard, a longer wildcard beats a shorter one), then the smallest distance, then table order.
    public static IcspLink? Find(ReadOnlySpan<char> network)
    {
        long now = Environment.TickCount64;
        Route? best = null;
        int bestScore = -1;
        foreach (var r in Volatile.Read(ref snapshot))
        {
            if (r.Key.Wildcard ? !network.StartsWith(r.Key.Prefix) : !network.SequenceEqual(r.Key.Prefix)) continue;
            if (r.ExpiresAt <= now || !r.Link.Ready) continue;
            int score = r.Key.Prefix.Length * 2 + (r.Key.Wildcard ? 0 : 1);
            if (score > bestScore || (score == bestScore && r.Distance < best!.Distance))
            {
                best = r;
                bestScore = score;
            }
        }
        return best?.Link;
    }

    // === changes ===
    // The neighbor on this link told us who it is.
    public static void LinkUp(IcspLink link)
    {
        string neighbor = link.Neighbor!;
        lock (gate)
        {
            int i = IndexOf(link, neighbor, false);
            var r = i >= 0 ? table[i] : Add(new Key(neighbor, false), link);
            r.Direct = true;
            r.Distance = 0;
            r.ExpiresAt = long.MaxValue;
            Publish();
        }
        Changed();
    }

    // The link is unavailable: nothing may be routed over it, and the other neighbors learn that.
    public static void LinkDown(IcspLink link)
    {
        lock (gate)
        {
            if (table.RemoveAll(r => r.Link == link) == 0) return;
            Publish();
        }
        Changed();
    }

    // body = NewRoutes frame without the header: [count: u32][48-byte route structs...]
    public static void OnNewRoutes(IcspLink link, ReadOnlySpan<byte> body)
    {
        if (body.Length < 4) return;
        var structs = body[4..];
        long count = Math.Min(BinaryPrimitives.ReadUInt32BigEndian(body), structs.Length / Icsp.RouteBytes);
        long now = Environment.TickCount64;
        string? neighbor = link.Neighbor;
        Span<char> digits = stackalloc char[Icsp.MaxNetworkDigits];
        bool dirty = false;

        lock (gate)
        {
            for (int i = 0; i < count; i++)
            {
                var s = structs.Slice(i * Icsp.RouteBytes, Icsp.RouteBytes);
                int n = Icsp.DecodeAddress(s, digits);
                uint ttl = BinaryPrimitives.ReadUInt32BigEndian(s[32..]);
                ushort distance = BinaryPrimitives.ReadUInt16BigEndian(s[36..]);
                byte action = s[38], kind = s[39];
                // a broken struct is skipped, the rest of the packet is still used
                if (n < 0 || action is not (Icsp.False or Icsp.True) || kind is not (Icsp.False or Icsp.True)) continue;

                var prefix = digits[..n];
                bool wildcard = kind == Icsp.True;
                // we know ourselves and our direct neighbor better than anyone
                if (!wildcard && (prefix.SequenceEqual(Config.LocalAddress) || prefix.SequenceEqual(neighbor))) continue;

                int at = IndexOf(link, prefix, wildcard);
                if (action == Icsp.True || ttl == 0)
                {
                    // revoke: only the mapping to THIS link goes away
                    if (at >= 0)
                    {
                        table.RemoveAt(at);
                        dirty = true;
                    }
                    continue;
                }
                if (at >= 0)
                {
                    var r = table[at];
                    if (r.Direct) continue;
                    dirty |= r.Distance != distance;
                    r.Distance = distance;
                    r.ExpiresAt = now + ttl; // the TTL counts down from the originator, never renewed by us
                }
                else
                {
                    var r = Add(new Key(new string(prefix), wildcard), link);
                    r.Distance = distance;
                    r.ExpiresAt = now + ttl;
                    dirty = true;
                }
            }
            if (dirty) Publish();
        }
        if (dirty) Changed();
    }

    static Route Add(Key key, IcspLink link)
    {
        var r = new Route(key, link);
        table.Add(r);
        return r;
    }

    static int IndexOf(IcspLink link, ReadOnlySpan<char> prefix, bool wildcard)
    {
        for (int i = 0; i < table.Count; i++)
        {
            var r = table[i];
            if (r.Link == link && r.Key.Wildcard == wildcard && prefix.SequenceEqual(r.Key.Prefix)) return i;
        }
        return -1;
    }

    // under gate
    static void Publish() => Volatile.Write(ref snapshot, table.ToArray());

    static void Changed()
    {
        if (Interlocked.Exchange(ref changePending, 1) == 0) changed.Release();
    }

    // === advertising ===
    // Sends changes right away (coalesced), drops expired routes, and every icsp_route_interval_ms
    // re-sends the whole table to every neighbor.
    public static async Task RunAsync(CancellationToken stopping)
    {
        long nextFull = Environment.TickCount64 + Config.IcspRouteIntervalMs;
        try
        {
            while (true)
            {
                long wait = Math.Clamp(nextFull - Environment.TickCount64, 0, 1000);
                bool triggered = await changed.WaitAsync((int)wait, stopping);
                if (triggered)
                {
                    await Task.Delay(50, stopping); // let a burst of changes (a whole NewRoutes, a reconnect) settle
                    Volatile.Write(ref changePending, 0);
                }

                long now = Environment.TickCount64;
                bool expired = RemoveExpired(now);
                bool full = now >= nextFull;
                if (full) nextFull = now + Config.IcspRouteIntervalMs;
                if (triggered || expired || full)
                {
                    try { Advertise(full, now); }
                    catch (Exception e) { Log.Error($"ICSP: route advertising failed: {e}"); }
                }
            }
        }
        catch (OperationCanceledException) { /* shutting down */ }
    }

    static bool RemoveExpired(long now)
    {
        lock (gate)
        {
            if (table.RemoveAll(r => r.ExpiresAt <= now) == 0) return false;
            Publish();
            return true;
        }
    }

    // What each neighbor should know: our own address + the best route per (prefix, wildcard) that did
    // NOT come from that neighbor, one hop further. Compared with what it was told before, only the
    // difference is sent (or everything, when full): new/changed routes as Add, vanished ones as Delete.
    static void Advertise(bool full, long now)
    {
        var routes = Volatile.Read(ref snapshot);
        foreach (var link in IcspNet.ReadyLinks())
        {
            var desired = new Dictionary<Key, (ushort Distance, uint Ttl)>
            {
                [new Key(Config.LocalAddress, false)] = (0, Config.IcspRouteTtlMs),
            };
            foreach (var r in routes)
            {
                if (r.Link == link || !r.Link.Ready || r.ExpiresAt <= now) continue;
                if (r.Distance == ushort.MaxValue) continue;                        // can't be incremented: kept locally only
                if (!r.Key.Wildcard && r.Key.Prefix == link.Neighbor) continue;     // it knows itself
                ushort distance = (ushort)(r.Distance + 1);
                uint ttl = r.Direct ? Config.IcspRouteTtlMs : (uint)Math.Clamp(r.ExpiresAt - now, 1, uint.MaxValue);
                if (!desired.TryGetValue(r.Key, out var known) || distance < known.Distance) desired[r.Key] = (distance, ttl);
            }

            var items = new List<(Key Key, ushort Distance, uint Ttl, bool Delete)>();
            foreach (var (key, v) in desired)
            {
                if (full || !link.Advertised.TryGetValue(key, out ushort told) || told != v.Distance)
                    items.Add((key, v.Distance, v.Ttl, false));
            }
            foreach (var key in link.Advertised.Keys)
            {
                if (!desired.ContainsKey(key)) items.Add((key, 0, 0, true));
            }
            if (items.Count == 0) continue;

            link.Advertised.Clear();
            foreach (var (key, v) in desired) link.Advertised[key] = v.Distance;
            Send(link, items);
        }
    }

    const int RoutesPerFrame = 4096;

    static void Send(IcspLink link, List<(Key Key, ushort Distance, uint Ttl, bool Delete)> items)
    {
        for (int first = 0; first < items.Count; first += RoutesPerFrame)
        {
            int n = Math.Min(RoutesPerFrame, items.Count - first);
            var frame = new byte[Icsp.HeaderBytes + 4 + n * Icsp.RouteBytes];
            Icsp.WriteHeader(frame, Icsp.NewRoutes, frame.Length);
            var w = new Icsp.Writer(frame) { Position = Icsp.HeaderBytes };
            w.U32((uint)n);
            for (int i = first; i < first + n; i++)
            {
                var (key, distance, ttl, delete) = items[i];
                Icsp.EncodeAddress(key.Prefix, w.Free);
                w.Position += Icsp.AddressBytes;
                w.U32(ttl);
                w.U16(distance);
                w.U8(delete ? Icsp.True : Icsp.False);
                w.U8(key.Wildcard ? Icsp.True : Icsp.False);
                w.Position += 8; // reserved, zeros
            }
            link.SendControl(Outgoing.Fixed(frame));
        }
    }

    // per-link memory of what was advertised to it (touched only by the advertise loop)
    public sealed class AdvertisedSet : Dictionary<Key, ushort>;
}
