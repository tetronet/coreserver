using System.Buffers;
using System.Text.Json;

namespace CoreServer;

// ["data-transmission", { package_info: { to, from?, max_hops?, ... }, package_data: "<base64>", ... }]
//
// Works directly on the received bytes: package_data (the bulk of the packet) is never decoded
// or re-encoded. Unknown fields are forwarded untouched. For duplicate keys the last one counts, like JSON.parse.
//
// The data object is analysed by Read() during the envelope pass (Protocol.TryParseEnvelope), so the
// whole message is scanned only once. Handle() then works only with the byte ranges found there.
//
// Fast path (big packet: has "from", compact envelope, fills the receive buffer): max_hops is decremented in place, padded
// to the same width with spaces ("10000" -> " 9999"), and the receive buffer itself is queued to the
// destination. Zero copies. Otherwise the packet is copied once into a right-sized buffer with the edits applied.
static class DataTransmission
{
    static ReadOnlySpan<byte> Prefix => "[\"data-transmission\","u8;

    // A replacement of msg[Start..End) with Text (Start == End means insertion).
    readonly record struct Edit(int Start, int End, byte[] Text);

    // What Read() found. Byte ranges are absolute (in the whole message); -1 = absent.
    public struct Packet
    {
        public bool Valid;                 // data is an object with package_info (object) and package_data (string, not too long)
        public int InfoEnd;                // right after package_info's closing '}'
        public int ToStart, ToEnd;
        public int FromStart, FromEnd;
        public bool FromIsNull;
        public int HopsStart, HopsEnd;
        public double? Hops;               // null when max_hops is not a finite number

        // Only needed when the packet leaves over ICSP (IcspBridge reads them there).
        // Raw JSON value ranges; End == 0 means absent.
        public int TypeStart, TypeEnd;       // package_info.package_type
        public int ConnStart, ConnEnd;       // package_info.connectionid
        public int LastStart, LastEnd;       // package_info.is_last_in_package_queue
        public int NoStart, NoEnd;           // package_info.package_no
        public int MsgStart, MsgEnd;         // package_info.message_id
        public int PayloadStart, PayloadEnd; // package_data (the string token)
        public int MetaStart, MetaEnd;       // metadata (next to package_data)
    }

    // Reads the data element the reader is positioned on, and leaves the reader on its last token
    // (exactly like r.Skip() would), filling `p`.
    public static void Read(ref Utf8JsonReader r, ref Packet p)
    {
        p.Valid = false;
        if (r.TokenType != JsonTokenType.StartObject)
        {
            r.Skip();
            return;
        }

        bool packageDataOk = false, hasInfo = false;
        while (r.Read() && r.TokenType == JsonTokenType.PropertyName)
        {
            bool isInfo = r.ValueTextEquals("package_info"u8);
            bool isData = !isInfo && r.ValueTextEquals("package_data"u8);
            bool isMeta = !isInfo && !isData && r.ValueTextEquals("metadata"u8);
            r.Read();
            if (isData)
            {
                p.PayloadStart = (int)r.TokenStartIndex;
                packageDataOk = r.TokenType == JsonTokenType.String && PackageDataFits(ref r);
                r.Skip();
                p.PayloadEnd = (int)r.BytesConsumed;
            }
            else if (isMeta)
            {
                p.MetaStart = (int)r.TokenStartIndex;
                r.Skip();
                p.MetaEnd = (int)r.BytesConsumed;
            }
            else if (isInfo)
            {
                hasInfo = r.TokenType == JsonTokenType.StartObject;
                if (hasInfo) ReadInfo(ref r, ref p); // the last package_info wins
                else r.Skip();
            }
            else
            {
                r.Skip();
            }
        }
        p.Valid = packageDataOk && hasInfo;
    }

    // JS counts UTF-16 chars. Raw UTF-8/escaped bytes are never fewer than chars, so the
    // byte length is an exact answer for every normal packet; only a huge one gets decoded.
    static bool PackageDataFits(ref Utf8JsonReader r) =>
        r.ValueSpan.Length < Config.MaxPackageDataLength
        || r.GetString()!.Length < Config.MaxPackageDataLength;

    // The reader is on package_info's '{'; leaves it on the matching '}'.
    static void ReadInfo(ref Utf8JsonReader r, ref Packet p)
    {
        p.ToStart = p.FromStart = p.HopsStart = -1;
        p.FromIsNull = false;
        p.Hops = null;
        p.TypeEnd = p.ConnEnd = p.LastEnd = p.NoEnd = p.MsgEnd = 0;
        while (r.Read() && r.TokenType == JsonTokenType.PropertyName)
        {
            int field = r.ValueTextEquals("to"u8) ? 1
                      : r.ValueTextEquals("from"u8) ? 2
                      : r.ValueTextEquals("max_hops"u8) ? 3
                      : r.ValueTextEquals("package_type"u8) ? 4
                      : r.ValueTextEquals("connectionid"u8) ? 5
                      : r.ValueTextEquals("is_last_in_package_queue"u8) ? 6
                      : r.ValueTextEquals("package_no"u8) ? 7
                      : r.ValueTextEquals("message_id"u8) ? 8
                      : 0;
            r.Read();
            if (field == 0)
            {
                r.Skip();
                continue;
            }
            var type = r.TokenType;
            int start = (int)r.TokenStartIndex;
            double? number = type == JsonTokenType.Number && r.TryGetDouble(out double d) ? d : null;
            r.Skip();
            int end = (int)r.BytesConsumed;

            switch (field)
            {
                case 1:
                    p.ToStart = start; p.ToEnd = end;
                    break;
                case 2:
                    p.FromStart = start; p.FromEnd = end;
                    p.FromIsNull = type == JsonTokenType.Null;
                    break;
                case 3:
                    // max_hops: null counts as absent
                    p.HopsStart = type == JsonTokenType.Null ? -1 : start;
                    p.HopsEnd = end;
                    p.Hops = number;
                    break;
                case 4: p.TypeStart = start; p.TypeEnd = end; break;
                case 5: p.ConnStart = start; p.ConnEnd = end; break;
                case 6: p.LastStart = start; p.LastEnd = end; break;
                case 7: p.NoStart = start; p.NoEnd = end; break;
                case 8: p.MsgStart = start; p.MsgEnd = end; break;
            }
        }
        p.InfoEnd = (int)r.BytesConsumed;
    }

    // Returns true when the buffer itself was queued to the destination (ownership passed on).
    public static bool Handle(Peer sender, byte[] buffer, int length, int dataStart, int dataEnd, in Packet info)
    {
        if (sender.Address == null || !info.Valid) return false; // must introduce itself first
        var msg = buffer.AsSpan(0, length);

        Span<char> receiver = stackalloc char[Addresses.MaxCanonicalLength];
        int receiverLength = info.ToStart < 0 ? -1 : Addresses.Parse(msg[info.ToStart..info.ToEnd], receiver);
        if (receiverLength < 0) return false;

        // "from" as given, canonical; -1 = absent, null or malformed
        Span<char> from = stackalloc char[Addresses.MaxCanonicalLength];
        int fromLength = info.FromStart < 0 || info.FromIsNull ? -1 : Addresses.Parse(msg[info.FromStart..info.FromEnd], from);

        Edit? fromEdit = null;
        if (Config.EnforceSourceAddress)
        {
            if (info.FromStart < 0)
            {
                // stamp it ourselves so receivers can trust it (string form, e.g. "7-850")
                fromEdit = new Edit(info.InfoEnd - 1, info.InfoEnd - 1, sender.FromProperty); // before the closing '}'
            }
            else if (info.FromIsNull)
            {
                fromEdit = new Edit(info.FromStart, info.FromEnd, sender.FromValue);
            }
            else if (fromLength < 0 || !Addresses.HasPrefix(from[..fromLength], sender.Address))
            {
                Log.Debug($"Forwarding data refused: {sender.Address} tried to send as someone else");
                return false;
            }
        }

        // TTL: no max_hops (or null) -> pass through, otherwise it must be a positive integer
        double? hops = null;
        if (info.HopsStart >= 0)
        {
            if (info.Hops is not double h || h != Math.Floor(h) || h <= 0) return false;
            hops = h;
        }

        // another network: over ICSP, converted into a binary Transmit frame (always a copy)
        if (!Router.IsLocal(receiver[..receiverLength]))
        {
            var source = fromLength >= 0 ? from[..fromLength] : sender.Address.AsSpan();
            IcspBridge.FromJson(msg, in info, receiver[..receiverLength], source, hops);
            return false;
        }

        Edit? hopsEdit = null;
        if (hops is double hv && !TryWriteInPlace(msg[info.HopsStart..info.HopsEnd], hv - 1))
        {
            hopsEdit = new Edit(info.HopsStart, info.HopsEnd, FormatNumber(hv - 1)); // e.g. "1e9", doesn't fit
        }

        var destination = Router.FindLocal(receiver[..receiverLength]);
        if (destination == null) return false;
        if (!destination.CanAcceptPacket(length))
        {
            Log.Debug($"Send queue of {destination.Address} is overloaded, packet dropped");
            return false;
        }

        // zero-copy: the received message is already exactly what has to go out.
        // Only when it fills most of the buffer: a 200-byte packet must not pin a 16 KB receive
        // buffer in someone's queue (that multiplied real queue memory by up to ~80x).
        if (fromEdit == null && hopsEdit == null && length * 2 >= buffer.Length && IsCompactEnvelope(msg, dataStart, dataEnd))
        {
            destination.SendPacket(new Outgoing(buffer, length, Pooled: true));
            return true;
        }

        destination.SendPacket(Build(msg, dataStart, dataEnd, fromEdit, hopsEdit));
        return false;
    }

    // Writes the number over the old one, right-aligned and padded with spaces: valid JSON of the
    // same length, so nothing moves. Fails only if the new number is longer than the old token.
    static bool TryWriteInPlace(Span<byte> token, double value)
    {
        Span<byte> digits = stackalloc byte[20];
        if (value > 9007199254740992 || !((long)value).TryFormat(digits, out int n) || n > token.Length) return false;
        token[..^n].Fill((byte)' ');
        digits[..n].CopyTo(token[^n..]);
        return true;
    }

    // ["data-transmission",<data>] with nothing extra around the data object
    static bool IsCompactEnvelope(ReadOnlySpan<byte> msg, int dataStart, int dataEnd) =>
        dataEnd == msg.Length - 1 && msg[^1] == (byte)']' && msg[..dataStart].SequenceEqual(Prefix);

    static byte[] FormatNumber(double value) =>
        System.Text.Encoding.UTF8.GetBytes(value <= 9007199254740992 ? ((long)value).ToString() : value.ToString("R"));

    // Prefix + data object with the edits applied + "]", in one pooled buffer.
    static Outgoing Build(ReadOnlySpan<byte> msg, int dataStart, int dataEnd, Edit? a, Edit? b)
    {
        // order the edits by position
        if (a is null || (b is not null && b.Value.Start < a.Value.Start)) (a, b) = (b, a);

        int length = Prefix.Length + (dataEnd - dataStart) + 1;
        if (a is { } ea) length += ea.Text.Length - (ea.End - ea.Start);
        if (b is { } eb) length += eb.Text.Length - (eb.End - eb.Start);

        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        var dst = buffer.AsSpan();
        Prefix.CopyTo(dst);
        int w = Prefix.Length;
        int pos = dataStart;
        if (a is { } e1) Apply(msg, dst, e1, ref pos, ref w);
        if (b is { } e2) Apply(msg, dst, e2, ref pos, ref w);
        msg[pos..dataEnd].CopyTo(dst[w..]);
        w += dataEnd - pos;
        dst[w++] = (byte)']';
        return new Outgoing(buffer, w, Pooled: true);
    }

    // copies msg[pos..e.Start), then e.Text instead of msg[e.Start..e.End)
    static void Apply(ReadOnlySpan<byte> msg, Span<byte> dst, Edit e, ref int pos, ref int w)
    {
        msg[pos..e.Start].CopyTo(dst[w..]);
        w += e.Start - pos;
        e.Text.CopyTo(dst[w..]);
        w += e.Text.Length;
        pos = e.End;
    }
}
