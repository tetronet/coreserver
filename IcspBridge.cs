using System.Buffers;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.Text.Json;
using System.Text.Unicode;

namespace CoreServer;

// Converts packets between RAWWS (JSON) and the ICSP Transmit frame, and forwards Transmit frames
// between ICSP links.
//
//   package_info.to                       <-> Destination Address   ("7-850-1"; arrays are written as ["7","850","1"])
//   package_info.from                     <-> Source Address
//   package_info.package_type             <-> Query Type
//   package_info.connectionid             <-> Connection ID
//   package_info.is_last_in_package_queue <-> Is Last In Packet Queue
//   package_info.package_no               <-> Packet No
//   package_info.message_id               <-> Message ID
//   package_info.max_hops                 <-> Max Hops
//   package_data (base64)                 <-> Data (raw bytes)
//   metadata                              <-> Metadata
// Missing optional fields become 0 / false / "". Other JSON fields don't exist in ICSP and are lost.
// Strings are carried as UTF-8 (plain ASCII stays ASCII), so e.g. Cyrillic file names in metadata survive.
static class IcspBridge
{
    // === RAWWS -> ICSP ===
    // receiver is not in our network; source is the checked sender address. hops = max_hops as
    // received (already checked to be a positive integer), null if absent.
    public static void FromJson(ReadOnlySpan<byte> msg, in DataTransmission.Packet p,
                                ReadOnlySpan<char> receiver, ReadOnlySpan<char> source, double? hops)
    {
        // Max Hops is mandatory in ICSP, so a packet without it stays in our network.
        // After our own decrement 0 would only be dropped by the next core server.
        if (hops is not double h || h - 1 < 1 || h - 1 > ushort.MaxValue) return;
        if (receiver.Length > 255 || source.Length > 255) return;
        var link = Router.FindRemote(receiver);
        if (link == null) return;

        if (!TryNumber(Token(msg, p.ConnStart, p.ConnEnd), uint.MaxValue, out ulong connection)
            || !TryBool(Token(msg, p.LastStart, p.LastEnd), out bool isLast)
            || !TryNumber(Token(msg, p.NoStart, p.NoEnd), ulong.MaxValue, out ulong packetNo)
            || !TryNumber(Token(msg, p.MsgStart, p.MsgEnd), ulong.MaxValue, out ulong messageId))
        {
            Log.Debug("ICSP: packet with a malformed package_info field dropped");
            return;
        }

        var type = Token(msg, p.TypeStart, p.TypeEnd);
        var meta = Token(msg, p.MetaStart, p.MetaEnd);
        var payload = msg[p.PayloadStart..p.PayloadEnd];
        // unescaped text is never longer than its raw JSON token, decoded base64 is 3/4 of it
        int bound = Icsp.HeaderBytes + 2 + 1 + receiver.Length + 1 + source.Length + 1 + type.Length
                  + 4 + 1 + 8 + 8 + 2 + payload.Length / 4 * 3 + 3 + 2 + meta.Length;
        if (!link.CanAcceptPacket(bound))
        {
            Log.Debug($"ICSP: send queue to {link.Name} is full, packet dropped");
            return;
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(bound);
        var w = new Icsp.Writer(buffer) { Position = Icsp.HeaderBytes };
        w.U16((ushort)(h - 1));
        w.ShortAscii(receiver);
        w.ShortAscii(source);
        int at = w.Position++;
        int n = CopyText(type, w.Free, 255);
        if (n < 0) goto bad;
        buffer[at] = (byte)n;
        w.Position += n;
        w.U32((uint)connection);
        w.U8(isLast ? Icsp.True : Icsp.False);
        w.U64(packetNo);
        w.U64(messageId);

        at = w.Position;
        w.Position += 2;
        n = DecodeBase64(payload, w.Free);
        if (n is < 0 or > ushort.MaxValue) goto bad;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(at), (ushort)n);
        w.Position += n;

        at = w.Position;
        w.Position += 2;
        n = CopyText(meta, w.Free, ushort.MaxValue);
        if (n < 0) goto bad;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(at), (ushort)n);
        w.Position += n;

        Icsp.WriteHeader(buffer, Icsp.Transmit, w.Position);
        link.SendPacket(new Outgoing(buffer, w.Position, Pooled: true));
        return;

    bad:
        Log.Debug("ICSP: packet doesn't fit into Transmit (bad base64 or too long field), dropped");
        ArrayPool<byte>.Shared.Return(buffer);
    }

    static ReadOnlySpan<byte> Token(ReadOnlySpan<byte> msg, int start, int end) => end == 0 ? default : msg[start..end];

    // absent or null -> 0; otherwise must be a non-negative integer <= max (5.0 and 1e3 count, like in JS)
    static bool TryNumber(ReadOnlySpan<byte> token, ulong max, out ulong value)
    {
        value = 0;
        if (token.IsEmpty) return true;
        var r = new Utf8JsonReader(token, Protocol.ReaderOptions);
        r.Read();
        if (r.TokenType == JsonTokenType.Null) return true;
        if (r.TokenType != JsonTokenType.Number) return false;
        if (r.TryGetUInt64(out value)) return value <= max;
        if (!r.TryGetDouble(out double d) || d != Math.Floor(d) || d < 0 || d >= 18446744073709551616.0 || d > max) return false;
        value = (ulong)d;
        return true;
    }

    // absent or null -> false; otherwise must be true/false
    static bool TryBool(ReadOnlySpan<byte> token, out bool value)
    {
        value = false;
        if (token.IsEmpty) return true;
        var r = new Utf8JsonReader(token, Protocol.ReaderOptions);
        r.Read();
        value = r.TokenType == JsonTokenType.True;
        return r.TokenType is JsonTokenType.True or JsonTokenType.False or JsonTokenType.Null;
    }

    // absent or null -> 0 bytes. A string is written into dst as UTF-8; returns its length,
    // or -1 if it isn't a string or is longer than max bytes.
    static int CopyText(ReadOnlySpan<byte> token, Span<byte> dst, int max)
    {
        if (token.IsEmpty) return 0;
        var r = new Utf8JsonReader(token, Protocol.ReaderOptions);
        r.Read();
        if (r.TokenType == JsonTokenType.Null) return 0;
        if (r.TokenType != JsonTokenType.String) return -1;
        int n;
        if (r.ValueIsEscaped)
        {
            n = r.CopyString(dst);
        }
        else
        {
            n = r.ValueSpan.Length;
            if (n > max) return -1;
            r.ValueSpan.CopyTo(dst);
        }
        return n <= max ? n : -1;
    }

    // package_data (a JSON string token) -> raw bytes in dst; -1 if it's not valid base64
    static int DecodeBase64(ReadOnlySpan<byte> token, Span<byte> dst)
    {
        var r = new Utf8JsonReader(token, Protocol.ReaderOptions);
        r.Read();
        if (!r.ValueIsEscaped)
        {
            return Base64.DecodeFromUtf8(r.ValueSpan, dst, out _, out int written) == OperationStatus.Done ? written : -1;
        }
        byte[] text = ArrayPool<byte>.Shared.Rent(r.ValueSpan.Length);
        try
        {
            int length = r.CopyString(text);
            return Base64.DecodeFromUtf8(text.AsSpan(0, length), dst, out _, out int written) == OperationStatus.Done ? written : -1;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(text);
        }
    }

    // === ICSP -> RAWWS, or on to the next core server ===
    public static void OnTransmit(IcspLink from, ReadOnlySpan<byte> frame)
    {
        // a bad boolean or a truncated frame: ignored. Max Hops 0: dropped, whatever the destination.
        if (!Icsp.TryParseTransmit(frame, out var t) || t.Hops == 0) return;
        ushort hops = (ushort)(t.Hops - 1);

        Span<char> receiver = stackalloc char[255];
        if (!ToAddress(t.Destination, receiver)) return;
        receiver = receiver[..t.Destination.Length];
        int dash = receiver.IndexOf('-');
        var network = dash < 0 ? receiver : receiver[..dash];

        // nothing from outside may claim to come from our own network
        if (StartsWithBlock(t.Source, Config.LocalAddress))
        {
            Log.Debug($"ICSP: {from.Name} sent a packet from our own network, dropped");
            return;
        }

        if (network.SequenceEqual(Config.LocalAddress))
        {
            DeliverLocal(in t, receiver, hops);
            return;
        }

        // transit: the frame goes on unchanged except Max Hops
        if (hops == 0) return;
        var next = Routes.Find(network);
        if (next == null)
        {
            Log.Debug($"ICSP: no route to network {network}");
            return;
        }
        if (!next.CanAcceptPacket(frame.Length)) return;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(frame.Length);
        frame.CopyTo(buffer);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(Icsp.HopsOffset), hops);
        next.SendPacket(new Outgoing(buffer, frame.Length, Pooled: true));
    }

    static void DeliverLocal(in Icsp.TransmitView t, ReadOnlySpan<char> receiver, ushort hops)
    {
        var peer = Router.FindLocal(receiver);
        if (peer == null) return;
        Span<char> source = stackalloc char[255];
        if (!t.Source.IsEmpty && !ToAddress(t.Source, source)) return;
        source = source[..t.Source.Length];

        int bound = 400 + 4 * (receiver.Length + source.Length) + 6 * (t.QueryType.Length + t.Metadata.Length)
                  + Base64.GetMaxEncodedToUtf8Length(t.Data.Length);
        if (!peer.CanAcceptPacket(bound)) return;

        byte[] buffer = ArrayPool<byte>.Shared.Rent(bound);
        var w = new JsonOut(buffer);
        w.Raw("[\"data-transmission\",{\"package_info\":{"u8);
        if (!source.IsEmpty)
        {
            w.Raw("\"from\":"u8);
            w.Address(source);
            w.Raw(","u8);
        }
        w.Raw("\"to\":"u8);
        w.Address(receiver);
        w.Raw(",\"package_type\":"u8);
        w.Text(t.QueryType);
        w.Raw(",\"connectionid\":"u8);
        w.Number(t.ConnectionId);
        w.Raw(t.IsLast ? ",\"is_last_in_package_queue\":true"u8 : ",\"is_last_in_package_queue\":false"u8);
        w.Raw(",\"package_no\":"u8);
        w.Number(t.PacketNo);
        w.Raw(",\"message_id\":"u8);
        w.Number(t.MessageId);
        w.Raw(",\"max_hops\":"u8);
        w.Number(hops);
        w.Raw("},\"package_data\":"u8);
        w.Base64(t.Data);
        if (!t.Metadata.IsEmpty)
        {
            w.Raw(",\"metadata\":"u8);
            w.Text(t.Metadata);
        }
        w.Raw("}]"u8);
        peer.SendPacket(new Outgoing(buffer, w.Position, Pooled: true));
    }

    // ASCII digit blocks joined by '-' ("7-850-1") -> chars. False for anything else.
    static bool ToAddress(ReadOnlySpan<byte> ascii, Span<char> dst)
    {
        if (ascii.IsEmpty || ascii[0] == '-' || ascii[^1] == '-') return false;
        for (int i = 0; i < ascii.Length; i++)
        {
            byte b = ascii[i];
            if (b == '-' ? ascii[i - 1] == '-' : b is < (byte)'0' or > (byte)'9') return false;
            dst[i] = (char)b;
        }
        return true;
    }

    // "7-850" starts with the block "7" (but "70-1" doesn't)
    static bool StartsWithBlock(ReadOnlySpan<byte> address, string block)
    {
        if (address.Length < block.Length || (address.Length > block.Length && address[block.Length] != '-')) return false;
        for (int i = 0; i < block.Length; i++)
        {
            if (address[i] != block[i]) return false;
        }
        return true;
    }

    // Appends JSON pieces to a buffer that is known to be big enough.
    ref struct JsonOut(Span<byte> buffer)
    {
        readonly Span<byte> buffer = buffer;
        public int Position;

        public void Raw(scoped ReadOnlySpan<byte> s)
        {
            s.CopyTo(buffer[Position..]);
            Position += s.Length;
        }

        void Byte(byte b) => buffer[Position++] = b;

        public void Number(ulong v)
        {
            v.TryFormat(buffer[Position..], out int n);
            Position += n;
        }

        // "7-850" -> ["7","850"]
        public void Address(scoped ReadOnlySpan<char> address)
        {
            Raw("[\""u8);
            foreach (char c in address)
            {
                if (c == '-') Raw("\",\""u8);
                else Byte((byte)c);
            }
            Raw("\"]"u8);
        }

        // UTF-8 text as a JSON string. Bytes that aren't valid UTF-8 are written as \u00XX (Latin-1),
        // so the result is always valid JSON.
        public void Text(scoped ReadOnlySpan<byte> s)
        {
            bool utf8 = Utf8.IsValid(s);
            Byte((byte)'"');
            foreach (byte b in s)
            {
                if (b is (byte)'"' or (byte)'\\')
                {
                    Byte((byte)'\\');
                    Byte(b);
                }
                else if (b < 0x20 || (b >= 0x80 && !utf8))
                {
                    Raw("\\u00"u8);
                    Byte((byte)"0123456789abcdef"[b >> 4]);
                    Byte((byte)"0123456789abcdef"[b & 0xF]);
                }
                else
                {
                    Byte(b);
                }
            }
            Byte((byte)'"');
        }

        public void Base64(scoped ReadOnlySpan<byte> data)
        {
            Byte((byte)'"');
            System.Buffers.Text.Base64.EncodeToUtf8(data, buffer[Position..], out _, out int n);
            Position += n;
            Byte((byte)'"');
        }
    }
}
