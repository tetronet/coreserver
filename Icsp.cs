using System.Buffers.Binary;

namespace CoreServer;

// ICSP wire format (see ICSP.odt). Every frame is [length: u32 BE][type: u8][body...],
// where length counts the type byte and the body (so it is at least 1). All numbers are big-endian.
static class Icsp
{
    public const byte Transmit = 0x01, NewRoutes = 0x40, WhoAreYou = 0x20, ImThis = 0xA0,
                      KeepAlive = 0x08, KeepAliveResult = 0x0A, Error = 0xFF, Die = 0x7F;

    public const int HeaderBytes = 5;        // length + type
    public const int AddressBytes = 32;      // network address, BCD with 0xF padding
    public const int MaxNetworkDigits = 64;
    public const int RouteBytes = 48;
    public const int HopsOffset = 5;         // Max Hops (u16) inside a Transmit frame: right after the header
    public const byte False = 0x00, True = 0xFF;

    // Biggest possible Transmit frame: header + hops + 3 strings of 255 + fixed fields + data + metadata.
    public const int MaxTransmitFrame = HeaderBytes + 2 + 3 * 256 + 4 + 1 + 8 + 8 + 2 + 65535 + 2 + 65535;

    public static readonly byte[] WhoAreYouFrame = Empty(WhoAreYou);
    public static readonly byte[] KeepAliveFrame = Empty(KeepAlive);
    public static readonly byte[] KeepAliveResultFrame = Empty(KeepAliveResult);
    public static readonly byte[] DieFrame = Empty(Die);
    // first touched after Config.Load()
    public static readonly byte[] ImThisFrame = BuildImThis();

    static byte[] Empty(byte type)
    {
        var frame = new byte[HeaderBytes];
        WriteHeader(frame, type, frame.Length);
        return frame;
    }

    static byte[] BuildImThis()
    {
        var frame = new byte[HeaderBytes + AddressBytes];
        WriteHeader(frame, ImThis, frame.Length);
        EncodeAddress(Config.LocalAddress, frame.AsSpan(HeaderBytes));
        return frame;
    }

    public static void WriteHeader(Span<byte> frame, byte type, int frameLength)
    {
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)(frameLength - 4));
        frame[4] = type;
    }

    // "063" -> 06 3F FF FF ... (32 bytes). digits: 1..64 ASCII digits, checked by the caller.
    public static void EncodeAddress(ReadOnlySpan<char> digits, Span<byte> dst)
    {
        dst[..AddressBytes].Fill(0xFF);
        for (int i = 0; i < digits.Length; i++)
        {
            int nibble = digits[i] - '0';
            ref byte b = ref dst[i >> 1];
            b = (i & 1) == 0 ? (byte)((nibble << 4) | 0x0F) : (byte)((b & 0xF0) | nibble);
        }
    }

    // Writes the digits into dst (room for 64) and returns their count, or -1 if the address is
    // broken: no digits at all, a nibble 0xA..0xE, or a digit after the 0xF padding.
    public static int DecodeAddress(ReadOnlySpan<byte> src, Span<char> dst)
    {
        int n = 0;
        bool padding = false;
        for (int i = 0; i < MaxNetworkDigits; i++)
        {
            int nibble = (i & 1) == 0 ? src[i >> 1] >> 4 : src[i >> 1] & 0x0F;
            if (nibble == 0xF)
            {
                padding = true;
                continue;
            }
            if (padding || nibble > 9) return -1;
            dst[n++] = (char)('0' + nibble);
        }
        return n == 0 ? -1 : n;
    }

    // === Transmit ===
    public ref struct TransmitView
    {
        public ushort Hops;
        public ReadOnlySpan<byte> Destination, Source, QueryType;
        public uint ConnectionId;
        public bool IsLast;
        public ulong PacketNo, MessageId;
        public ReadOnlySpan<byte> Data, Metadata;
    }

    // frame = the whole Transmit frame, length prefix included. False = truncated, or a boolean that is
    // neither 0x00 nor 0xFF (such a packet must be ignored). Bytes after Metadata are ignored.
    public static bool TryParseTransmit(ReadOnlySpan<byte> frame, out TransmitView t)
    {
        t = default;
        var c = new Cursor(frame[HeaderBytes..]);
        t.Hops = c.U16();
        t.Destination = c.Take(c.U8());
        t.Source = c.Take(c.U8());
        t.QueryType = c.Take(c.U8());
        t.ConnectionId = c.U32();
        byte isLast = c.U8();
        t.PacketNo = c.U64();
        t.MessageId = c.U64();
        t.Data = c.Take(c.U16());
        t.Metadata = c.Take(c.U16());
        t.IsLast = isLast == True;
        return c.Ok && isLast is False or True;
    }

    // Reads fields one after another; any read past the end turns Ok off and returns zeros.
    ref struct Cursor(ReadOnlySpan<byte> rest)
    {
        ReadOnlySpan<byte> rest = rest;
        public bool Ok = true;

        public ReadOnlySpan<byte> Take(int n)
        {
            if (!Ok || n > rest.Length)
            {
                Ok = false;
                return default;
            }
            var taken = rest[..n];
            rest = rest[n..];
            return taken;
        }

        public byte U8() { var b = Take(1); return Ok ? b[0] : (byte)0; }
        public ushort U16() { var b = Take(2); return Ok ? BinaryPrimitives.ReadUInt16BigEndian(b) : (ushort)0; }
        public uint U32() { var b = Take(4); return Ok ? BinaryPrimitives.ReadUInt32BigEndian(b) : 0; }
        public ulong U64() { var b = Take(8); return Ok ? BinaryPrimitives.ReadUInt64BigEndian(b) : 0; }
    }

    // Writes fields one after another into a buffer that is known to be big enough.
    public ref struct Writer(Span<byte> buffer)
    {
        readonly Span<byte> buffer = buffer;
        public int Position;

        public Span<byte> Free => buffer[Position..];
        public void U8(byte v) => buffer[Position++] = v;
        public void U16(ushort v) { BinaryPrimitives.WriteUInt16BigEndian(Free, v); Position += 2; }
        public void U32(uint v) { BinaryPrimitives.WriteUInt32BigEndian(Free, v); Position += 4; }
        public void U64(ulong v) { BinaryPrimitives.WriteUInt64BigEndian(Free, v); Position += 8; }
        public void Bytes(ReadOnlySpan<byte> v) { v.CopyTo(Free); Position += v.Length; }

        // ASCII chars (digits and '-') as bytes, behind a u8 length
        public void ShortAscii(ReadOnlySpan<char> v)
        {
            U8((byte)v.Length);
            for (int i = 0; i < v.Length; i++) buffer[Position + i] = (byte)v[i];
            Position += v.Length;
        }
    }
}
