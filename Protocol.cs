using System.Text;
using System.Text.Json;

namespace CoreServer;

// Wire format: every message is a JSON array ["event", data] or ["event"].
// Exception: before registration a device may answer get-addr with a bare address (no JSON).
static class Protocol
{
    // the reader is not recursive, so a deep limit is safe (JS JSON.parse has none at all)
    public static readonly JsonReaderOptions ReaderOptions = new() { MaxDepth = 4096 };

    public enum Event { Unknown, DeviceType, SelfAddr, DataTransmission }

    // === server -> client control messages ===
    public static readonly Outgoing GetAddr = Control("""["get-addr"]""");
    public static readonly Outgoing AddrOk = Control("""["addr-ok"]""");
    public static readonly Outgoing GetDeviceType = Control("""["get-device-type"]""");
    public static readonly Outgoing InvalidAddr = Control("""["?invalid-addr"]""");
    public static readonly Outgoing InvalidDeviceType = Control("""["?invalid-device-type"]""");
    public static readonly Outgoing NoFreeAddr = Control("""["?no-free-addr"]""");

    // ["set-modem-local-address",["7","850"]]  (address blocks are digits, nothing to escape)
    public static Outgoing SetModemLocalAddress(string address) =>
        Control("[\"set-modem-local-address\",[\"" + address.Replace("-", "\",\"") + "\"]]");

    static Outgoing Control(string json) => Outgoing.Fixed(Encoding.UTF8.GetBytes(json));

    // === client -> server ===
    // Returns true when the buffer itself was forwarded and now belongs to a send queue.
    public static bool Dispatch(Peer peer, byte[] buffer, int length)
    {
        var msg = buffer.AsSpan(0, length);
        // only a registered peer may send data, so only then is the data object read in the same pass
        var packet = new DataTransmission.Packet();
        if (!TryParseEnvelope(msg, peer.Address != null, ref packet, out var ev, out int dataStart, out int dataEnd))
        {
            // not a JSON array: an unregistered device may answer get-addr with a raw ASCII address
            if (peer.Address == null)
            {
                string text = Encoding.UTF8.GetString(msg);
                if (text.Length <= 64) peer.OnSelfAddr(text);
            }
            else
            {
                Log.Debug("Received malformed message (expected array)");
            }
            return false;
        }

        switch (ev)
        {
            case Event.DeviceType:
                peer.OnDeviceType(dataStart < 0 ? [] : msg[dataStart..dataEnd]);
                return false;
            case Event.SelfAddr:
                peer.OnSelfAddr(ShortString(dataStart < 0 ? [] : msg[dataStart..dataEnd]));
                return false;
            case Event.DataTransmission:
                return dataStart >= 0 && DataTransmission.Handle(peer, buffer, length, dataStart, dataEnd, in packet);
            default:
                Log.Debug("Received unknown event");
                return false;
        }
    }

    // Validates the whole message and finds the event name and the byte range of the data element.
    // Returns false if the message is not a valid JSON array (dataStart = -1 when there is no data).
    // For "data-transmission" (when readData) the data object is analysed during this same pass
    // into `packet`, so the big package_data string is scanned once, not twice.
    static bool TryParseEnvelope(ReadOnlySpan<byte> msg, bool readData, ref DataTransmission.Packet packet,
                                 out Event ev, out int dataStart, out int dataEnd)
    {
        ev = Event.Unknown;
        dataStart = dataEnd = -1;
        // Cheap pre-check: anything that isn't [ ... ] (JSON whitespace around is allowed) can't be valid,
        // and rejecting it here skips the JsonException the reader would throw (exceptions are what made
        // garbage 2x more expensive than valid messages). Same result as the full parse, just faster.
        var trimmed = msg.Trim(" \t\r\n"u8);
        if (trimmed.Length < 2 || trimmed[0] != (byte)'[' || trimmed[^1] != (byte)']') return false;
        try
        {
            var r = new Utf8JsonReader(msg, ReaderOptions);
            if (!r.Read() || r.TokenType != JsonTokenType.StartArray) return false;
            for (int i = 0; r.Read() && r.TokenType != JsonTokenType.EndArray; i++)
            {
                if (i == 0 && r.TokenType == JsonTokenType.String)
                {
                    ev = r.ValueTextEquals("data-transmission"u8) ? Event.DataTransmission
                       : r.ValueTextEquals("self-addr"u8) ? Event.SelfAddr
                       : r.ValueTextEquals("device-type"u8) ? Event.DeviceType
                       : Event.Unknown;
                }
                if (i == 1)
                {
                    dataStart = (int)r.TokenStartIndex;
                    if (readData && ev == Event.DataTransmission) DataTransmission.Read(ref r, ref packet);
                    else r.Skip();
                    dataEnd = (int)r.BytesConsumed;
                    continue;
                }
                r.Skip();
            }
            while (r.Read()) { } // throws on anything after the array
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    // Is this raw JSON value exactly the given string?
    public static bool IsString(ReadOnlySpan<byte> json, ReadOnlySpan<byte> expected)
    {
        if (json.IsEmpty) return false;
        var r = new Utf8JsonReader(json, ReaderOptions);
        return r.Read() && r.TokenType == JsonTokenType.String && r.ValueTextEquals(expected);
    }

    // The decoded string if this raw JSON value is a string of sane length (an address), otherwise null.
    static string? ShortString(ReadOnlySpan<byte> json)
    {
        if (json.IsEmpty || json.Length > 512) return null;
        var r = new Utf8JsonReader(json, ReaderOptions);
        return r.Read() && r.TokenType == JsonTokenType.String ? r.GetString() : null;
    }
}
