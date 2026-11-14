using System.Text.Json;

namespace CoreServer;

// An address is a list of digit blocks: "7-850" <-> ["7", "850"].
static class Addresses
{
    const int MaxBlocks = 16;
    const int MaxBlockLength = 16;
    const int MaxStringLength = (MaxBlocks + 1) * (MaxBlockLength + 1);

    // Room for any canonical address, even while a trailing "*" is still in it.
    public const int MaxCanonicalLength = MaxStringLength;

    // Turns "7-850" / ["7","850"] / ["7",850,"*"] (raw JSON value) into its canonical text "7-850",
    // written into dst (at least MaxCanonicalLength chars). Returns the length, or -1 for anything
    // malformed (non-digit blocks, too long, wrong type...). Allocates nothing: runs on every packet.
    public static int Parse(ReadOnlySpan<byte> json, Span<char> dst)
    {
        var r = new Utf8JsonReader(json, Protocol.ReaderOptions);
        r.Read();
        if (r.TokenType == JsonTokenType.String)
        {
            // cheap size check before decoding (one char is at most 6 escaped bytes)
            if (r.ValueSpan.Length > MaxStringLength * 6) return -1;
            // decoded text is never longer than its raw bytes
            Span<char> text = stackalloc char[r.ValueSpan.Length];
            int n = r.CopyString(text);
            if (n > MaxStringLength) return -1;
            return CanonicalFromString(text[..n], dst);
        }
        if (r.TokenType != JsonTokenType.StartArray) return -1;

        // Blocks are written joined with '-'. A "*" block is allowed only as the very last one,
        // which is checked at the end (we don't know which element is the last one yet).
        Span<char> block = stackalloc char[MaxBlockLength * 6];
        int w = 0, count = 0, lastStart = 0;
        bool lastIsStar = false;
        while (r.Read() && r.TokenType != JsonTokenType.EndArray)
        {
            if (count > MaxBlocks) return -1; // "+1" leaves room for a trailing "*"
            if (lastIsStar) return -1;        // "*" followed by another block
            int len;
            if (r.TokenType == JsonTokenType.String)
            {
                if (r.ValueSpan.Length > MaxBlockLength * 6) return -1;
                len = r.CopyString(block);
            }
            else if (r.TokenType == JsonTokenType.Number)
            {
                len = NumberToBlock(ref r, block);
                if (len < 0) return -1;
            }
            else return -1;

            var b = block[..len];
            lastIsStar = b is "*";
            if (!lastIsStar && !IsDigitBlock(b)) return -1;
            lastStart = w;
            if (count > 0) dst[w++] = '-';
            b.CopyTo(dst[w..]);
            w += len;
            count++;
        }
        if (lastIsStar) { w = lastStart; count--; } // trailing wildcard
        return count is 0 or > MaxBlocks ? -1 : w;
    }

    // "7-850", "7-850-*" -> "7-850"; same rules as Validate() on the split string.
    static int CanonicalFromString(ReadOnlySpan<char> text, Span<char> dst)
    {
        if (text is "*") return -1;                // only a wildcard, no blocks
        if (text.EndsWith("-*")) text = text[..^2]; // trailing wildcard
        int count = 0;
        foreach (var range in text.Split('-'))
        {
            if (++count > MaxBlocks || !IsDigitBlock(text[range])) return -1;
        }
        text.CopyTo(dst);
        return text.Length;
    }

    static bool IsDigitBlock(ReadOnlySpan<char> block) =>
        block.Length is > 0 and <= MaxBlockLength && !block.ContainsAnyExceptInRange('0', '9');

    // Is the canonical address `address` the same as `prefix` or inside it? Compares whole blocks,
    // so "70-1" does NOT count as being inside "7". (prefix must be canonical too)
    public static bool HasPrefix(ReadOnlySpan<char> address, string prefix) =>
        address.StartsWith(prefix) && (address.Length == prefix.Length || address[prefix.Length] == '-');

    public static string[]? Parse(string raw)
    {
        if (raw.Length > MaxStringLength) return null;
        return Validate(new List<string>(raw.Split('-')));
    }

    static string[]? Validate(List<string> blocks)
    {
        if (blocks.Count > 0 && blocks[^1] == "*") blocks.RemoveAt(blocks.Count - 1); // trailing wildcard
        if (blocks.Count == 0 || blocks.Count > MaxBlocks) return null;
        foreach (var block in blocks)
        {
            if (block.Length == 0 || block.Length > MaxBlockLength) return null;
            foreach (char c in block)
            {
                if (c is < '0' or > '9') return null;
            }
        }
        return blocks.ToArray();
    }

    // JSON numbers in an address array are accepted the way JS String(n) prints them:
    // only non-negative integers print as plain digits.
    // Writes the digits into dst, returns their count or -1.
    static int NumberToBlock(ref Utf8JsonReader r, scoped Span<char> dst)
    {
        if (!r.TryGetDouble(out double d) || d != Math.Floor(d) || d < 0 || d >= 1e16) return -1;
        return ((long)d).TryFormat(dst, out int n, default, System.Globalization.CultureInfo.InvariantCulture) ? n : -1;
    }

    // Compares whole blocks, so "70-1" does NOT count as being inside "7".
    static bool HasPrefix(string[] blocks, string[] prefix)
    {
        if (prefix.Length > blocks.Length) return false;
        for (int i = 0; i < prefix.Length; i++)
        {
            if (blocks[i] != prefix[i]) return false;
        }
        return true;
    }

    // Is this exactly an address of a direct slave of this server? (e.g. 7-850)
    public static bool IsSlave(string[] blocks) =>
        blocks.Length == Config.LocalBlocks.Length + 1
        && HasPrefix(blocks, Config.LocalBlocks)
        && blocks[^1].Length == Config.SmlaLength;
}
