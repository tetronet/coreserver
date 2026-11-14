using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CoreServer;

// CableEncryption v1.5: everything on a wire is AES-256-GCM with a key shared in advance (seckeys in
// config.json). No handshake, and nothing on the TCP stream is distinguishable from random bytes:
//
//   [salt, 32 random bytes]                                  once, at the start of each direction
//   [length, 4 bytes][tag, 16]  [body, length bytes][tag, 16]  every record
//
// - Each side starts its direction with its own random salt. The direction's session key is
//   HKDF-SHA256(shared key, salt, info "CableEncryption v1.5").
// - Nonces are not sent: a 96-bit big-endian counter per direction, from 0, +1 for every AEAD
//   operation (the length block and the body take one each). Fresh salt = fresh key, so a nonce
//   never repeats, whatever the clock does.
// - length (uint32 BE) is the body's size without its tag. The body is one whole ICSP packet
//   (with its own 5-byte header) followed by any number of padding bytes, which are ignored.
// - No additional authenticated data.
static class CableEncryption
{
    public const int KeyBytes = 32;
    public const int SaltBytes = 32;
    public const int TagBytes = 16;
    public const int NonceBytes = 12;
    public const int LengthBlock = 4 + TagBytes;           // encrypted length + its tag
    public const int Overhead = LengthBlock + TagBytes;    // per record, padding not counted
    // small packets (keep-alives, routes, short data) get 0..MaxPadding random bytes, so their sizes
    // don't give them away; big ones are not padded (that would only cost bandwidth)
    public const int MaxPadding = 255;
    const int PadBelow = 1024;

    public static readonly byte[] Info = "CableEncryption v1.5"u8.ToArray();

    public static byte[] NewKey() => RandomNumberGenerator.GetBytes(KeyBytes);

    // our salt for one connection (remembered, see Remember)
    public static byte[] NewSalt()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltBytes);
        Remember(salt);
        return salt;
    }

    public static int Padding(int frameLength) =>
        frameLength < PadBelow ? RandomNumberGenerator.GetInt32(MaxPadding + 1) : 0;

    // Salts this process has used or accepted in the last 24 h. A salt seen twice means a recorded
    // stream played again, or our own stream sent back to us: both are refused.
    static readonly Dictionary<string, long> seen = [];
    static readonly Lock gate = new();

    public static bool Remember(ReadOnlySpan<byte> salt)
    {
        string key = Convert.ToBase64String(salt);
        long now = Environment.TickCount64;
        lock (gate)
        {
            if (seen.Count >= 10_000)
            {
                foreach (var (old, at) in seen.ToArray())
                {
                    if (now - at > 86_400_000) seen.Remove(old);
                }
            }
            return seen.TryAdd(key, now);
        }
    }
}

// One direction of one connection. Not thread-safe: one sender, one receiver.
sealed class CableCipher : IDisposable
{
    readonly AesGcm aes;
    ulong counter;

    public CableCipher(byte[] sharedKey, ReadOnlySpan<byte> salt)
    {
        Span<byte> key = stackalloc byte[CableEncryption.KeyBytes];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedKey, key, salt, CableEncryption.Info);
        aes = new AesGcm(key, CableEncryption.TagBytes);
        CryptographicOperations.ZeroMemory(key);
    }

    public void Dispose() => aes.Dispose();

    void NextNonce(Span<byte> nonce)
    {
        nonce[..4].Clear();
        BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], counter++);
    }

    // Writes one record for an ICSP packet; dst must hold frame.Length + padding + Overhead bytes.
    public int Seal(ReadOnlySpan<byte> frame, int padding, Span<byte> dst)
    {
        Span<byte> nonce = stackalloc byte[CableEncryption.NonceBytes];
        int n = frame.Length + padding;
        var length = dst[..4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)n);
        NextNonce(nonce);
        aes.Encrypt(nonce, length, length, dst.Slice(4, CableEncryption.TagBytes));

        var body = dst.Slice(CableEncryption.LengthBlock, n);
        frame.CopyTo(body);
        body[frame.Length..].Clear(); // padding: encrypted, so it looks random anyway
        NextNonce(nonce);
        aes.Encrypt(nonce, body, body, dst.Slice(CableEncryption.LengthBlock + n, CableEncryption.TagBytes));
        return CableEncryption.Overhead + n;
    }

    // block = [length][tag], decrypted in place. False = wrong key or changed data.
    public bool OpenLength(Span<byte> block, out uint length)
    {
        length = 0;
        if (!Open(block[..4], block.Slice(4, CableEncryption.TagBytes))) return false;
        length = BinaryPrimitives.ReadUInt32BigEndian(block);
        return true;
    }

    // record = [body][tag]; the body is decrypted in place
    public bool OpenBody(Span<byte> record) =>
        Open(record[..^CableEncryption.TagBytes], record[^CableEncryption.TagBytes..]);

    // the body of a skipped (too big) record still used up a nonce
    public void SkipBody() => counter++;

    bool Open(Span<byte> data, ReadOnlySpan<byte> tag)
    {
        Span<byte> nonce = stackalloc byte[CableEncryption.NonceBytes];
        NextNonce(nonce);
        try
        {
            aes.Decrypt(nonce, data, tag, data);
            return true;
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }
    }
}
