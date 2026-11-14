using System.Net;
using System.Security.Cryptography;

namespace CoreServer;

// Who is connected and under which address.
// Every registered address is a direct slave "<LocalAddress>-NNN" with exactly SmlaLength digits,
// so the table is a plain array indexed by NNN: no hashing, no strings on the hot path.
// Lookups (every packet) are lock-free; changes (rare) go under one lock.
static class Registry
{
    static readonly int space = (int)Math.Pow(10, Config.SmlaLength);
    static readonly Peer?[] slots = new Peer?[space];
    static readonly Dictionary<IPAddress, int> perIp = new();
    static readonly Lock gate = new();
    static int clients;

    // slave = the digits of the slave block, e.g. "850"
    public static Peer? FindSlave(ReadOnlySpan<char> slave)
    {
        if (slave.Length != Config.SmlaLength) return null;
        return Volatile.Read(ref slots[SlotOf(slave)]);
    }

    // digits only (checked by the caller), at most SmlaLength of them
    static int SlotOf(ReadOnlySpan<char> digits)
    {
        int n = 0;
        foreach (char c in digits) n = n * 10 + (c - '0');
        return n;
    }

    // === connection limits ===
    public static bool TryConnect(IPAddress ip)
    {
        lock (gate)
        {
            int fromIp = perIp.GetValueOrDefault(ip);
            if (clients >= Config.MaxClients || fromIp >= Config.MaxClientsPerIp) return false;
            perIp[ip] = fromIp + 1;
            clients++;
            return true;
        }
    }

    public static void Disconnect(IPAddress ip)
    {
        lock (gate)
        {
            clients--;
            int left = perIp.GetValueOrDefault(ip, 1) - 1;
            if (left <= 0) perIp.Remove(ip); else perIp[ip] = left;
        }
    }

    // === addresses ===
    // Picks and registers a free random slave address, or returns null if (practically) none is left.
    public static string? TryAllocate(Peer peer)
    {
        lock (gate)
        {
            for (int i = 0; i < Config.MaxAddressAllocationAttempts; i++)
            {
                int slot = RandomNumberGenerator.GetInt32(space);
                if (slots[slot] == null)
                {
                    string address = Config.LocalAddress + "-" + slot.ToString().PadLeft(Config.SmlaLength, '0');
                    Register(peer, address, slot);
                    return address;
                }
            }
        }
        return null;
    }

    // Registers a requested slave address (Addresses.IsSlave) unless somebody else is online under it (no hijacking).
    public static bool TryClaim(Peer peer, string address)
    {
        int slot = SlotOf(address.AsSpan(address.Length - Config.SmlaLength));
        lock (gate)
        {
            var holder = slots[slot];
            if (holder != null && holder != peer && holder.IsOpen) return false;
            Register(peer, address, slot);
            return true;
        }
    }

    static void Register(Peer peer, string address, int slot)
    {
        peer.SetAddress(address, slot);
        Volatile.Write(ref slots[slot], peer); // publishes the peer's address fields too
    }

    // Frees the peer's address, but only if it still belongs to this peer.
    public static void Release(Peer peer)
    {
        if (peer.Address != null) Interlocked.CompareExchange(ref slots[peer.Slot], null, peer);
    }
}
