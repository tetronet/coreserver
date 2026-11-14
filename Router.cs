namespace CoreServer;

// Decides where a packet for a given address goes. Addresses are canonical ("7-850-1"), see Addresses.Parse.
static class Router
{
    // Is the address inside our own network (our slaves and everything below them)?
    public static bool IsLocal(ReadOnlySpan<char> receiver) => Addresses.HasPrefix(receiver, Config.LocalAddress);

    // One of our slaves. receiver must be digit blocks.
    public static Peer? FindLocal(ReadOnlySpan<char> receiver)
    {
        string local = Config.LocalAddress;
        if (receiver.Length <= local.Length || !Addresses.HasPrefix(receiver, local))
        {
            Log.Debug($"No route for address {receiver}");
            return null;
        }

        // the block right after ours is the slave: "7-850-1" -> "850"
        var rest = receiver[(local.Length + 1)..];
        int dash = rest.IndexOf('-');
        var peer = Registry.FindSlave(dash < 0 ? rest : rest[..dash]);
        if (peer == null) Log.Debug("no address destination");
        return peer;
    }

    // Another network: the ICSP link towards it, by its network address (the first block).
    public static IcspLink? FindRemote(ReadOnlySpan<char> receiver)
    {
        int dash = receiver.IndexOf('-');
        var link = Routes.Find(dash < 0 ? receiver : receiver[..dash]);
        if (link == null) Log.Debug($"No ICSP route for address {receiver}");
        return link;
    }
}
