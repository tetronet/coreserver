using System.Text.Json;

namespace CoreServer;

// All settings live in config.json (see the commented example next to the project).
// This class only reads, checks and exposes them. Load() must run before anything else.
//
// Where the file is looked for, first match wins:
//   1. command line:            CoreServer --config /path/to/config.json
//   2. environment variable:    CORESERVER_CONFIG=/path/to/config.json
//   3. next to the executable:  <folder of CoreServer>/config.json
// If it doesn't exist, it is created there with the built-in defaults.
// Keys that are missing in the file keep their defaults; an unknown key (a typo) is an error.
static class Config
{
    public static string Path { get; private set; } = "";

    // === ADDRESS OF THIS SERVER (MUST BE A SINGLE BLOCK FOR A CORESERVER) ===
    public static string LocalAddress { get; private set; } = "";
    public static string[] LocalBlocks { get; private set; } = [];
    // how many digits are generated for slaves
    public static int SmlaLength { get; private set; }

    // === NETWORK ===
    public static int Port { get; private set; }
    // environment variable CORESERVER_TLS=0 turns TLS off whatever the file says (handy for local tests)
    public static bool UseTls { get; private set; }
    public static string TlsKeyPath { get; private set; } = "";
    public static string TlsCertPath { get; private set; } = "";

    // === SEND QUEUE ===
    public static int MaxSendQueuePackets { get; private set; }
    public static long MaxSendQueueBytes { get; private set; }
    public static long MaxTotalQueuedBytes { get; private set; }
    public static int MaxQueueDelayMs { get; private set; }
    public static int SocketSendBufferBytes { get; private set; }
    public static int StuckKickMs { get; private set; }
    public static long MaxControlBacklogBytes { get; private set; }

    // === LIMITS ===
    public static int MaxPackageDataLength { get; private set; }
    public static int MaxPayloadBytes { get; private set; }
    public static int RegistrationTimeoutMs { get; private set; }
    public static int MaxClients { get; private set; }
    public static int MaxClientsPerIp { get; private set; }
    public static TimeSpan Heartbeat { get; private set; }
    public static int MaxAddressAllocationAttempts { get; private set; }
    public static int ReceiveBufferBytes { get; private set; }

    // === ANTI-SPOOFING ===
    public static bool EnforceSourceAddress { get; private set; }

    // === ICSP (links to other core servers) ===
    public static int IcspPort { get; private set; }         // 0 = don't listen, only dial
    public static Wire[] Wires { get; private set; } = [];   // empty = ICSP off
    public static int IcspKeepAliveIntervalMs { get; private set; }
    public static int IcspTimeoutMs { get; private set; }
    public static int IcspRouteIntervalMs { get; private set; }
    public static uint IcspRouteTtlMs { get; private set; }
    public static int IcspReconnectMs { get; private set; }
    public static long IcspMaxSendQueueBytes { get; private set; }
    // CableEncryption key of every wire (same index as Wires), from seckeys or generated
    public static byte[][] WireKeys { get; private set; } = [];

    // Reads (or creates) the file. Throws ConfigException with a readable message on any problem.
    public static void Load(string[] args)
    {
        Path = FindPath(args);
        Settings s;
        if (File.Exists(Path))
        {
            s = SettingsJson.Read(Path, File.ReadAllText(Path));
        }
        else
        {
            s = new Settings();
            try
            {
                File.WriteAllText(Path, SettingsJson.Write(s));
                Log.Info($"{Path} not found, created it with the default settings");
            }
            catch (Exception e)
            {
                Log.Error($"{Path} not found and can't be created ({e.Message}), using the default settings");
            }
        }

        Validate(s);

        LocalAddress = s.LocalAddress;
        LocalBlocks = s.LocalAddress.Split('-');
        SmlaLength = s.SmlaLength;
        Port = s.Port;
        UseTls = s.UseTls && Environment.GetEnvironmentVariable("CORESERVER_TLS") != "0";
        TlsKeyPath = s.TlsKeyPath;
        TlsCertPath = s.TlsCertPath;
        MaxSendQueuePackets = s.MaxSendQueuePackets;
        MaxSendQueueBytes = s.MaxSendQueueBytes;
        MaxTotalQueuedBytes = s.MaxTotalQueuedBytes;
        MaxQueueDelayMs = s.MaxQueueDelayMs;
        SocketSendBufferBytes = s.SocketSendBufferBytes;
        StuckKickMs = s.StuckKickMs;
        MaxControlBacklogBytes = s.MaxControlBacklogBytes;
        MaxPackageDataLength = s.MaxPackageDataLength;
        MaxPayloadBytes = s.MaxPayloadBytes;
        RegistrationTimeoutMs = s.RegistrationTimeoutMs;
        MaxClients = s.MaxClients;
        MaxClientsPerIp = s.MaxClientsPerIp;
        Heartbeat = TimeSpan.FromSeconds(s.HeartbeatSeconds);
        MaxAddressAllocationAttempts = s.MaxAddressAllocationAttempts;
        ReceiveBufferBytes = s.ReceiveBufferBytes;
        EnforceSourceAddress = s.EnforceSourceAddress;
        IcspPort = s.IcspPort;
        Wires = s.Wires.Select((w, i) => Wire.Parse(w, i)!).ToArray();
        IcspKeepAliveIntervalMs = s.IcspKeepAliveIntervalMs;
        IcspTimeoutMs = s.IcspTimeoutMs;
        IcspRouteIntervalMs = s.IcspRouteIntervalMs;
        IcspRouteTtlMs = (uint)s.IcspRouteTtlMs;
        IcspReconnectMs = s.IcspReconnectMs;
        IcspMaxSendQueueBytes = s.IcspMaxSendQueueBytes;
        WireKeys = LoadKeys(s);
    }

    // Keys for all wires. A missing or empty one is generated and written into seckeys in the file.
    // It is NEVER printed: the console may well go over an unencrypted line.
    static byte[][] LoadKeys(Settings s)
    {
        var keys = new byte[Wires.Length][];
        var generated = new List<(string Wire, string Hex)>();
        foreach (var wire in Wires)
        {
            if (s.SecKeys.TryGetValue(wire.Name, out string? hex) && hex.Length > 0)
            {
                keys[wire.Index] = Convert.FromHexString(hex);
            }
            else if (generated.FindIndex(g => g.Wire == wire.Name) is int i and >= 0)
            {
                keys[wire.Index] = Convert.FromHexString(generated[i].Hex); // the same wire listed twice
            }
            else
            {
                keys[wire.Index] = CableEncryption.NewKey();
                generated.Add((wire.Name, Convert.ToHexStringLower(keys[wire.Index])));
            }
        }
        if (generated.Count > 0)
        {
            try
            {
                SettingsJson.StoreKeys(Path, generated);
                foreach (var g in generated)
                    Log.Info($"There was no key for {g.Wire}, so it was written in the config's seckeys. NEVER transfer these keys insecurely");
            }
            catch (Exception e)
            {
                foreach (var g in generated)
                    Log.Error($"There was no key for {g.Wire} and it can't be written to {Path} ({e.Message}). " +
                              "ICSP over this wire won't work until seckeys has a key for it");
            }
        }
        if (Wires.Length > 0 && !OperatingSystem.IsWindows()
            && (File.GetUnixFileMode(Path) & UnixFileMode.OtherRead) != 0)
        {
            Log.Info($"WARNING: {Path} holds ICSP keys but every user on this machine can read it (chmod 600 it)");
        }
        return keys;
    }

    static string FindPath(string[] args)
    {
        int i = Array.IndexOf(args, "--config");
        if (i >= 0)
        {
            if (i + 1 >= args.Length) throw new ConfigException("--config needs a file path after it");
            return System.IO.Path.GetFullPath(args[i + 1]);
        }
        string? env = Environment.GetEnvironmentVariable("CORESERVER_CONFIG");
        if (!string.IsNullOrEmpty(env)) return System.IO.Path.GetFullPath(env);
        return System.IO.Path.Combine(AppContext.BaseDirectory, "config.json");
    }

    static void Validate(Settings s)
    {
        var errors = new List<string>();
        void Check(bool ok, string message) { if (!ok) errors.Add(message); }

        bool addressOk = s.LocalAddress is { Length: > 0 }
            && s.LocalAddress.Split('-').All(b => b.Length is > 0 and <= 16 && b.All(char.IsAsciiDigit));
        Check(addressOk, "local_address must be digit blocks like \"7\"");
        // the registry is an array of 10^smla_length entries (8 bytes each)
        Check(s.SmlaLength is >= 1 and <= 7, "smla_length must be 1..7");
        Check(s.Port is >= 1 and <= 65535, "port must be 1..65535");
        if (s.UseTls)
        {
            Check(!string.IsNullOrWhiteSpace(s.TlsKeyPath), "tls_key_path is empty but use_tls is true");
            Check(!string.IsNullOrWhiteSpace(s.TlsCertPath), "tls_cert_path is empty but use_tls is true");
        }
        Check(s.MaxSendQueuePackets > 0, "max_send_queue_packets must be > 0");
        Check(s.MaxSendQueueBytes > 0, "max_send_queue_bytes must be > 0");
        Check(s.MaxTotalQueuedBytes >= s.MaxSendQueueBytes, "max_total_queued_bytes must be >= max_send_queue_bytes");
        Check(s.MaxQueueDelayMs > 0, "max_queue_delay_ms must be > 0");
        Check(s.SocketSendBufferBytes >= 4096, "socket_send_buffer_bytes must be >= 4096");
        Check(s.StuckKickMs > 0, "stuck_kick_ms must be > 0");
        Check(s.MaxControlBacklogBytes > 0, "max_control_backlog_bytes must be > 0");
        Check(s.MaxPackageDataLength > 0, "max_package_data_length must be > 0");
        Check(s.MaxPayloadBytes is >= 1024 and <= 64 * 1024 * 1024, "max_payload_bytes must be 1 KB..64 MB");
        Check(s.RegistrationTimeoutMs > 0, "registration_timeout_ms must be > 0");
        Check(s.MaxClients > 0, "max_clients must be > 0");
        Check(s.MaxClientsPerIp > 0, "max_clients_per_ip must be > 0");
        Check(s.HeartbeatSeconds > 0, "heartbeat_seconds must be > 0");
        Check(s.MaxAddressAllocationAttempts > 0, "max_address_allocation_attempts must be > 0");
        Check(s.ReceiveBufferBytes >= 256 && s.ReceiveBufferBytes <= s.MaxPayloadBytes, "receive_buffer_bytes must be 256..max_payload_bytes");

        Check(s.IcspPort is >= 0 and <= 65535, "icsp_port must be 0..65535 (0 = don't listen)");
        foreach (string w in s.Wires)
        {
            Check(Wire.Parse(w, 0) != null, $"wires: \"{w}\" is not \"host\" or \"host:port\"");
        }
        if (s.Wires.Length > 0)
        {
            Check(addressOk && !s.LocalAddress.Contains('-'), "local_address must be a single block (like \"7\") to use ICSP wires");
        }
        Check(s.IcspKeepAliveIntervalMs > 0, "icsp_keepalive_interval_ms must be > 0");
        Check(s.IcspTimeoutMs > s.IcspKeepAliveIntervalMs * 3L / 2, "icsp_timeout_ms must be > 1.5 x icsp_keepalive_interval_ms (keep-alives come at random 0.5..1.5 x intervals)");
        Check(s.IcspRouteIntervalMs > 0, "icsp_route_interval_ms must be > 0");
        Check(s.IcspRouteTtlMs is > 0 and <= uint.MaxValue, "icsp_route_ttl_ms must be 1..4294967295");
        Check(s.IcspReconnectMs > 0, "icsp_reconnect_ms must be > 0");
        Check(s.IcspMaxSendQueueBytes > 0 && s.IcspMaxSendQueueBytes <= s.MaxTotalQueuedBytes,
              "icsp_max_send_queue_bytes must be 1..max_total_queued_bytes");
        foreach (var (wire, key) in s.SecKeys)
        {
            Check(key.Length == 0 || key.Length == CableEncryption.KeyBytes * 2 && key.All(char.IsAsciiHexDigit),
                  $"seckeys: the key for \"{wire}\" must be {CableEncryption.KeyBytes * 2} hex digits (or \"\" to generate one)");
        }

        if (errors.Count > 0) throw new ConfigException($"{Path}:\n  " + string.Join("\n  ", errors));
    }
}

sealed class ConfigException(string message) : Exception(message);

// The file's contents. The values here are the defaults (used for missing keys and for a new file).
sealed class Settings
{
    public string LocalAddress { get; set; } = "7";
    public int SmlaLength { get; set; } = 3;

    public int Port { get; set; } = 3000;
    public bool UseTls { get; set; } = true;
    public string TlsKeyPath { get; set; } = "/etc/letsencrypt/live/data-set.su/privkey.pem";
    public string TlsCertPath { get; set; } = "/etc/letsencrypt/live/data-set.su/fullchain.pem";

    public int MaxSendQueuePackets { get; set; } = 1024;
    public long MaxSendQueueBytes { get; set; } = 4 * 1024 * 1024;
    public long MaxTotalQueuedBytes { get; set; } = 256 * 1024 * 1024;
    public int MaxQueueDelayMs { get; set; } = 1000;
    public int SocketSendBufferBytes { get; set; } = 64 * 1024;
    public int StuckKickMs { get; set; } = 10000;
    public long MaxControlBacklogBytes { get; set; } = 1024 * 1024;

    public int MaxPackageDataLength { get; set; } = 87385;
    public int MaxPayloadBytes { get; set; } = 128 * 1024;
    public int RegistrationTimeoutMs { get; set; } = 10000;
    public int MaxClients { get; set; } = 2000;
    public int MaxClientsPerIp { get; set; } = 50;
    public int HeartbeatSeconds { get; set; } = 30;
    public int MaxAddressAllocationAttempts { get; set; } = 1000;
    public int ReceiveBufferBytes { get; set; } = 16 * 1024;

    public bool EnforceSourceAddress { get; set; } = true;

    public int IcspPort { get; set; } = Wire.DefaultPort;
    public string[] Wires { get; set; } = [];
    public int IcspKeepAliveIntervalMs { get; set; } = 2000;
    public int IcspTimeoutMs { get; set; } = 10000;
    public int IcspRouteIntervalMs { get; set; } = 15 * 60 * 1000;
    public long IcspRouteTtlMs { get; set; } = 86400000;
    public int IcspReconnectMs { get; set; } = 5000;
    public long IcspMaxSendQueueBytes { get; set; } = 16 * 1024 * 1024;
    public Dictionary<string, string> SecKeys { get; set; } = [];   // wire (as written in wires) -> hex key
}


// Reads and writes Settings as JSON by hand: no reflection and no source generator, so it works
// with Native AOT and in any IDE. Every key is listed once in Fields (name, how to read, how to write).
static class SettingsJson
{
    sealed record Field(string Name, Action<Settings, JsonElement, string> Read, Action<Settings, Utf8JsonWriter> Write);

    static readonly Field[] Fields =
    [
        Str("local_address", s => s.LocalAddress, (s, v) => s.LocalAddress = v),
        Int("smla_length", s => s.SmlaLength, (s, v) => s.SmlaLength = v),

        Int("port", s => s.Port, (s, v) => s.Port = v),
        Bool("use_tls", s => s.UseTls, (s, v) => s.UseTls = v),
        Str("tls_key_path", s => s.TlsKeyPath, (s, v) => s.TlsKeyPath = v),
        Str("tls_cert_path", s => s.TlsCertPath, (s, v) => s.TlsCertPath = v),

        Int("max_send_queue_packets", s => s.MaxSendQueuePackets, (s, v) => s.MaxSendQueuePackets = v),
        Long("max_send_queue_bytes", s => s.MaxSendQueueBytes, (s, v) => s.MaxSendQueueBytes = v),
        Long("max_total_queued_bytes", s => s.MaxTotalQueuedBytes, (s, v) => s.MaxTotalQueuedBytes = v),
        Int("max_queue_delay_ms", s => s.MaxQueueDelayMs, (s, v) => s.MaxQueueDelayMs = v),
        Int("socket_send_buffer_bytes", s => s.SocketSendBufferBytes, (s, v) => s.SocketSendBufferBytes = v),
        Int("stuck_kick_ms", s => s.StuckKickMs, (s, v) => s.StuckKickMs = v),
        Long("max_control_backlog_bytes", s => s.MaxControlBacklogBytes, (s, v) => s.MaxControlBacklogBytes = v),

        Int("max_package_data_length", s => s.MaxPackageDataLength, (s, v) => s.MaxPackageDataLength = v),
        Int("max_payload_bytes", s => s.MaxPayloadBytes, (s, v) => s.MaxPayloadBytes = v),
        Int("registration_timeout_ms", s => s.RegistrationTimeoutMs, (s, v) => s.RegistrationTimeoutMs = v),
        Int("max_clients", s => s.MaxClients, (s, v) => s.MaxClients = v),
        Int("max_clients_per_ip", s => s.MaxClientsPerIp, (s, v) => s.MaxClientsPerIp = v),
        Int("heartbeat_seconds", s => s.HeartbeatSeconds, (s, v) => s.HeartbeatSeconds = v),
        Int("max_address_allocation_attempts", s => s.MaxAddressAllocationAttempts, (s, v) => s.MaxAddressAllocationAttempts = v),
        Int("receive_buffer_bytes", s => s.ReceiveBufferBytes, (s, v) => s.ReceiveBufferBytes = v),

        Bool("enforce_source_address", s => s.EnforceSourceAddress, (s, v) => s.EnforceSourceAddress = v),

        Int("icsp_port", s => s.IcspPort, (s, v) => s.IcspPort = v),
        StrArray("wires", s => s.Wires, (s, v) => s.Wires = v),
        Int("icsp_keepalive_interval_ms", s => s.IcspKeepAliveIntervalMs, (s, v) => s.IcspKeepAliveIntervalMs = v),
        Int("icsp_timeout_ms", s => s.IcspTimeoutMs, (s, v) => s.IcspTimeoutMs = v),
        Int("icsp_route_interval_ms", s => s.IcspRouteIntervalMs, (s, v) => s.IcspRouteIntervalMs = v),
        Long("icsp_route_ttl_ms", s => s.IcspRouteTtlMs, (s, v) => s.IcspRouteTtlMs = v),
        Int("icsp_reconnect_ms", s => s.IcspReconnectMs, (s, v) => s.IcspReconnectMs = v),
        Long("icsp_max_send_queue_bytes", s => s.IcspMaxSendQueueBytes, (s, v) => s.IcspMaxSendQueueBytes = v),
        StrMap("seckeys", s => s.SecKeys, (s, v) => s.SecKeys = v),
    ];

    // Missing keys keep the defaults from Settings. Comments and trailing commas are allowed.
    public static Settings Read(string path, string text)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(text, new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });
        }
        catch (JsonException e)
        {
            throw new ConfigException($"{path}: not valid JSON near line {e.LineNumber + 1}, position {e.BytePositionInLine + 1}");
        }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                throw new ConfigException($"{path}: must be a JSON object {{ ... }}");

            var s = new Settings();
            var errors = new List<string>();
            foreach (var property in doc.RootElement.EnumerateObject())
            {
                var field = Array.Find(Fields, f => f.Name == property.Name);
                if (field == null)
                {
                    errors.Add($"unknown key \"{property.Name}\" (typo?)");
                    continue;
                }
                try
                {
                    field.Read(s, property.Value, property.Name);
                }
                catch (ConfigException e)
                {
                    errors.Add(e.Message);
                }
            }
            if (errors.Count > 0) throw new ConfigException($"{path}:\n  " + string.Join("\n  ", errors));
            return s;
        }
    }

    public static string Write(Settings s)
    {
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        {
            w.WriteStartObject();
            foreach (var field in Fields) field.Write(s, w);
            w.WriteEndObject();
        }
        return System.Text.Encoding.UTF8.GetString(stream.ToArray()) + Environment.NewLine;
    }

    static Field Int(string name, Func<Settings, int> get, Action<Settings, int> set) => new(name,
        (s, v, key) => set(s, v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out int n) ? n
                              : throw new ConfigException($"\"{key}\" must be a whole number")),
        (s, w) => w.WriteNumber(name, get(s)));

    static Field Long(string name, Func<Settings, long> get, Action<Settings, long> set) => new(name,
        (s, v, key) => set(s, v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out long n) ? n
                              : throw new ConfigException($"\"{key}\" must be a whole number")),
        (s, w) => w.WriteNumber(name, get(s)));

    static Field Bool(string name, Func<Settings, bool> get, Action<Settings, bool> set) => new(name,
        (s, v, key) => set(s, v.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw new ConfigException($"\"{key}\" must be true or false"),
        }),
        (s, w) => w.WriteBoolean(name, get(s)));

    static Field StrArray(string name, Func<Settings, string[]> get, Action<Settings, string[]> set) => new(name,
        (s, v, key) => set(s, v.ValueKind == JsonValueKind.Array && v.EnumerateArray().All(e => e.ValueKind == JsonValueKind.String)
                              ? v.EnumerateArray().Select(e => e.GetString()!).ToArray()
                              : throw new ConfigException($"\"{key}\" must be an array of strings: [\"a\", \"b\"]")),
        (s, w) =>
        {
            w.WriteStartArray(name);
            foreach (string item in get(s)) w.WriteStringValue(item);
            w.WriteEndArray();
        });

    static Field StrMap(string name, Func<Settings, Dictionary<string, string>> get, Action<Settings, Dictionary<string, string>> set) => new(name,
        (s, v, key) => set(s, v.ValueKind == JsonValueKind.Object && v.EnumerateObject().All(p => p.Value.ValueKind == JsonValueKind.String)
                              ? v.EnumerateObject().GroupBy(p => p.Name).ToDictionary(g => g.Key, g => g.Last().Value.GetString()!)
                              : throw new ConfigException($"\"{key}\" must be an object of strings: {{\"a\": \"b\"}}")),
        (s, w) =>
        {
            w.WriteStartObject(name);
            foreach (var (k, v) in get(s)) w.WriteString(k, v);
            w.WriteEndObject();
        });

    // Puts generated keys into seckeys by editing the file's text, so comments and formatting stay.
    // Empty values are filled in, missing entries are added, a missing "seckeys" goes right after "wires".
    public static void StoreKeys(string path, List<(string Wire, string Hex)> keys)
    {
        byte[] file = File.ReadAllBytes(path);
        int bom = file.AsSpan().StartsWith("\uFEFF"u8) ? 3 : 0;
        string nl = file.AsSpan().IndexOf("\r\n"u8) >= 0 ? "\r\n" : "\n";
        static string Quote(string text) => "\"" + JsonEncodedText.Encode(text).ToString() + "\"";
        string Entries(IEnumerable<(string Wire, string Hex)> list) =>
            string.Join("," + nl, list.Select(k => $"    {Quote(k.Wire)}: {Quote(k.Hex)}"));

        var edits = new List<(int At, int Remove, string Text)>();
        var written = new HashSet<string>();
        bool hasSection = false;
        int wiresEnd = -1;
        var r = new Utf8JsonReader(file.AsSpan(bom), new JsonReaderOptions
        {
            CommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        });
        r.Read(); // {
        while (r.Read() && r.TokenType == JsonTokenType.PropertyName)
        {
            bool isKeys = r.ValueTextEquals("seckeys"u8);
            bool isWires = r.ValueTextEquals("wires"u8);
            r.Read();
            if (isKeys && r.TokenType == JsonTokenType.StartObject)
            {
                hasSection = true;
                int open = bom + (int)r.BytesConsumed; // right after '{'
                bool empty = true;
                while (r.Read() && r.TokenType == JsonTokenType.PropertyName)
                {
                    empty = false;
                    string name = r.GetString()!;
                    r.Read();
                    int i = keys.FindIndex(k => k.Wire == name);
                    if (i >= 0 && r.TokenType == JsonTokenType.String)
                    {
                        edits.Add((bom + (int)r.TokenStartIndex, (int)(r.BytesConsumed - r.TokenStartIndex), Quote(keys[i].Hex)));
                        written.Add(name);
                    }
                    r.Skip();
                }
                var missing = keys.Where(k => !written.Contains(k.Wire)).ToList();
                if (missing.Count > 0) edits.Add((open, 0, nl + Entries(missing) + (empty ? nl + "  " : ",")));
            }
            else
            {
                r.Skip();
                if (isWires) wiresEnd = bom + (int)r.BytesConsumed;
            }
        }
        if (!hasSection)
        {
            if (wiresEnd < 0) throw new InvalidDataException("no \"wires\" in the file");
            edits.Add((wiresEnd, 0, "," + nl + "  \"seckeys\": {" + nl + Entries(keys) + nl + "  }"));
        }

        var result = new List<byte>(file);
        foreach (var e in edits.OrderByDescending(e => e.At))
        {
            result.RemoveRange(e.At, e.Remove);
            result.InsertRange(e.At, System.Text.Encoding.UTF8.GetBytes(e.Text));
        }
        byte[] bytes = result.ToArray();

        // never write a file that wouldn't load back with these keys
        var check = Read(path, System.Text.Encoding.UTF8.GetString(bytes.AsSpan(bom)));
        if (keys.Any(k => !check.SecKeys.TryGetValue(k.Wire, out string? v) || v != k.Hex))
            throw new InvalidDataException("couldn't find where to put the keys in the file");
        File.WriteAllBytes(path, bytes); // in place: owner and permissions stay
    }

    static Field Str(string name, Func<Settings, string> get, Action<Settings, string> set) => new(name,
        (s, v, key) => set(s, v.ValueKind == JsonValueKind.String ? v.GetString()!
                              : throw new ConfigException($"\"{key}\" must be a string in quotes")),
        (s, w) => w.WriteString(name, get(s)));
}
