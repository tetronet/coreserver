# CoreServer

CoreServer is the core server of a Tetronet network. Devices (modems, address machines) connect to it over
WebSocket and get an address, and it routes packets between them. Core servers also link to each other
over **ICSP**, an encrypted binary protocol over TCP, so packets can travel between networks.

Community: [t.me/TetronetCommunications](https://t.me/TetronetCommunications)

## Features

- **WebSocket server** (`ws://`, or `wss://` with its own TLS) on ASP.NET Core / Kestrel. TLS certificates
  reload on `SIGHUP` without dropping connections.
- **Address allocation**: the server has a fixed network address (for example `7`), and connected devices get
  addresses inside it (`7-850`).
- **Anti-spoofing**: a client can't send packets with someone else's source address, and packets arriving
  from other networks that claim to come from ours are dropped.
- **Links between core servers (ICSP)** with a routing table that updates itself. Routes appear and
  disappear as links go up and down (with split horizon), and the hop count (`max_hops`) is limited.
- **Encryption of the wires (CableEncryption v1.5)**: everything between core servers is AES-256-GCM
  with pre-shared keys. There's no handshake and no plaintext headers, so the TCP stream looks like random
  bytes. Small packets get random padding, keep-alives go out at random intervals, and replayed connections
  are refused.
- **Overload protection**: each connection has a bounded send queue. When it's full, new packets are
  dropped (tail drop), packets that wait too long are dropped too, and connections that are stuck get
  disconnected. There's a hard limit on total queue memory and limits on clients, clients per IP, message
  size and registration time.
- **Built for a small VPS**: the code never blocks, buffers are pooled, small messages are sent in batches,
  and it runs comfortably on 1 CPU core. Native AOT is supported.
- **No logs by default**: debug logging is compiled out unless you turn it on yourself.

## Protocol in brief

Every WebSocket message is a JSON array: `["event", data]` or `["event"]`.

- On connect the server asks the device for its type and address (`get-device-type`, `get-addr`) and
  confirms the address with `addr-ok`, or refuses with `?invalid-addr`, `?invalid-device-type` or
  `?no-free-addr`.
- Data goes as `["data-transmission", { "package_info": {...}, "package_data": "<base64>", ... }]`.
  `package_info.from` must belong to the sender. If it's missing, the server fills it in.
- A packet without `max_hops` never leaves the local network. With `max_hops` it can go to other core servers
  over ICSP, and each hop decrements the value.

The ICSP specification is in `ICSP.odt`.

## Build and run

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download) to build. The server needs the
ASP.NET Core 10 runtime (`aspnetcore-runtime-10.0`), or nothing if you build it self-contained.

```bash
dotnet publish -c Release -o /opt/coreserver
/opt/coreserver/CoreServer
```

Self-contained (no runtime needed on the server):

```bash
dotnet publish -c Release -r linux-x64 --self-contained -o /opt/coreserver
```

Native AOT (smaller memory use and instant start; build on Linux with `clang` installed):

```bash
dotnet publish -c Release -r linux-x64 -p:PublishAot=true -o /opt/coreserver
```

Local test without TLS:

```bash
CORESERVER_TLS=0 dotnet run -c Release
```

### systemd

```ini
[Service]
Environment=DOTNET_SYSTEM_NET_SOCKETS_INLINE_COMPLETIONS=1
ExecStart=/opt/coreserver/CoreServer
Restart=always
```

`DOTNET_SYSTEM_NET_SOCKETS_INLINE_COMPLETIONS=1` keeps socket work on the epoll thread. On a 1-core VPS this
roughly halves CPU load.

After a certificate renewal, run `kill -HUP <pid>`.

## Configuration

All settings are in `config.json`. The server looks for it in this order:

1. `CoreServer --config /path/to/config.json`
2. the `CORESERVER_CONFIG` environment variable
3. next to the executable. If it isn't there, it's created with default values and comments.

Comments and trailing commas are allowed. A missing key keeps its default. An unknown key (a typo) stops the
server with an error.

The main settings:

| Key | Default | Meaning |
|---|---|---|
| `local_address` | | address of this network, digits only (a single block if you use ICSP) |
| `smla_length` | `3` | how many digits are generated for client addresses (1..7) |
| `port` | `3000` | WebSocket port |
| `use_tls`, `tls_key_path`, `tls_cert_path` | | `wss://` directly, or `false` behind a reverse proxy that handles TLS |
| `max_clients`, `max_clients_per_ip` | `2000`, `50` | connection limits (raise the per-IP limit behind a proxy) |
| `enforce_source_address` | `true` | anti-spoofing of `package_info.from` |
| `wires` | `[]` | other core servers to link with: `"host:port"` or `"host"` (port 6336) |
| `icsp_port` | `6336` | port where other core servers connect to us (`0` means only dial out) |
| `seckeys` | | wire encryption keys, see below |

Every other setting (queues, timeouts, ICSP intervals) is described in the comments of the generated
`config.json`.

## Linking two core servers

Both servers list each other in `wires`. Only hosts listed in `wires` may connect to `icsp_port`. If both
sides dial, one connection is kept. Example for servers `a.example.org` (network `7`) and `b.example.org`
(network `12`):

```jsonc
// on a.example.org
"local_address": "7",
"wires": ["b.example.org"],
"seckeys": { "b.example.org": "" }
```

```jsonc
// on b.example.org
"local_address": "12",
"wires": ["a.example.org"],
"seckeys": { "a.example.org": "<the same 64 hex digits as on a>" }
```

Each server stores the key under **its own name for the wire**, exactly as written in its `wires`.
The key must be the same on both sides.

## Exchanging encryption keys

A wire key is 32 bytes written as 64 hex digits. Anyone who has it can read and forge everything on that wire,
so treat it like a password.

### Getting a key

- Leave the key empty (`""`) and start the server. It generates a random key and writes it into
  `config.json`. It's never printed to the console or the log.
- Or generate one yourself: `openssl rand -hex 32`.

Only **one** side creates the key and sends it to the other.

### How to send it

Use only end-to-end encrypted channels, where nobody in between (including the service itself) can read the
message:

- **Signal**: the best option. Turn on disappearing messages in the chat before you send.
- **Telegram Secret Chat** (a "secret chat", not a regular one): set a self-destruct timer.
  Regular Telegram chats, groups and Saved Messages are stored on Telegram's servers and **are not** end-to-end
  encrypted, so don't use them.
- **In person**: on paper, or as a QR code shown from screen to screen (`qrencode -t ANSI <key>`).
- **Other E2E options**: Matrix/Element in an encrypted room, a PGP/age-encrypted file, SimpleX, Session.

Don't send keys by email, in regular chats (Telegram, Discord, VK, WhatsApp groups), in the Telegram group of
the project, or as screenshots that end up in a cloud photo gallery.

### Check that it arrived intact

After sending, compare part of the key over a **different** channel. For example, read the first and last 8
digits to each other on a voice call. If they match, nobody swapped the key on the way.

### After the exchange

- Delete the message with the key from both devices, if the timer hasn't done it already.
- Make `config.json` readable only by the server's user: `chmod 600 config.json`. The server warns if
  other users can read it.
- If a key may have leaked, replace it with a new one on both sides right away. There is no forward secrecy:
  with the key, someone who recorded old traffic on the wire can decrypt it too.

## Debug logging

Uncomment the `DEBUG_LOG` line in `CoreServer.csproj`. When it's off, debug logging is compiled away
entirely.

**Be fair.** Debug mode logs are for debugging only. Don't keep them running in production, and don't collect
or store users' data with them.

## License

BSD 3-Clause with the Commons Clause, see [`LICENSE`](LICENSE).

You may use CoreServer for free, including inside a commercial company (for example, so the staff of a pickup
point can stay in touch with their families), and you may give anyone free access to Tetronet through it.
You may **not** sell access to Tetronet or anything else whose value comes mainly from CoreServer, make money
from it through ads or user data, or inspect, store or sell the data it relays.
