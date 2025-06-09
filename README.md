🧦 cesium-socks
============

**cesium-socks** is a SOCKS5-over-DNS tunnel written in Go. It lets clients proxy TCP traffic through a DNS tunnel to bypass network restrictions or censorship. It uses the [cesiumlib](https://github.com/TransIRC/cesiumlib) for DNS encapsulation and `go-socks5` for SOCKS5 handling.

* * * * *

✨ Features
----------

-   Tunnels SOCKS5 traffic using DNS queries

-   Client/server design with symmetric shared-password authentication

-   Simple `.conf`-file-based configuration

-   Lightweight and dependency-minimal

-   Built-in SOCKS5 proxy on the client side (hardcoded to `127.0.0.1:1080`)

* * * * *

🔧 Configuration
----------------

cesium-socks uses a key-value config file (e.g. `client.conf` or `server.conf`). Lines starting with `#` are comments.

### Supported Keys

| Key | Description | Required | Used In |
| --- | --- | --- | --- |
| `listen_addr` | Address to bind (server DNS listener or client-side DNS socket) | ✅ | Both |
| `listen_port` | Port to bind (DNS server, or DNS client port) | ✅ | Both |
| `tunnel_domain` | The domain to use for the DNS tunnel (must be delegated to the server) | ✅ | Both |
| `password` | Shared secret to authenticate/encrypt tunnel traffic | ✅ | Both |
| `tunnel_ip` | **Client only** --- IP of the DNS tunnel server | ✅ | Client |

* * * * *

🖥️ Example Configs
-------------------

### `client.conf`

```
# Local DNS client setup
listen_addr = 127.0.0.1
listen_port = 5353 (use a DNS port like 53 or 5353 preferably)
tunnel_domain = t.example.com
password = mysecret
tunnel_ip = 1.2.3.4

```

-   Client opens a SOCKS5 proxy on `127.0.0.1:1080` (hardcoded)

-   All traffic is tunneled to `1.2.3.4` over DNS queries to `t.example.com`

### `server.conf`

```
# Server-side DNS tunnel
listen_addr = 0.0.0.0
listen_port = 53
tunnel_domain = t.example.com
password = mysecret

```

-   Server listens on UDP port 53

-   Responds to DNS queries for `t.example.com`

Make sure to delegate your domain subdomain correctly in DNS:

```
tunnel.example.com. IN A 1.2.3.4

```

* * * * *

🚀 Running
----------

### Server

```
sudo ./cesium-socks -server -config server.conf

```

-   Requires `sudo` or proper capabilities to bind to port 53

-   Starts the DNS tunnel server

### Client

```
./cesium-socks -config client.conf

```

-   Starts a local SOCKS5 proxy on `127.0.0.1:1080`

-   Tunnels outbound TCP traffic via DNS queries to the configured server

* * * * *

🧪 Testing
----------

After running the client:

1.  Configure a SOCKS5-compatible app (browser, curl, etc.) to use `127.0.0.1:1080` as proxy.

2.  Try accessing an external site. The traffic should flow over DNS.


⚠️ Limitations
--------------

-   SOCKS5 port is hardcoded to `127.0.0.1:1080`

-   DNS tunneling is not suitable for high-throughput applications (e.g. video streaming)

-   No support for UDP connections
