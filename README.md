# FunSIP

A transaction-stateful SIP proxy and registration server with a JavaScript routing engine.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    route.js                         │
│              (JavaScript routing)                    │
├──────────┬──────────┬────────────┬──────────────────┤
│ auth     │ registrar│   proxy    │  location DB     │
│ (digest) │ (REGISTER│ (stateful  │  (SQLite)        │
│          │  handler)│  forward)  │                  │
├──────────┴──────────┴────────────┴──────────────────┤
│              Transaction Layer                       │
│    ICT / NICT / IST / NIST  (RFC3261 §17)           │
├─────────────────────────────────────────────────────┤
│              Transport Layer                         │
│           UDP + TCP (IPv4)                           │
└─────────────────────────────────────────────────────┘
```

## Features

- **RFC3261 transaction state machines** — all four (ICT, NICT, IST, NIST) with proper timers
- **JavaScript routing engine** — full JS with regex, conditionals, hot-reload via SIGHUP or HTTP API
- **Registrar** — persistent SIP bindings in SQLite, contact rewriting for NAT
- **Digest authentication** — RFC2617, credentials in SQLite
- **Stateful proxy** — Via insertion, Record-Route, Max-Forwards, credential stripping, in-dialog routing
- **Retransmission handling** — absorbed by server transactions per RFC3261
- **100 Trying** — auto-generated for INVITE server transactions
- **UDP + TCP transport** — IPv4
- **HTTP/JSON management API** — status, transactions, stats, logs (ring buffer), hot reload
- **CLI tool** — subscriber/location database management, server status queries

## Quick Start

```bash
# Build
go build -o bin/funsip ./cmd/funsip
go build -o bin/funsipctl ./cmd/funsipctl

# Add a subscriber
./bin/funsipctl subscriber add alice localhost secret123

# Create config (or use defaults)
cat > funsip.json <<EOF
{
  "listen_ip": "0.0.0.0",
  "listen_port": 5060,
  "domain": "example.com",
  "db_path": "funsip.db",
  "script_path": "route.js",
  "http_ip": "127.0.0.1",
  "http_port": 8080
}
EOF

# Copy and edit the routing script
cp scripts/route.js route.js
# Edit route.js — set DOMAIN to match your config

# Start the server
./bin/funsip -config funsip.json
```

## Routing Script

The routing script is JavaScript executed for each out-of-dialog or dialog-initiating SIP request. In-dialog requests (with a To-tag) are automatically routed using Route headers per RFC3261 §16.

### Available functions

| Function | Description |
|---|---|
| `authenticate(realm)` | Challenge/verify digest credentials. Returns `true` if authenticated, sends 401/407 challenge and returns `false` otherwise. |
| `fixContact(req)` | Rewrite Contact header with the actual source IP:port (NAT traversal). |
| `processRegister(req)` | Save/remove registrations and send 200 OK with current bindings. |
| `sendResponse(code, reason)` | Send a SIP response to the current request. |
| `lookup()` | Look up registered contacts for the Request-URI. Returns array of binding objects. |
| `lookup(uriString)` | Look up registered contacts for a specific URI. |
| `proxy(binding)` | Forward request to a registered contact (uses received IP:port). |
| `proxyTo(destination, transport)` | Forward request to a fixed destination (e.g. `"10.0.0.1:5060"`). |
| `log(...)` | Write to the server log. |

### Request object properties

```javascript
req.method           // "INVITE", "REGISTER", etc.
req.requestUri.user  // user part of Request-URI
req.requestUri.host  // host part of Request-URI
req.requestUri.full  // full Request-URI string
req.from.user        // From header user
req.from.host        // From header host
req.from.tag         // From tag
req.to.user          // To header user
req.to.host          // To header host
req.callId           // Call-ID
req.sourceIp         // actual source IP
req.sourcePort       // actual source port
req.transport        // "UDP" or "TCP"
req.getHeader(name)  // get any header value
req.getHeaders(name) // get all values for a multi-value header
```

### Example script

```javascript
var DOMAIN = "example.com";

function onRequest(req) {
    if (req.method === "REGISTER") {
        if (!authenticate(DOMAIN)) return;
        fixContact();
        processRegister();
        return;
    }

    if (/^(INVITE|MESSAGE)$/.test(req.method)) {
        if (req.from && req.from.host === DOMAIN) {
            if (!authenticate(DOMAIN)) return;
        }

        var contacts = lookup();
        if (contacts && contacts.length > 0) {
            proxy(contacts[0]);
        } else {
            sendResponse(404, "Not Found");
        }
        return;
    }

    sendResponse(405, "Method Not Allowed");
}
```

## CLI Reference

```
funsipctl subscriber list [domain]
funsipctl subscriber add <user> <domain> <password>
funsipctl subscriber delete <user> <domain>

funsipctl location list
funsipctl location delete <aor>
funsipctl location purge

funsipctl status              # server status (via HTTP API)
funsipctl stats               # server statistics
funsipctl transactions        # active transactions
funsipctl registrations       # active registrations
funsipctl logs                # recent log messages
funsipctl reload              # hot-reload routing script
```

Use `-db path` to specify database path (default: `funsip.db`).
Use `-api url` to specify management API URL (default: `http://127.0.0.1:8080`).

## Management API

| Endpoint | Method | Description |
|---|---|---|
| `/status` | GET | Server status, uptime, version, transaction/transport stats |
| `/stats` | GET | Aggregate statistics |
| `/transactions` | GET | Active transaction list with state and age |
| `/registrations` | GET | All active registrations |
| `/logs` | GET | Ring buffer of recent log messages (last 1000) |
| `/reload` | POST | Hot-reload the routing script |

## What the transaction layer handles automatically

- Retransmission absorption (server transactions)
- Retransmission generation (client transactions, UDP only)
- 100 Trying generation for INVITE server transactions
- ACK generation for non-2xx responses (INVITE client transactions)
- Timer-based state transitions per RFC3261 §17
- Transaction matching via Via branch parameter

## Future extensions

- SDP/RTP relay and recording
- Alternative databases (PostgreSQL, MySQL)
- URI canonicalization via database lookup
- Blacklists and call forwarding
- Dialog state tracking
- Alternative destination retry on failure
- Event generation (call-start, call-end, registration, auth-failure)
- PCAP recording
- TLS transport
- Go-based routing scripts (yaegi)
