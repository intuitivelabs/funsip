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
# Run tests (integration tests cover REGISTER/auth, OPTIONS, INVITE,
# retransmission absorption, and the management API)
go test ./...

# Build
go build -o bin/funsip ./cmd/funsip
go build -o bin/funsipctl ./cmd/funsipctl
go build -o bin/funsiptop ./cmd/funsiptop

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
| `fixContact()` | Rewrite Contact header with the actual source IP:port (NAT traversal). |
| `processRegister()` | Save/remove registrations and send 200 OK with current bindings. |
| `sendResponse(code, reason)` | Send a SIP response to the current request. |
| `sendResponse(code, reason, headers)` | Same as above, plus extra response headers. `headers` is an object `{"X-Foo": "bar", "X-List": ["a", "b"]}` or an array of `"Name: value"` strings. |
| `appendHeader(name, value)` | Append a header to the current request (also propagates into anything proxied afterwards). Multiple calls add multiple values. |
| `removeHeader(name)` | Remove all instances of a header by name. Compact forms (e.g. `"v"` for `Via`, `"f"` for `From`) are accepted. |
| `lookup()` | Look up registered contacts for the Request-URI. Returns array of binding objects. |
| `lookup(uriString)` | Look up registered contacts for a specific URI. |
| `proxy(binding)` | Forward request to a registered contact (uses received IP:port). |
| `proxyTo(destination, transport)` | Forward request to a fixed destination (e.g. `"10.0.0.1:5060"`). |
| `log(...)` | Write to the server log. |

### Implicit SIP behaviour (NOT in the script)

The transaction layer handles these automatically — your routing script will not see them:

- **ACK retransmissions** are absorbed by the INVITE server transaction.
- **100 Trying** is generated for each INVITE server transaction.
- **CANCEL matching a pending INVITE** (RFC3261 §9.2): a 200 OK is sent for the CANCEL; CANCEL is forwarded on every INVITE branch still in `Calling` or `Proceeding` (i.e. that has not received a final response); a 487 Request Terminated is sent for the INVITE if no final response has been forwarded yet. Only orphan CANCELs (no matching INVITE) reach the routing script.
- **Retransmissions** of any kind are absorbed by the matching transaction.

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

    if (/^(INVITE|MESSAGE|CANCEL)$/.test(req.method)) {
        // CANCEL cannot carry meaningful credentials; skip auth for it.
        // (Note: a CANCEL that matches a pending INVITE never reaches the
        // script — the SIP stack handles it implicitly. This branch only
        // sees orphan CANCELs.)
        if (req.method !== "CANCEL" && req.from && req.from.host === DOMAIN) {
            if (!authenticate(DOMAIN)) return;
        }

        appendHeader("X-Routed-By", "funsip");
        removeHeader("Privacy");

        var contacts = lookup();
        if (contacts && contacts.length > 0) {
            proxy(contacts[0]);
        } else {
            sendResponse(404, "Not Found", {"X-Reason": "no registration"});
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
| `/status` | GET | Server status: uptime, version, build info, runtime, transaction/transport/processing stats |
| `/metrics` | GET | Same as `/status` (alias) |
| `/stats` | GET | Aggregate statistics |
| `/transactions` | GET | Active transaction list with state and age |
| `/registrations` | GET | All active registrations |
| `/logs` | GET | Ring buffer of recent log messages (last 1000) |
| `/script` | GET | Current routing script source |
| `/deploy` | POST | Validate, install, and activate a new routing script (request body = script source). Backs up the previous script for rollback. |
| `/rollback` | POST | Restore the most recently deployed-over script. |
| `/reload` | POST | Re-read routing script from disk |

The `/status` endpoint returns:

- `version`, `uptime`, `uptime_seconds`
- `build`: `vcs_revision`, `vcs_time`, `go_version`
- `runtime`: `goroutines`, `gomaxprocs`
- `transactions`: counts by side and INVITE/non-INVITE class
- `transport`: UDP/TCP message counters
- `processing`: requests received / forwarded / answered locally / retransmissions; responses by class (1xx-6xx); average processing delay (5 min and 1 hour windows); request rate (5 min and 1 hour windows)

## TUI: funsiptop

A curses-style monitor with four tabs:

```
funsiptop -api http://127.0.0.1:8080
```

| Tab | Key | Content |
|---|---|---|
| Stats | `1` / `F1` | Build, uptime, runtime, transactions, transport, processing metrics |
| Logs | `2` / `F2` | Ring buffer log messages, auto-scrolling |
| Registrations | `3` / `F3` | Active SIP registrations table |
| Deploy | `4` / `F4` | Edit the routing script in-place |

Other keys: `q` quit, `r` refresh, `Ctrl-D` deploy script, `Ctrl-R` rollback, `Ctrl-L` reload from server.

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
