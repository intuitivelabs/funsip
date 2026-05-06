# FunSIP

A transaction-stateful SIP proxy and registration server with a JavaScript routing engine.

Copyright © 2026 ipteles s.r.o. Licensed under the GNU General Public License v3.0 or later — see [LICENSE](LICENSE) and [COPYRIGHT](COPYRIGHT).

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

## Install

The fastest way — install the three binaries straight into `$GOBIN` (or `$GOPATH/bin`, or `~/go/bin`):

```bash
go install github.com/intuitivelabs/funsip/cmd/funsip@latest
go install github.com/intuitivelabs/funsip/cmd/funsipctl@latest
go install github.com/intuitivelabs/funsip/cmd/funsiptop@latest
```

Make sure that directory is on your `PATH` (e.g. `export PATH="$PATH:$(go env GOPATH)/bin"`).

You'll still want a routing script on disk — grab the example:

```bash
curl -O https://raw.githubusercontent.com/intuitivelabs/funsip/main/scripts/route.js
```

## Build from source

```bash
git clone https://github.com/intuitivelabs/funsip.git
cd funsip

# Run tests (cover REGISTER/auth, OPTIONS, INVITE, retransmission
# absorption, CANCEL, dialog/media lifecycle, RTCP modes, and more)
go test ./...

# Build the three binaries
go build -o bin/funsip    ./cmd/funsip
go build -o bin/funsipctl ./cmd/funsipctl
go build -o bin/funsiptop ./cmd/funsiptop
```

## First run

```bash
# Add a subscriber
funsipctl subscriber add alice localhost secret123

# Create config (or accept defaults)
cat > funsip.json <<'EOF'
{
  "listen_ip":   "0.0.0.0",
  "listen_port": 5060,
  "domain":      "example.com",
  "db_path":     "funsip.db",
  "script_path": "route.js",
  "http_ip":     "127.0.0.1",
  "http_port":   8080
}
EOF

# Edit the routing script — set DOMAIN to match your config
${EDITOR:-vi} route.js

# Start the server
funsip -config funsip.json
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
| `setupDialog({dlgGate: bool, pcap: bool, timeout: secs})` | Track this INVITE as a SIP dialog. The early dialog is created on the dialog-initiating INVITE (no To-tag) and confirmed when a 2xx response with a To-tag passes through. On BYE the dialog is torn down implicitly. Options: `dlgGate` (server-wide once enabled — in-dialog requests with no matching dialog are answered 481 and not forwarded); `pcap` (capture all signaling for this Call-ID into a per-dialog `.pcap` file in the configured directory; writes are batched on a separate goroutine and never block SIP/RTP); `timeout` in seconds (default 3660 — 61 min). When the timeout fires the stack acts as a back-to-back UA: a BYE is sent to each side and a separate counter is bumped. |
| `anchorMedia({symmetric, idleTimeout, pcap, wav, dtmf, qos})` | Anchor RTP/RTCP through this server. The SDP body of the current request is parsed and rewritten so that `c=` / `m=` / `a=rtcp` point at relay sockets allocated for this Call-ID. The answer SDP in the response is rewritten symmetrically when the response passes back through the proxy. With `symmetric:true` (default) packets are forwarded to wherever the peer is observed sending from (RTP latching, NAT-friendly); with `symmetric:false` packets are forwarded to the address advertised in the original SDP. The relay binds RTP/RTCP port pairs consecutively (rtcp = rtp+1), so all three RTCP signaling modes route correctly: `a=rtcp-mux` (RFC5761) is preserved verbatim; explicit `a=rtcp:port` (RFC3605) is rewritten to the relay's RTCP port; implicit (no `a=rtcp`, peer assumes rtp+1) needs no rewrite. Sockets are released on BYE, when the dialog times out (B2BUA path), and when no RTP has been observed for `idleTimeout` (default 120 s) — but only if neither side has signalled hold via `a=sendonly`, `a=inactive`, or `c=IN IP4 0.0.0.0`. **Optional analyzers (default off):** `pcap:true` writes every received RTP/RTCP datagram to a per-call `.pcap` file; `wav:true` decodes G.711 audio (PT 0 / 8) into one mono 16-bit-PCM `.wav` file per direction; `dtmf:true` parses RFC4733 named telephone events (auto-detected from `a=rtpmap` `telephone-event`) and runs the six quality checks listed below; `qos:true` tracks RTP packet loss and inter-arrival jitter (RFC3550 §A.8) and computes a simplified ITU E-model MoS. All analyzer file writes are batched on a separate goroutine and never block the SIP/RTP datapath. |
| `appendHeader(name, value)` | Append a header to the current request (also propagates into anything proxied afterwards). Multiple calls add multiple values. |
| `removeHeader(name)` | Remove all instances of a header by name. Compact forms (e.g. `"v"` for `Via`, `"f"` for `From`) are accepted. |
| `setRequestUri(uri)` | Rewrite the Request-URI. Argument is a URI string (`"sip:user@host:port"`) or a partial-update object (`{user: "...", host: "...", port: 5060}`). |
| `lookup()` | Look up registered contacts for the Request-URI. Returns array of binding objects. |
| `lookup(uriString)` | Look up registered contacts for a specific URI. |
| `proxy()` | Forward to the host:port encoded in the current Request-URI. The Request-URI itself is preserved verbatim. |
| `proxy(binding)` | Forward request to a registered contact (uses received IP:port). |
| `proxyTo(destination, transport)` | Forward request to a fixed destination (e.g. `"10.0.0.1:5060"`). |
| `proxy(..., {recordRoute: bool})` | All `proxy*` forms accept a trailing options object. `recordRoute` (default `true`) controls whether a `Record-Route` header with the `;lr` loose-routing parameter is added. Setting `false` suppresses Record-Route — useful for stateless edge proxies that do not need to stay in the signaling path of subsequent in-dialog requests. |
| `log(...)` | Write to the server log. |

### Implicit SIP behaviour (NOT in the script)

The transaction layer handles these automatically — your routing script will not see them:

- **ACK retransmissions** are absorbed by the INVITE server transaction.
- **100 Trying** is generated for each INVITE server transaction.
- **CANCEL matching a pending INVITE** (RFC3261 §9.2): a 200 OK is sent for the CANCEL; CANCEL is forwarded on every INVITE branch still in `Calling` or `Proceeding` (i.e. that has not received a final response); a 487 Request Terminated is sent for the INVITE if no final response has been forwarded yet. Only orphan CANCELs (no matching INVITE) reach the routing script.
- **Retransmissions** of any kind are absorbed by the matching transaction.
- **Max-Forwards loop guard**: if a received request has no `Max-Forwards` header, the stack inserts `Max-Forwards: 70`. On forward, the value is decremented by one; if it would go below zero, the forward is refused with `483 Too Many Hops`.
- **rport / received** (RFC3261 §18.2.1, RFC3581): on receive, the topmost Via header is updated in place — `received=` is added if the source IP differs from the sent-by host, and `rport=` is filled in with the actual source port if the parameter was present without a value.
- **TCP connection reuse**: every accepted and every dialed TCP connection is kept open, registered in an alias table keyed by peer `host:port`, and reused for subsequent sends. SO_KEEPALIVE is enabled. If a cached connection's write fails (peer reset, half-close, network drop), the entry is removed and the send transparently re-dials a fresh connection. Concurrent sends to the same destination are serialized through a per-destination lock so only one socket is ever opened. The current alias-table size is reported as `transport.tcp_connections` in `/status`.
- **Script execution timeout** (`script_timeout_ms`, default 3000): if the JavaScript routing script runs longer than this, a goja `Interrupt` aborts it. The server answers the transaction with `408 Request Timeout` and, for INVITE, fans CANCEL out to every upstream branch the script had already created via `proxy()` / `proxyTo()`.
- **INVITE transaction timeout** (`invite_timeout_ms`, default 180000 — 3 min): an additional wall-clock cap on INVITE server transactions that have not sent a final response yet. RFC3261's IST state machine alone does not bound a stalled-upstream IST in `Proceeding`. On expiry the UAC is answered `408 Request Timeout` and CANCEL is sent to every pending upstream branch. Non-INVITE transactions are bounded by the standard RFC3261 timer (Timer F = 32 s).

## Events

When `events_url` is configured (e.g. `"events_url": "http://collector.example.com/_bulk"` in `funsip.json`), the stack POSTs one JSON event per situation to that URL. Emission is fully asynchronous — events are dropped onto a bounded channel and a single worker goroutine drains it; if the channel overflows the event is dropped and a counter is bumped. The SIP / RTP hot path never blocks on disk or network I/O.

| `type2` | When |
|---|---|
| `auth-failed` | A SIP transaction completed with a final `401` or `407` response |
| `call-attempt` | An INVITE transaction completed with a final response `>=300` (other than `401`/`407`) |
| `call-start` | An INVITE transaction completed with a final `2xx` response |
| `call-end` | A tracked dialog ended via BYE (`originator: caller-terminated`/`callee-terminated`) or timed out (`originator: timeout`) |
| `reg-new` | A REGISTER stored a new (or refreshed) binding |
| `reg-del` | A REGISTER with `Expires: 0` (or `Contact: *`) removed a binding |
| `reg-expired` | The registrar's expiry sweeper removed a binding whose `expires_at` had elapsed |

Each event has the shape

```json
{
  "@timestamp": "2026-05-06T12:34:56.789Z",
  "type": "event",
  "type2": "call-start",
  "attrs": { "type": "call-start", "method": "INVITE", "call-id": "...", "from": "...", "to": "...", "r-uri": "...", "source": "1.2.3.4", "src-port": 54321, "transport": "udp", "sip-code": 200, "reason": "OK", ... },
  "client": { "ip": "1.2.3.4", "port": 54321, "transport": "udp" },
  "sip": { "call_id": "...", "from": "...", "fromtag": "...", "to": "...", "totag": "...", "request": { "method": "INVITE" }, "response": { "status": 200 }, "sip_reason": "OK" }
}
```

`call-end` additionally carries `attrs.duration` (seconds), `event.duration`, and `sip.originator`. When `anchorMedia` analyzers were active, `event.media` carries:

- `dtmf` — array of detected RFC4733 telephone events. Each entry has `digit`, `duration_ms`, `volume_dbm0`, `packet_count`, `end_packets`, `had_end`, plus arrays of `errors` and `warnings`. Quality checks applied per event:

  | # | Check | Threshold | Severity |
  |---|---|---|---|
  | 1 | Duration too short | `< 40 ms` = error, `< 80 ms` = warn | error/warn |
  | 2 | Excessive duration (stuck key/signaling) | `> 1000 ms` | warn |
  | 3 | Missing end flag | end bit absent | error |
  | 4 | Low packet redundancy | `< 3` end packets | warn |
  | 5 | Low volume | attenuation `> 36` dBm0 | warn |
  | 6 | Short inter-digit gap | `< 40 ms` (ITU-T Q.24) | warn |

- `qos` — `packets_received`, `packets_lost`, `loss_percent`, `jitter_ms`, `mos` (ITU E-model, simplified: `R0=93.2`, `Ie≈30·loss%`, MoS clamped to [1, 4.5]).
- `wav` — array of file paths (one per direction).
- `pcap` — path to the per-call media pcap file.
- **Dialog cleanup on BYE**: if the script enabled dialog tracking via `setupDialog`, an in-dialog BYE matching a known dialog tears down the dialog state (cancels the timeout timer, closes the per-dialog PCAP file) before the BYE is forwarded.
- **Dialog timeout B2BUA**: if no BYE arrives within the configured timeout (default 61 min), the stack sends a BYE to each side of the call (Caller→Callee and Callee→Caller, each with its own From/To and a CSeq high enough to outrank in-dialog use), increments the `dialogs.timed_out` counter, and removes the dialog state.

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
