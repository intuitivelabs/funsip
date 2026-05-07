package script

import (
	"sync"
	"time"
)

// limitOpts is the parsed form of the JS options object that
// callers pass to `limit(key, opts)`.
type limitOpts struct {
	Window    time.Duration
	MaxCount  int
	TTL       time.Duration
	Blacklist bool
}

// rateLimiter is a sliding-window rate limiter with two independent
// deny-until tables. Once a key's count crosses MaxCount inside
// Window the key is blacklisted for TTL — and if Blacklist is true,
// the originating source IP is blacklisted for the same TTL so that
// any subsequent request from that IP is denied irrespective of key.
//
// Memory bound: the per-key timestamp ring is capped at MaxCount
// entries. Once that many in-window hits have been recorded, the
// next hit would already exceed MaxCount — so the limiter denies
// without appending. The structure therefore does NOT grow with
// the number of per-key matches; it is bounded by MaxCount per key
// regardless of traffic.
//
//   - hits[key] is a slice of timestamps, len(hits[key]) <= MaxCount.
//   - keyDeny[key] / ipDeny[ip] hold "deny-until" timestamps; an
//     entry past its expiry is lazily evicted on the next access.
type rateLimiter struct {
	mu      sync.Mutex
	hits    map[string][]time.Time
	keyDeny map[string]time.Time
	ipDeny  map[string]time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		hits:    make(map[string][]time.Time),
		keyDeny: make(map[string]time.Time),
		ipDeny:  make(map[string]time.Time),
	}
}

// check records one request for key/ip and returns true if the
// request is allowed, false if it must be denied. A denial may come
// from:
//
//   1. The originating IP is currently blacklisted (set on a prior
//      key-violation when Blacklist:true was in effect).
//   2. The key itself is currently in deny-until (set on its own
//      prior overflow).
//   3. Adding this request would push the count strictly above
//      MaxCount within Window — in which case the request is
//      denied and the key (plus optionally the IP) is added to the
//      respective deny-until tables until now+TTL.
func (l *rateLimiter) check(key, ip string, opts limitOpts) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	if ip != "" {
		if t, ok := l.ipDeny[ip]; ok {
			if now.Before(t) {
				return false
			}
			delete(l.ipDeny, ip)
		}
	}
	if t, ok := l.keyDeny[key]; ok {
		if now.Before(t) {
			return false
		}
		delete(l.keyDeny, key)
		delete(l.hits, key)
	}

	cutoff := now.Add(-opts.Window)
	hits := l.hits[key]
	valid := hits[:0]
	for _, t := range hits {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= opts.MaxCount {
		// Already MaxCount in-window hits recorded. Adding this one
		// would exceed the cap. Deny — and don't grow the slice
		// any further (this is what bounds per-key memory).
		l.hits[key] = valid
		until := now.Add(opts.TTL)
		l.keyDeny[key] = until
		if opts.Blacklist && ip != "" {
			l.ipDeny[ip] = until
		}
		return false
	}

	valid = append(valid, now)
	l.hits[key] = valid
	return true
}
