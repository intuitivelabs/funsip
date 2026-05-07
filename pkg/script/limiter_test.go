package script

import (
	"testing"
	"time"
)

func TestLimiterAllowsUpToMaxCount(t *testing.T) {
	l := newRateLimiter()
	opts := limitOpts{Window: time.Hour, MaxCount: 5, TTL: 2 * time.Hour}
	for i := 0; i < 5; i++ {
		if !l.check("key", "1.2.3.4", opts) {
			t.Errorf("hit %d: want allow, got deny", i+1)
		}
	}
}

func TestLimiterDeniesAfterMaxCount(t *testing.T) {
	l := newRateLimiter()
	opts := limitOpts{Window: time.Hour, MaxCount: 5, TTL: 2 * time.Hour}
	for i := 0; i < 5; i++ {
		l.check("key", "1.2.3.4", opts)
	}
	if l.check("key", "1.2.3.4", opts) {
		t.Error("6th hit: want deny, got allow")
	}
	// All further hits in TTL window: deny.
	for i := 0; i < 3; i++ {
		if l.check("key", "1.2.3.4", opts) {
			t.Errorf("hit during deny-TTL %d: want deny, got allow", i)
		}
	}
}

func TestLimiterPerKeyMemoryIsBounded(t *testing.T) {
	l := newRateLimiter()
	opts := limitOpts{Window: time.Hour, MaxCount: 5, TTL: 2 * time.Hour}
	// Drive 10 000 hits into a single key — the slice must never
	// grow past MaxCount.
	for i := 0; i < 10_000; i++ {
		l.check("hot-key", "1.2.3.4", opts)
	}
	l.mu.Lock()
	got := len(l.hits["hot-key"])
	l.mu.Unlock()
	if got > opts.MaxCount {
		t.Errorf("per-key slice grew to %d entries, must be <= MaxCount (%d)", got, opts.MaxCount)
	}
}

func TestLimiterBlacklistOptionAffectsOtherKeys(t *testing.T) {
	l := newRateLimiter()
	opts := limitOpts{Window: time.Hour, MaxCount: 2, TTL: time.Hour, Blacklist: true}
	ip := "9.9.9.9"

	// Trip the limit on key "A".
	l.check("A", ip, opts)
	l.check("A", ip, opts)
	if l.check("A", ip, opts) {
		t.Fatal("third hit should have been denied")
	}

	// A request from the same IP for an UNRELATED key should also
	// be denied because Blacklist:true added the IP to ipDeny.
	if l.check("B", ip, opts) {
		t.Error("blacklisted IP should be denied even for a different key")
	}
}

func TestLimiterBlacklistOffDoesNotPropagate(t *testing.T) {
	l := newRateLimiter()
	opts := limitOpts{Window: time.Hour, MaxCount: 2, TTL: time.Hour /* Blacklist:false */}
	ip := "9.9.9.9"

	l.check("A", ip, opts)
	l.check("A", ip, opts)
	if l.check("A", ip, opts) {
		t.Fatal("third hit should have been denied")
	}
	// Without Blacklist, a different key from the same IP must
	// still be allowed.
	if !l.check("B", ip, opts) {
		t.Error("non-blacklisted limit must not affect other keys from same IP")
	}
}

func TestLimiterDifferentIPsDoNotShare(t *testing.T) {
	l := newRateLimiter()
	opts := limitOpts{Window: time.Hour, MaxCount: 2, TTL: time.Hour, Blacklist: true}

	// Trip 1.1.1.1 — IP gets blacklisted.
	l.check("X", "1.1.1.1", opts)
	l.check("X", "1.1.1.1", opts)
	l.check("X", "1.1.1.1", opts) // denied + blacklist

	// Different IP, same key: the key itself is denied (its own
	// keyDeny is set), but a fresh key from a fresh IP must be
	// allowed.
	if !l.check("Y", "2.2.2.2", opts) {
		t.Error("fresh key from a fresh IP must be allowed")
	}
}
