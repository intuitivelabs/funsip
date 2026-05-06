package media

import (
	"sync"
	"time"

	"github.com/intuitivelabs/funsip/pkg/rtp"
)

// AnalyzerReport is what the dialog manager attaches to a call-end
// event when any of the analyzer's options were enabled.
type AnalyzerReport struct {
	DTMF []DTMFReport `json:"dtmf,omitempty"`
	QoS  *QoSReport   `json:"qos,omitempty"`
	WAV  []string     `json:"wav,omitempty"`
	PCAP string       `json:"pcap,omitempty"`
}

// DTMFReport is one detected RFC4733 telephone-event with the six
// quality checks the user asked for. Errors are hard problems
// (event missing the end bit, duration < 40 ms); warnings are
// suspicious but recoverable patterns. Severities follow the user's
// table in the task statement.
type DTMFReport struct {
	Digit       string   `json:"digit"`
	DurationMs  int      `json:"duration_ms"`
	VolumeDBm0  int      `json:"volume_dbm0"`
	PacketCount int      `json:"packet_count"`
	EndPackets  int      `json:"end_packets"`
	HadEnd      bool     `json:"had_end"`
	Warnings    []string `json:"warnings,omitempty"`
	Errors      []string `json:"errors,omitempty"`
}

// QoSReport summarizes per-direction RTP quality plus a simplified
// E-model MoS. One report per RTP stream direction (A→B and B→A).
type QoSReport struct {
	PacketsReceived uint64  `json:"packets_received"`
	PacketsLost     uint64  `json:"packets_lost"`
	LossPercent     float64 `json:"loss_percent"`
	JitterMs        float64 `json:"jitter_ms"`
	MoS             float64 `json:"mos"`
}

// dtmfTracker observes one direction of RTP and groups packets that
// share an RTP timestamp into a single telephone event (RFC4733
// §2.5.1). At end-of-event (timestamp changes, or the analyzer is
// flushed at call-end) it emits a DTMFReport with all six checks
// applied.
type dtmfTracker struct {
	mu        sync.Mutex
	eventPT   uint8
	rate      uint32 // RTP clock rate, typically 8000
	digits    []DTMFReport
	lastEndAt time.Time

	hasActive    bool
	activeTS     uint32
	activeDigit  uint8
	activeMaxDur uint16
	activeMaxVol uint8 // worst (highest) attenuation seen
	activePkts   int
	activeEnds   int
	activeSeenE  bool
	activeStart  time.Time
}

func newDTMFTracker(eventPT uint8, rate uint32) *dtmfTracker {
	if rate == 0 {
		rate = 8000
	}
	return &dtmfTracker{eventPT: eventPT, rate: rate}
}

// Observe is called from the relay loop for every received RTP
// packet on this direction. Non-DTMF payload types are ignored.
func (t *dtmfTracker) Observe(h *rtp.Header, payload []byte) {
	if t == nil || h == nil || h.PayloadType != t.eventPT {
		return
	}
	ev := rtp.ParseTelephoneEvent(payload)
	if ev == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.hasActive || h.Timestamp != t.activeTS {
		if t.hasActive {
			t.closeActiveLocked()
		}
		t.hasActive = true
		t.activeTS = h.Timestamp
		t.activeDigit = ev.Event
		t.activeMaxDur = ev.Duration
		t.activeMaxVol = ev.Volume
		t.activePkts = 1
		t.activeEnds = 0
		t.activeSeenE = false
		t.activeStart = time.Now()
		if ev.EndBit {
			t.activeEnds = 1
			t.activeSeenE = true
		}
		return
	}

	t.activePkts++
	if ev.Duration > t.activeMaxDur {
		t.activeMaxDur = ev.Duration
	}
	if ev.Volume > t.activeMaxVol {
		t.activeMaxVol = ev.Volume
	}
	if ev.EndBit {
		t.activeEnds++
		t.activeSeenE = true
	}
}

// Flush closes any pending event and returns the accumulated
// reports. The tracker is reset so a future call returns just new
// digits.
func (t *dtmfTracker) Flush() []DTMFReport {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.hasActive {
		t.closeActiveLocked()
	}
	out := t.digits
	t.digits = nil
	return out
}

func (t *dtmfTracker) closeActiveLocked() {
	durationMs := int(uint64(t.activeMaxDur) * 1000 / uint64(t.rate))

	rep := DTMFReport{
		Digit:       rtp.EventDigit(t.activeDigit),
		DurationMs:  durationMs,
		VolumeDBm0:  int(t.activeMaxVol),
		PacketCount: t.activePkts,
		EndPackets:  t.activeEnds,
		HadEnd:      t.activeSeenE,
	}

	// Quality checks per the user's table:
	//
	// 1. Duration too short:  < 40 ms = error, < 80 ms = warn
	// 2. Excessive duration:  > 1000 ms = warn (stuck key/signaling)
	// 3. Missing end flag:    end bit absent = error
	// 4. Low redundancy:      < 3 end packets = warn
	// 5. Low volume:          attenuation > 36 dBm0 = warn
	// 6. Short inter-digit:   gap < 40 ms = warn
	switch {
	case durationMs < 40:
		rep.Errors = append(rep.Errors, "duration_too_short")
	case durationMs < 80:
		rep.Warnings = append(rep.Warnings, "duration_short")
	}
	if durationMs > 1000 {
		rep.Warnings = append(rep.Warnings, "excessive_duration")
	}
	if !t.activeSeenE {
		rep.Errors = append(rep.Errors, "missing_end_flag")
	}
	if t.activeEnds < 3 {
		rep.Warnings = append(rep.Warnings, "low_redundancy")
	}
	if t.activeMaxVol > 36 {
		rep.Warnings = append(rep.Warnings, "low_volume")
	}
	if !t.lastEndAt.IsZero() {
		if t.activeStart.Sub(t.lastEndAt) < 40*time.Millisecond {
			rep.Warnings = append(rep.Warnings, "short_inter_digit_gap")
		}
	}

	t.digits = append(t.digits, rep)
	t.lastEndAt = time.Now()
	t.hasActive = false
}

// qosTracker computes RFC3550-style packet loss and jitter for one
// RTP stream direction, and converts them to a simplified ITU
// E-model MoS estimate.
type qosTracker struct {
	mu sync.Mutex

	rate uint32

	received      uint64
	lost          int64
	highestSeq    uint32 // sequence with rollover counted
	firstSeq      bool
	lastTransit   int64
	jitter        float64 // RTP-clock units
}

func newQoSTracker(rate uint32) *qosTracker {
	if rate == 0 {
		rate = 8000
	}
	return &qosTracker{rate: rate}
}

// Observe accounts for one received RTP packet.
func (q *qosTracker) Observe(h *rtp.Header, arrival time.Time) {
	if q == nil || h == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	q.received++
	seq := uint32(h.Sequence)
	if !q.firstSeq {
		q.firstSeq = true
		q.highestSeq = seq
	} else {
		// Reconstruct 32-bit "extended" sequence, accounting for
		// 16-bit rollover. Diff > 32768 means we wrapped.
		prev := q.highestSeq
		diff := int32(seq) - int32(prev&0xFFFF)
		if diff < -32768 {
			diff += 65536
		} else if diff > 32768 {
			diff -= 65536
		}
		newHi := int64(prev) + int64(diff)
		if newHi > int64(prev) {
			// New highest. Anything between prev+1 and newHi-1 was
			// lost (or out of order).
			q.lost += newHi - int64(prev) - 1
			q.highestSeq = uint32(newHi)
		}
	}

	// Inter-arrival jitter (RFC3550 A.8). transit = arrival-
	// timestamp; J = J + (|D(i-1, i)| - J)/16.
	arrivalTS := uint32(uint64(arrival.UnixNano()) * uint64(q.rate) / 1_000_000_000)
	transit := int64(arrivalTS) - int64(h.Timestamp)
	if q.lastTransit != 0 {
		d := transit - q.lastTransit
		if d < 0 {
			d = -d
		}
		q.jitter += (float64(d) - q.jitter) / 16
	}
	q.lastTransit = transit
}

// Report returns a snapshot of current QoS metrics with a simplified
// E-model MoS:
//
//	R0 = 93.2  (G.711 baseline)
//	Ie ~= 30 * loss_percent / 100
//	R  = max(0, R0 - Ie)
//	MoS = clamp(1 + 0.035*R + R*(R-60)*(100-R)*7e-6, 1, 4.5)
//
// Real production-grade MoS would also factor in delay (Id), code
// dependency (Ie-eff), and bursty-loss correction. This keeps the
// proxy simple while giving a single comparable number.
func (q *qosTracker) Report() *QoSReport {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	expected := q.received + uint64(maxInt64(q.lost, 0))
	var lossPct float64
	if expected > 0 {
		lossPct = float64(q.lost) / float64(expected) * 100
	}
	if lossPct < 0 {
		lossPct = 0
	}
	jitterMs := q.jitter * 1000 / float64(q.rate)

	r0 := 93.2
	ie := 30.0 * lossPct / 100
	r := r0 - ie
	if r < 0 {
		r = 0
	}
	if r > 100 {
		r = 100
	}
	mos := 1.0 + 0.035*r + r*(r-60)*(100-r)*7e-6
	if mos < 1 {
		mos = 1
	}
	if mos > 4.5 {
		mos = 4.5
	}

	loss := uint64(0)
	if q.lost > 0 {
		loss = uint64(q.lost)
	}

	return &QoSReport{
		PacketsReceived: q.received,
		PacketsLost:     loss,
		LossPercent:     lossPct,
		JitterMs:        jitterMs,
		MoS:             mos,
	}
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
