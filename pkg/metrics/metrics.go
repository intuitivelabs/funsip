package metrics

import (
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

const Version = "0.1.0"

type Metrics struct {
	StartTime               time.Time
	RequestsReceived        atomic.Uint64
	Retransmissions         atomic.Uint64
	RequestsForwarded       atomic.Uint64
	ResponsesReceived       atomic.Uint64
	RequestsAnsweredLocally atomic.Uint64

	Responses1xx atomic.Uint64
	Responses2xx atomic.Uint64
	Responses3xx atomic.Uint64
	Responses4xx atomic.Uint64
	Responses5xx atomic.Uint64
	Responses6xx atomic.Uint64

	delays *windowed
	rates  *windowed
}

func New() *Metrics {
	return &Metrics{
		StartTime: time.Now(),
		delays:    &windowed{},
		rates:     &windowed{},
	}
}

func (m *Metrics) RecordReceived() {
	m.RequestsReceived.Add(1)
	m.rates.add(1, 0)
}

func (m *Metrics) RecordRetransmission() {
	m.Retransmissions.Add(1)
}

func (m *Metrics) RecordForwarded() {
	m.RequestsForwarded.Add(1)
}

func (m *Metrics) RecordResponseReceived(statusCode int) {
	m.ResponsesReceived.Add(1)
	switch {
	case statusCode >= 100 && statusCode < 200:
		m.Responses1xx.Add(1)
	case statusCode >= 200 && statusCode < 300:
		m.Responses2xx.Add(1)
	case statusCode >= 300 && statusCode < 400:
		m.Responses3xx.Add(1)
	case statusCode >= 400 && statusCode < 500:
		m.Responses4xx.Add(1)
	case statusCode >= 500 && statusCode < 600:
		m.Responses5xx.Add(1)
	case statusCode >= 600 && statusCode < 700:
		m.Responses6xx.Add(1)
	}
}

func (m *Metrics) RecordLocallyAnswered() {
	m.RequestsAnsweredLocally.Add(1)
}

func (m *Metrics) RecordDelay(ms int64) {
	m.delays.add(1, ms)
}

func (m *Metrics) DelayStats(windowMin int) (count int64, avgMs int64) {
	return m.delays.stats(windowMin)
}

func (m *Metrics) RequestRate(windowMin int) float64 {
	count, _ := m.rates.stats(windowMin)
	if windowMin <= 0 {
		return 0
	}
	return float64(count) / (float64(windowMin) * 60.0)
}

type windowed struct {
	mu      sync.Mutex
	buckets [60]bucket
}

type bucket struct {
	minute int64
	count  int64
	sumMs  int64
}

func (w *windowed) add(count, sumMs int64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	minute := time.Now().Unix() / 60
	idx := minute % 60
	if w.buckets[idx].minute != minute {
		w.buckets[idx] = bucket{minute: minute}
	}
	w.buckets[idx].count += count
	w.buckets[idx].sumMs += sumMs
}

func (w *windowed) stats(windowMin int) (totalCount int64, avgMs int64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	minute := time.Now().Unix() / 60
	var sumMs int64

	for i := 0; i < 60; i++ {
		b := w.buckets[i]
		if b.minute > 0 && minute-b.minute < int64(windowMin) {
			totalCount += b.count
			sumMs += b.sumMs
		}
	}

	if totalCount > 0 {
		avgMs = sumMs / totalCount
	}
	return
}

func BuildInfo() (vcsRev, vcsTime string) {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if len(s.Value) > 8 {
					vcsRev = s.Value[:8]
				} else {
					vcsRev = s.Value
				}
			case "vcs.time":
				vcsTime = s.Value
			}
		}
	}
	return
}

func RuntimeInfo() (numGoroutines, maxProcs int, goVersion string) {
	return runtime.NumGoroutine(), runtime.GOMAXPROCS(0), runtime.Version()
}
