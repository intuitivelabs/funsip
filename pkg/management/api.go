package management

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/funsip/funsip/pkg/script"
	"github.com/funsip/funsip/pkg/store"
	"github.com/funsip/funsip/pkg/transaction"
	"github.com/funsip/funsip/pkg/transport"
)

const Version = "0.1.0"

type API struct {
	txLayer   *transaction.Layer
	transport *transport.Manager
	scriptEng *script.Engine
	db        *store.DB
	startTime time.Time
	logBuf    *RingBuffer
	server    *http.Server
}

func NewAPI(
	txLayer *transaction.Layer,
	tm *transport.Manager,
	scriptEng *script.Engine,
	db *store.DB,
) *API {
	return &API{
		txLayer:   txLayer,
		transport: tm,
		scriptEng: scriptEng,
		db:        db,
		startTime: time.Now(),
		logBuf:    NewRingBuffer(1000),
	}
}

func (a *API) LogBuffer() *RingBuffer {
	return a.logBuf
}

func (a *API) Start(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", a.handleStatus)
	mux.HandleFunc("/transactions", a.handleTransactions)
	mux.HandleFunc("/stats", a.handleStats)
	mux.HandleFunc("/logs", a.handleLogs)
	mux.HandleFunc("/registrations", a.handleRegistrations)
	mux.HandleFunc("/reload", a.handleReload)

	a.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	log.Printf("[management] HTTP API listening on %s", addr)
	go func() {
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[management] HTTP server error: %v", err)
		}
	}()
	return nil
}

func (a *API) Stop() {
	if a.server != nil {
		a.server.Close()
	}
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	txStats := a.txLayer.Stats()
	tpStats := a.transport.GetStats()

	status := map[string]interface{}{
		"version": Version,
		"uptime":  time.Since(a.startTime).String(),
		"uptime_seconds": int(time.Since(a.startTime).Seconds()),
		"transactions": map[string]interface{}{
			"total_created":    txStats.TotalCreated,
			"active":           txStats.Active,
			"server_count":     txStats.ServerTxCount,
			"client_count":     txStats.ClientTxCount,
			"avg_resp_time_ms": txStats.AvgRespTimeMs,
		},
		"transport": map[string]interface{}{
			"udp_received":  tpStats.UDPReceived,
			"udp_sent":      tpStats.UDPSent,
			"tcp_received":  tpStats.TCPReceived,
			"tcp_sent":      tpStats.TCPSent,
			"parse_errors":  tpStats.ParseErrors,
		},
	}

	writeJSON(w, status)
}

func (a *API) handleTransactions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, a.txLayer.ActiveTransactions())
}

func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	txStats := a.txLayer.Stats()
	tpStats := a.transport.GetStats()

	stats := map[string]interface{}{
		"version":              Version,
		"uptime_seconds":       int(time.Since(a.startTime).Seconds()),
		"total_transactions":   txStats.TotalCreated,
		"active_transactions":  txStats.Active,
		"avg_response_time_ms": txStats.AvgRespTimeMs,
		"udp_messages_in":      tpStats.UDPReceived,
		"udp_messages_out":     tpStats.UDPSent,
		"tcp_messages_in":      tpStats.TCPReceived,
		"tcp_messages_out":     tpStats.TCPSent,
		"parse_errors":         tpStats.ParseErrors,
	}

	writeJSON(w, stats)
}

func (a *API) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, a.logBuf.Entries())
}

func (a *API) handleRegistrations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bindings, err := a.db.ListAllBindings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var result []map[string]interface{}
	for _, b := range bindings {
		result = append(result, map[string]interface{}{
			"aor":           b.AOR,
			"contact":       b.Contact,
			"expires_at":    b.ExpiresAt.Format(time.RFC3339),
			"received_ip":   b.ReceivedIP,
			"received_port": b.ReceivedPort,
			"transport":     b.Transport,
			"user_agent":    b.UserAgent,
		})
	}

	writeJSON(w, result)
}

func (a *API) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := a.scriptEng.Reload(); err != nil {
		writeJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "script reloaded",
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

type RingBuffer struct {
	entries []LogEntry
	pos     int
	full    bool
	mu      sync.Mutex
}

func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		entries: make([]LogEntry, size),
	}
}

func (rb *RingBuffer) Write(p []byte) (n int, err error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	msg := string(p)
	rb.entries[rb.pos] = LogEntry{
		Timestamp: time.Now(),
		Message:   msg,
	}
	rb.pos = (rb.pos + 1) % len(rb.entries)
	if rb.pos == 0 {
		rb.full = true
	}
	return len(p), nil
}

func (rb *RingBuffer) Entries() []LogEntry {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	var result []LogEntry
	if rb.full {
		result = append(result, rb.entries[rb.pos:]...)
		result = append(result, rb.entries[:rb.pos]...)
	} else {
		result = rb.entries[:rb.pos]
	}

	filtered := make([]LogEntry, 0, len(result))
	for _, e := range result {
		if e.Message != "" {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func (rb *RingBuffer) String() string {
	entries := rb.Entries()
	var s string
	for _, e := range entries {
		s += fmt.Sprintf("[%s] %s", e.Timestamp.Format("15:04:05"), e.Message)
	}
	return s
}
