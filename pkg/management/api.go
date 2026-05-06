package management

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/intuitivelabs/funsip/pkg/metrics"
	"github.com/intuitivelabs/funsip/pkg/script"
	"github.com/intuitivelabs/funsip/pkg/store"
	"github.com/intuitivelabs/funsip/pkg/transaction"
	"github.com/intuitivelabs/funsip/pkg/transport"
)

const Version = metrics.Version

type API struct {
	txLayer   *transaction.Layer
	transport *transport.Manager
	scriptEng *script.Engine
	db        *store.DB
	metrics   *metrics.Metrics
	startTime time.Time
	logBuf    *RingBuffer
	server    *http.Server
}

func NewAPI(
	txLayer *transaction.Layer,
	tm *transport.Manager,
	scriptEng *script.Engine,
	db *store.DB,
	m *metrics.Metrics,
) *API {
	return &API{
		txLayer:   txLayer,
		transport: tm,
		scriptEng: scriptEng,
		db:        db,
		metrics:   m,
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
	mux.HandleFunc("/metrics", a.handleMetrics)
	mux.HandleFunc("/transactions", a.handleTransactions)
	mux.HandleFunc("/stats", a.handleStats)
	mux.HandleFunc("/logs", a.handleLogs)
	mux.HandleFunc("/registrations", a.handleRegistrations)
	mux.HandleFunc("/reload", a.handleReload)
	mux.HandleFunc("/script", a.handleScript)
	mux.HandleFunc("/deploy", a.handleDeploy)
	mux.HandleFunc("/rollback", a.handleRollback)

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
	goroutines, gomaxprocs, goVer := metrics.RuntimeInfo()
	vcsRev, vcsTime := metrics.BuildInfo()

	status := map[string]interface{}{
		"version":        Version,
		"uptime":         time.Since(a.startTime).String(),
		"uptime_seconds": int(time.Since(a.startTime).Seconds()),
		"build": map[string]interface{}{
			"vcs_revision": vcsRev,
			"vcs_time":     vcsTime,
			"go_version":   goVer,
		},
		"runtime": map[string]interface{}{
			"goroutines":  goroutines,
			"gomaxprocs":  gomaxprocs,
		},
		"transactions": map[string]interface{}{
			"total_created":      txStats.TotalCreated,
			"active":             txStats.Active,
			"server_count":       txStats.ServerTxCount,
			"client_count":       txStats.ClientTxCount,
			"pending_invite":     txStats.PendingINVITE,
			"pending_non_invite": txStats.PendingNonINVITE,
			"avg_resp_time_ms":   txStats.AvgRespTimeMs,
		},
		"transport": map[string]interface{}{
			"udp_received":     tpStats.UDPReceived,
			"udp_sent":         tpStats.UDPSent,
			"tcp_received":     tpStats.TCPReceived,
			"tcp_sent":         tpStats.TCPSent,
			"parse_errors":     tpStats.ParseErrors,
			"tcp_connections":  tpStats.TCPConnections,
		},
	}

	if a.metrics != nil {
		_, avgDelay5m := a.metrics.DelayStats(5)
		_, avgDelay1h := a.metrics.DelayStats(60)
		status["processing"] = map[string]interface{}{
			"requests_received":          a.metrics.RequestsReceived.Load(),
			"retransmissions_received":   a.metrics.Retransmissions.Load(),
			"requests_forwarded":         a.metrics.RequestsForwarded.Load(),
			"responses_received":         a.metrics.ResponsesReceived.Load(),
			"requests_answered_locally":  a.metrics.RequestsAnsweredLocally.Load(),
			"avg_delay_5m_ms":            avgDelay5m,
			"avg_delay_1h_ms":            avgDelay1h,
			"request_rate_5m_per_sec":    a.metrics.RequestRate(5),
			"request_rate_1h_per_sec":    a.metrics.RequestRate(60),
			"responses_by_class": map[string]uint64{
				"1xx": a.metrics.Responses1xx.Load(),
				"2xx": a.metrics.Responses2xx.Load(),
				"3xx": a.metrics.Responses3xx.Load(),
				"4xx": a.metrics.Responses4xx.Load(),
				"5xx": a.metrics.Responses5xx.Load(),
				"6xx": a.metrics.Responses6xx.Load(),
			},
		}
		status["dialogs"] = map[string]interface{}{
			"active":     a.metrics.DialogsActive.Load(),
			"created":    a.metrics.DialogsCreated.Load(),
			"completed":  a.metrics.DialogsCompleted.Load(),
			"timed_out":  a.metrics.DialogsTimedOut.Load(),
		}
	}

	writeJSON(w, status)
}

func (a *API) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.handleStatus(w, r)
}

func (a *API) handleScript(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, a.scriptEng.Source())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	if err := a.scriptEng.Deploy(string(body)); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{
		"success":      true,
		"message":      "script deployed",
		"can_rollback": a.scriptEng.HasRollback(),
	})
}

func (a *API) handleRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := a.scriptEng.Rollback(); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "rolled back to previous script",
	})
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
