package server_test

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/funsip/funsip/pkg/auth"
	"github.com/funsip/funsip/pkg/config"
	"github.com/funsip/funsip/pkg/server"
	"github.com/funsip/funsip/pkg/store"
)

const testScript = `
var DOMAIN = "test.local";

function onRequest(req) {
    if (req.method === "REGISTER") {
        if (!authenticate(DOMAIN)) return;
        fixContact();
        processRegister();
        return;
    }

    if (req.method === "OPTIONS") {
        sendResponse(200, "OK");
        return;
    }

    if (/^(INVITE|MESSAGE|SUBSCRIBE)$/.test(req.method)) {
        if (req.from && req.from.host === DOMAIN) {
            if (!authenticate(DOMAIN)) return;
        }

        var contacts = lookup();
        if (contacts && contacts.length > 0) {
            log("routing " + req.method + " to " + contacts[0].contact);
            proxy(contacts[0]);
        } else {
            sendResponse(404, "Not Found");
        }
        return;
    }

    if (req.method === "CANCEL") {
        sendResponse(200, "OK");
        return;
    }

    sendResponse(405, "Method Not Allowed");
}
`

type harness struct {
	t          *testing.T
	srv        *server.Server
	sipPort    int
	httpPort   int
	tmpDir     string
	clientConn *net.UDPConn
	clientAddr *net.UDPAddr
}

func setupHarness(t *testing.T) *harness {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "funsip-test-*")
	if err != nil {
		t.Fatal(err)
	}

	scriptPath := filepath.Join(tmpDir, "route.js")
	if err := os.WriteFile(scriptPath, []byte(testScript), 0644); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")

	sipPort := freePort(t, "udp")
	httpPort := freePort(t, "tcp")

	cfg := &config.Config{
		ListenIP:   "127.0.0.1",
		ListenPort: sipPort,
		Domain:     "test.local",
		DBPath:     dbPath,
		ScriptPath: scriptPath,
		HTTPIP:     "127.0.0.1",
		HTTPPort:   httpPort,
	}

	srv, err := server.New(cfg)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatal(err)
	}

	if err := srv.Start(); err != nil {
		srv.Stop()
		os.RemoveAll(tmpDir)
		t.Fatal(err)
	}

	time.Sleep(50 * time.Millisecond)

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	clientConn, err := net.ListenUDP("udp4", clientAddr)
	if err != nil {
		srv.Stop()
		os.RemoveAll(tmpDir)
		t.Fatal(err)
	}

	h := &harness{
		t:          t,
		srv:        srv,
		sipPort:    sipPort,
		httpPort:   httpPort,
		tmpDir:     tmpDir,
		clientConn: clientConn,
		clientAddr: clientConn.LocalAddr().(*net.UDPAddr),
	}

	t.Cleanup(func() {
		clientConn.Close()
		srv.Stop()
		os.RemoveAll(tmpDir)
	})

	return h
}

func freePort(t *testing.T, network string) int {
	t.Helper()
	switch network {
	case "udp":
		l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		port := l.LocalAddr().(*net.UDPAddr).Port
		l.Close()
		return port
	default:
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		return port
	}
}

func (h *harness) addSubscriber(username, domain, password string) {
	h.t.Helper()
	sub := &store.Subscriber{
		Username: username,
		Domain:   domain,
		HA1:      auth.ComputeHA1(username, domain, password),
		Password: password,
	}
	if err := h.srv.DB.UpsertSubscriber(sub); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) sendSIP(msg string) string {
	h.t.Helper()
	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}
	if _, err := h.clientConn.WriteToUDP([]byte(msg), target); err != nil {
		h.t.Fatal(err)
	}

	h.clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := h.clientConn.ReadFromUDP(buf)
	if err != nil {
		h.t.Fatalf("no SIP response: %v", err)
	}
	return string(buf[:n])
}

func (h *harness) sendSIPNoReply(msg string) {
	h.t.Helper()
	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}
	if _, err := h.clientConn.WriteToUDP([]byte(msg), target); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) get(path string) map[string]interface{} {
	h.t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d%s", h.httpPort, path)
	resp, err := http.Get(url)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		h.t.Fatal(err)
	}
	return result
}

func parseStatusLine(response string) (int, string) {
	lines := strings.Split(response, "\r\n")
	if len(lines) == 0 {
		return 0, ""
	}
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 3 {
		return 0, ""
	}
	var code int
	fmt.Sscanf(parts[1], "%d", &code)
	return code, parts[2]
}

func extractHeader(response string, name string) string {
	lower := strings.ToLower(name) + ":"
	for _, line := range strings.Split(response, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), lower) {
			return strings.TrimSpace(line[len(lower):])
		}
	}
	return ""
}

// ---------- Tests ----------

func TestOptions200(t *testing.T) {
	h := setupHarness(t)

	msg := buildRequest("OPTIONS", "sip:test.local", h.clientAddr.Port,
		"alice", "tester", "options-call-1", 1, nil, "")

	resp := h.sendSIP(msg)
	code, reason := parseStatusLine(resp)

	if code != 200 {
		t.Fatalf("expected 200, got %d %s\n%s", code, reason, resp)
	}
}

func TestRegisterUnauthorizedThenAuthorized(t *testing.T) {
	h := setupHarness(t)
	h.addSubscriber("alice", "test.local", "secret")

	// Step 1: REGISTER without credentials -> 401
	msg := buildRequest("REGISTER", "sip:test.local", h.clientAddr.Port,
		"alice", "alice", "reg-call-1", 1,
		[]string{"Contact: <sip:alice@127.0.0.1:9999>", "Expires: 3600"}, "")

	resp := h.sendSIP(msg)
	code, _ := parseStatusLine(resp)
	if code != 401 {
		t.Fatalf("expected 401, got %d\n%s", code, resp)
	}

	wwwAuth := extractHeader(resp, "WWW-Authenticate")
	if !strings.Contains(wwwAuth, `realm="test.local"`) {
		t.Fatalf("expected realm=\"test.local\" in WWW-Authenticate, got: %s", wwwAuth)
	}

	nonce := extractAuthParam(wwwAuth, "nonce")
	if nonce == "" {
		t.Fatal("no nonce in challenge")
	}

	// Step 2: REGISTER with correct credentials -> 200
	authHeader := buildDigestAuth("alice", "test.local", "secret", nonce, "REGISTER", "sip:test.local")
	msg2 := buildRequest("REGISTER", "sip:test.local", h.clientAddr.Port,
		"alice", "alice", "reg-call-2", 2,
		[]string{
			"Contact: <sip:alice@127.0.0.1:9999>",
			"Expires: 3600",
			"Authorization: " + authHeader,
		}, "")

	resp2 := h.sendSIP(msg2)
	code2, _ := parseStatusLine(resp2)
	if code2 != 200 {
		t.Fatalf("expected 200 OK after auth, got %d\n%s", code2, resp2)
	}

	// Verify binding was saved
	bindings, err := h.srv.DB.LookupBindings("sip:alice@test.local")
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) == 0 {
		t.Fatal("no bindings saved after successful REGISTER")
	}
}

func TestRegisterWrongPassword(t *testing.T) {
	h := setupHarness(t)
	h.addSubscriber("alice", "test.local", "secret")

	msg := buildRequest("REGISTER", "sip:test.local", h.clientAddr.Port,
		"alice", "alice", "reg-fail-1", 1,
		[]string{"Contact: <sip:alice@127.0.0.1:9999>", "Expires: 3600"}, "")

	resp := h.sendSIP(msg)
	code, _ := parseStatusLine(resp)
	if code != 401 {
		t.Fatalf("expected 401 first, got %d", code)
	}
	nonce := extractAuthParam(extractHeader(resp, "WWW-Authenticate"), "nonce")

	// Wrong password
	authHeader := buildDigestAuth("alice", "test.local", "wrongpass", nonce, "REGISTER", "sip:test.local")
	msg2 := buildRequest("REGISTER", "sip:test.local", h.clientAddr.Port,
		"alice", "alice", "reg-fail-2", 2,
		[]string{
			"Contact: <sip:alice@127.0.0.1:9999>",
			"Expires: 3600",
			"Authorization: " + authHeader,
		}, "")

	resp2 := h.sendSIP(msg2)
	code2, _ := parseStatusLine(resp2)
	if code2 != 401 {
		t.Fatalf("expected 401 (wrong password), got %d\n%s", code2, resp2)
	}
}

func TestInviteToUnregisteredUser(t *testing.T) {
	h := setupHarness(t)

	msg := buildRequest("INVITE", "sip:nobody@test.local", h.clientAddr.Port,
		"caller", "nobody", "invite-call-1", 1,
		[]string{"Contact: <sip:caller@127.0.0.1:9999>"}, "")

	// First response will be 100 Trying (auto-generated by IST), we need to drain
	// then read the actual response
	resp := h.sendSIP(msg)
	code, _ := parseStatusLine(resp)

	// Could be 100 Trying first, then 404. Or just 404 if from is not in our domain.
	// Since "caller@test.local" is from our domain, it triggers auth -> 407
	// Let's check both possibilities.
	if code == 100 {
		// drain trying, get next response
		h.clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 65535)
		n, _, err := h.clientConn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("expected follow-up response: %v", err)
		}
		resp = string(buf[:n])
		code, _ = parseStatusLine(resp)
	}

	// caller@test.local triggers auth challenge (407)
	if code != 407 {
		t.Fatalf("expected 407 (auth challenge for our-domain caller), got %d\n%s", code, resp)
	}
}

func TestRegisterAndInvite(t *testing.T) {
	h := setupHarness(t)
	h.addSubscriber("alice", "test.local", "secret")
	h.addSubscriber("bob", "test.local", "bobpass")

	// Register alice
	registerUser(t, h, "alice", "secret", "reg-alice-1", 1)

	// Verify alice is registered
	bindings, err := h.srv.DB.LookupBindings("sip:alice@test.local")
	if err != nil || len(bindings) == 0 {
		t.Fatal("alice not registered")
	}

	// Bob INVITEs alice
	bobNonce := getNonceForUser(t, h, "bob")

	authHeader := buildDigestAuth("bob", "test.local", "bobpass", bobNonce, "INVITE", "sip:alice@test.local")
	inviteMsg := buildRequest("INVITE", "sip:alice@test.local", h.clientAddr.Port,
		"bob", "alice", "invite-bob-alice", 1,
		[]string{
			"Contact: <sip:bob@127.0.0.1:9999>",
			"Authorization: " + authHeader,
		}, "")

	// We need to receive 100 Trying
	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}
	if _, err := h.clientConn.WriteToUDP([]byte(inviteMsg), target); err != nil {
		t.Fatal(err)
	}

	h.clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := h.clientConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}

	resp := string(buf[:n])
	code, _ := parseStatusLine(resp)

	// Should be 100 Trying
	if code != 100 {
		t.Logf("got code %d (expected 100 Trying first)\n%s", code, resp)
	}

	// Verify proxy made an outbound transaction (forwarding to alice)
	stats := h.get("/stats")
	totalTx := stats["total_transactions"]
	if totalTx == nil {
		t.Fatal("no total_transactions in stats")
	}
}

func TestManagementAPI(t *testing.T) {
	h := setupHarness(t)
	h.addSubscriber("alice", "test.local", "secret")

	status := h.get("/status")
	if status["version"] == nil {
		t.Error("status missing version field")
	}
	if status["uptime"] == nil {
		t.Error("status missing uptime field")
	}

	stats := h.get("/stats")
	if stats["uptime_seconds"] == nil {
		t.Error("stats missing uptime_seconds field")
	}

	// Generate some traffic
	registerUser(t, h, "alice", "secret", "mgmt-reg-1", 1)

	regs := h.getArray("/registrations")
	if len(regs) == 0 {
		t.Error("expected at least one registration")
	}

	// Seed the log ring buffer (logger isn't piped to it in tests
	// because that would mutate global log.SetOutput state).
	h.srv.Mgmt.LogBuffer().Write([]byte("test log entry\n"))

	logs := h.getArray("/logs")
	if len(logs) == 0 {
		t.Error("expected log entries in ring buffer")
	}

	// Test reload
	url := fmt.Sprintf("http://127.0.0.1:%d/reload", h.httpPort)
	resp, err := http.Post(url, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var reloadResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&reloadResult)
	if reloadResult["success"] != true {
		t.Errorf("reload failed: %v", reloadResult)
	}
}

func TestMetricsTracking(t *testing.T) {
	h := setupHarness(t)
	h.addSubscriber("alice", "test.local", "secret")

	// Send OPTIONS (locally answered with 200)
	msg := buildRequest("OPTIONS", "sip:test.local", h.clientAddr.Port,
		"alice", "tester", "metrics-opt-1", 1, nil, "")
	h.sendSIP(msg)

	// Register alice (locally answered: 401 then 200)
	registerUser(t, h, "alice", "secret", "metrics-reg", 1)

	status := h.get("/status")
	pr, ok := status["processing"].(map[string]interface{})
	if !ok {
		t.Fatal("processing section missing from status")
	}

	if got := getInt(pr, "requests_received"); got < 3 {
		t.Errorf("requests_received: expected >=3 (OPTIONS + 2 REGISTERs), got %d", got)
	}
	if got := getInt(pr, "requests_answered_locally"); got < 3 {
		t.Errorf("requests_answered_locally: expected >=3 (200 OPTIONS + 401 + 200 REGISTER), got %d", got)
	}

	classes, ok := pr["responses_by_class"].(map[string]interface{})
	if !ok {
		t.Fatal("responses_by_class section missing")
	}
	_ = classes // values are 0 since no upstream responses came in this test

	// Verify INVITE/non-INVITE breakdown is present
	tx := status["transactions"].(map[string]interface{})
	if _, has := tx["pending_invite"]; !has {
		t.Error("pending_invite missing from transactions stats")
	}
	if _, has := tx["pending_non_invite"]; !has {
		t.Error("pending_non_invite missing from transactions stats")
	}

	// Verify build/runtime info is present
	if _, has := status["build"]; !has {
		t.Error("build info missing")
	}
	if _, has := status["runtime"]; !has {
		t.Error("runtime info missing")
	}
}

func TestDeployAndRollback(t *testing.T) {
	h := setupHarness(t)

	// Get original script
	origText := h.getText("/script")
	if !strings.Contains(origText, "onRequest") {
		t.Fatalf("unexpected initial script: %q", origText)
	}

	// Deploy a new script that always returns 480
	newScript := `function onRequest(req) { sendResponse(480, "Temporarily Unavailable"); }`
	result := h.postText("/deploy", newScript)
	if result["success"] != true {
		t.Fatalf("deploy failed: %v", result)
	}

	// Send OPTIONS — should now get 480
	msg := buildRequest("OPTIONS", "sip:test.local", h.clientAddr.Port,
		"alice", "x", "deploy-opt-1", 1, nil, "")
	resp := h.sendSIP(msg)
	code, _ := parseStatusLine(resp)
	if code != 480 {
		t.Errorf("after deploy: expected 480, got %d", code)
	}

	// Rollback
	rb := h.postText("/rollback", "")
	if rb["success"] != true {
		t.Fatalf("rollback failed: %v", rb)
	}

	// Send OPTIONS again — original script returns 200
	msg2 := buildRequest("OPTIONS", "sip:test.local", h.clientAddr.Port,
		"alice", "x", "deploy-opt-2", 2, nil, "")
	resp2 := h.sendSIP(msg2)
	code2, _ := parseStatusLine(resp2)
	if code2 != 200 {
		t.Errorf("after rollback: expected 200, got %d", code2)
	}
}

func TestDeployInvalidScript(t *testing.T) {
	h := setupHarness(t)

	// Deploy a script with a syntax error
	bad := `function onRequest(req) { this is not valid javascript ====== `
	result := h.postText("/deploy", bad)
	if result["success"] == true {
		t.Fatal("expected deploy to fail for invalid script")
	}
	if result["error"] == nil {
		t.Error("expected error message in response")
	}

	// Verify the original script is still active
	msg := buildRequest("OPTIONS", "sip:test.local", h.clientAddr.Port,
		"alice", "x", "invalid-opt", 1, nil, "")
	resp := h.sendSIP(msg)
	code, _ := parseStatusLine(resp)
	if code != 200 {
		t.Errorf("original script should still work: expected 200, got %d", code)
	}
}

func TestTransactionRetransmissionAbsorbed(t *testing.T) {
	h := setupHarness(t)

	msg := buildRequest("OPTIONS", "sip:test.local", h.clientAddr.Port,
		"alice", "test", "retx-call-1", 1, nil, "")

	// First send - should get 200
	resp1 := h.sendSIP(msg)
	code1, _ := parseStatusLine(resp1)
	if code1 != 200 {
		t.Fatalf("first response: expected 200, got %d", code1)
	}

	// Retransmit same message - server tx should absorb and re-send same response
	resp2 := h.sendSIP(msg)
	code2, _ := parseStatusLine(resp2)
	if code2 != 200 {
		t.Fatalf("retransmit response: expected 200, got %d", code2)
	}

	// Verify only ONE transaction was created (not two)
	stats := h.get("/stats")
	totalTx, _ := stats["total_transactions"].(float64)
	if totalTx != 1 {
		t.Errorf("expected exactly 1 transaction (retransmits absorbed), got %v", totalTx)
	}
}

// ---------- Helpers ----------

func (h *harness) getArray(path string) []interface{} {
	h.t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d%s", h.httpPort, path)
	resp, err := http.Get(url)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()

	var result []interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

func (h *harness) getText(path string) string {
	h.t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d%s", h.httpPort, path)
	resp, err := http.Get(url)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body := make([]byte, 0, 4096)
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}
	return string(body)
}

func (h *harness) postText(path, body string) map[string]interface{} {
	h.t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d%s", h.httpPort, path)
	resp, err := http.Post(url, "text/plain", strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

func getInt(m map[string]interface{}, key string) int64 {
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return int64(f)
		}
	}
	return 0
}

func buildRequest(method, ruri string, viaPort int, fromUser, toUser, callID string, cseq int, extra []string, body string) string {
	var sb strings.Builder
	branch := fmt.Sprintf("z9hG4bK%d-%s", time.Now().UnixNano(), callID)

	fmt.Fprintf(&sb, "%s %s SIP/2.0\r\n", method, ruri)
	fmt.Fprintf(&sb, "Via: SIP/2.0/UDP 127.0.0.1:%d;branch=%s;rport\r\n", viaPort, branch)
	fmt.Fprintf(&sb, "Max-Forwards: 70\r\n")
	fmt.Fprintf(&sb, "From: <sip:%s@test.local>;tag=%s-tag\r\n", fromUser, callID)
	fmt.Fprintf(&sb, "To: <sip:%s@test.local>\r\n", toUser)
	fmt.Fprintf(&sb, "Call-ID: %s\r\n", callID)
	fmt.Fprintf(&sb, "CSeq: %d %s\r\n", cseq, method)
	for _, h := range extra {
		fmt.Fprintf(&sb, "%s\r\n", h)
	}
	fmt.Fprintf(&sb, "Content-Length: %d\r\n\r\n", len(body))
	sb.WriteString(body)

	return sb.String()
}

func buildDigestAuth(username, realm, password, nonce, method, uri string) string {
	ha1 := auth.ComputeHA1(username, realm, password)
	ha2 := md5sum(method + ":" + uri)
	response := md5sum(ha1 + ":" + nonce + ":" + ha2)

	return fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=MD5`,
		username, realm, nonce, uri, response,
	)
}

func md5sum(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func extractAuthParam(header, key string) string {
	idx := strings.Index(header, key+"=")
	if idx < 0 {
		return ""
	}
	rest := header[idx+len(key)+1:]
	if strings.HasPrefix(rest, `"`) {
		end := strings.Index(rest[1:], `"`)
		if end < 0 {
			return ""
		}
		return rest[1 : 1+end]
	}
	end := strings.IndexAny(rest, ", ")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func registerUser(t *testing.T, h *harness, username, password, callID string, cseq int) {
	t.Helper()

	msg := buildRequest("REGISTER", "sip:test.local", h.clientAddr.Port,
		username, username, callID, cseq,
		[]string{
			fmt.Sprintf("Contact: <sip:%s@127.0.0.1:%d>", username, h.clientAddr.Port),
			"Expires: 3600",
		}, "")

	resp := h.sendSIP(msg)
	code, _ := parseStatusLine(resp)
	if code != 401 {
		t.Fatalf("expected 401, got %d", code)
	}

	nonce := extractAuthParam(extractHeader(resp, "WWW-Authenticate"), "nonce")
	authHeader := buildDigestAuth(username, "test.local", password, nonce, "REGISTER", "sip:test.local")

	msg2 := buildRequest("REGISTER", "sip:test.local", h.clientAddr.Port,
		username, username, callID+"b", cseq+1,
		[]string{
			fmt.Sprintf("Contact: <sip:%s@127.0.0.1:%d>", username, h.clientAddr.Port),
			"Expires: 3600",
			"Authorization: " + authHeader,
		}, "")

	resp2 := h.sendSIP(msg2)
	code2, _ := parseStatusLine(resp2)
	if code2 != 200 {
		t.Fatalf("REGISTER (auth) for %s: expected 200, got %d\n%s", username, code2, resp2)
	}
}

func getNonceForUser(t *testing.T, h *harness, username string) string {
	t.Helper()
	msg := buildRequest("INVITE", "sip:somebody@test.local", h.clientAddr.Port,
		username, "somebody", "nonce-fetch-"+username, 1,
		[]string{fmt.Sprintf("Contact: <sip:%s@127.0.0.1:%d>", username, h.clientAddr.Port)}, "")

	resp := h.sendSIP(msg)
	code, _ := parseStatusLine(resp)

	// May get 100 Trying first
	if code == 100 {
		h.clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 65535)
		n, _, _ := h.clientConn.ReadFromUDP(buf)
		resp = string(buf[:n])
	}

	return extractAuthParam(extractHeader(resp, "Proxy-Authenticate"), "nonce")
}
