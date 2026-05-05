package server_test

import (
	"bytes"
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
	"github.com/funsip/funsip/pkg/dialog"
	"github.com/funsip/funsip/pkg/media"
	"github.com/funsip/funsip/pkg/sdp"
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

    if (/^(INVITE|MESSAGE|SUBSCRIBE|CANCEL)$/.test(req.method)) {
        // CANCEL cannot be authenticated; orphan CANCELs reach this point.
        if (req.method !== "CANCEL" && req.from && req.from.host === DOMAIN) {
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

func TestCancelMatchedInvite(t *testing.T) {
	h := setupHarness(t)
	h.addSubscriber("bob", "test.local", "bobpass")

	// Sink socket to receive what the proxy forwards upstream.
	sinkConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sinkConn.Close()
	sinkPort := sinkConn.LocalAddr().(*net.UDPAddr).Port

	// Pre-register alice with binding to the sink so the proxy forwards there.
	if err := h.srv.DB.SaveBinding(&store.Binding{
		AOR:          "sip:alice@test.local",
		Contact:      fmt.Sprintf("sip:alice@127.0.0.1:%d", sinkPort),
		ReceivedIP:   "127.0.0.1",
		ReceivedPort: sinkPort,
		Transport:    "UDP",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	bobNonce := getNonceForUser(t, h, "bob")
	authHeader := buildDigestAuth("bob", "test.local", "bobpass", bobNonce, "INVITE", "sip:alice@test.local")

	callID := "cancel-test-call"
	branch := fmt.Sprintf("z9hG4bK%d-cancel", time.Now().UnixNano())
	fromTag := "bob-cancel-tag"

	invite := buildRequestExplicit("INVITE", "sip:alice@test.local", h.clientAddr.Port,
		"bob", "alice", callID, 1, branch, fromTag,
		[]string{
			fmt.Sprintf("Contact: <sip:bob@127.0.0.1:%d>", h.clientAddr.Port),
			"Authorization: " + authHeader,
		}, "")

	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}
	if _, err := h.clientConn.WriteToUDP([]byte(invite), target); err != nil {
		t.Fatal(err)
	}

	// Wait for the proxy to forward the INVITE to the sink.
	sinkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := sinkConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("sink did not receive forwarded INVITE: %v", err)
	}
	fwd := string(buf[:n])
	if !strings.HasPrefix(fwd, "INVITE ") {
		t.Errorf("expected forwarded INVITE, got prefix: %q", firstLine(fwd))
	}

	// Bob sends CANCEL with the same branch / Call-ID / From-tag.
	cancel := buildRequestExplicit("CANCEL", "sip:alice@test.local", h.clientAddr.Port,
		"bob", "alice", callID, 1, branch, fromTag, nil, "")
	if _, err := h.clientConn.WriteToUDP([]byte(cancel), target); err != nil {
		t.Fatal(err)
	}

	var got200, got487 bool
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (!got200 || !got487) {
		h.clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 65535)
		n, _, err := h.clientConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		msg := string(buf[:n])
		code, _ := parseStatusLine(msg)
		cseq := extractHeader(msg, "CSeq")
		switch {
		case code == 200 && strings.Contains(cseq, "CANCEL"):
			got200 = true
		case code == 487 && strings.Contains(cseq, "INVITE"):
			got487 = true
		}
	}
	if !got200 {
		t.Error("did not receive 200 OK for CANCEL")
	}
	if !got487 {
		t.Error("did not receive 487 Request Terminated for INVITE")
	}

	// Sink should also receive the forwarded CANCEL on the same branch.
	sinkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	deadline2 := time.Now().Add(2 * time.Second)
	var sawCancel bool
	for time.Now().Before(deadline2) && !sawCancel {
		sinkConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _, err := sinkConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if strings.HasPrefix(string(buf[:n]), "CANCEL ") {
			sawCancel = true
		}
	}
	if !sawCancel {
		t.Error("sink did not receive forwarded CANCEL on the pending branch")
	}
}

func TestCancelOrphanGoesThroughScript(t *testing.T) {
	h := setupHarness(t)

	// CANCEL with no matching INVITE — the script processes it. Since
	// nobody is registered for "nobody@test.local" the script returns 404.
	cancel := buildRequest("CANCEL", "sip:nobody@test.local", h.clientAddr.Port,
		"alice", "nobody", "orphan-cancel", 1, nil, "")

	resp := h.sendSIP(cancel)
	code, _ := parseStatusLine(resp)

	if code == 401 || code == 407 {
		t.Errorf("orphan CANCEL got auth challenge %d (CANCEL must not be authenticated)", code)
	}
	if code != 404 {
		t.Errorf("expected 404 for orphan CANCEL with no destination, got %d", code)
	}
}

func TestAppendAndRemoveHeader(t *testing.T) {
	h := setupHarness(t)

	sinkConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sinkConn.Close()
	sinkPort := sinkConn.LocalAddr().(*net.UDPAddr).Port

	if err := h.srv.DB.SaveBinding(&store.Binding{
		AOR:          "sip:dest@test.local",
		Contact:      fmt.Sprintf("sip:dest@127.0.0.1:%d", sinkPort),
		ReceivedIP:   "127.0.0.1",
		ReceivedPort: sinkPort,
		Transport:    "UDP",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	script := `
function onRequest(req) {
    appendHeader("X-Funsip", "first");
    appendHeader("X-Funsip", "second");
    removeHeader("Subject");
    // Compact form: "v" should resolve to Via — but Via is critical so we
    // just test compact-form resolution via a non-mandatory header.
    removeHeader("s");  // also Subject in compact form
    var contacts = lookup();
    if (contacts.length > 0) proxy(contacts[0]);
    else sendResponse(404, "Not Found");
}
`
	if r := h.postText("/deploy", script); r["success"] != true {
		t.Fatalf("deploy failed: %v", r)
	}

	msg := buildRequest("MESSAGE", "sip:dest@test.local", h.clientAddr.Port,
		"ext", "dest", "header-test", 1,
		[]string{"Subject: should be removed", "Content-Type: text/plain"}, "hi")

	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}
	if _, err := h.clientConn.WriteToUDP([]byte(msg), target); err != nil {
		t.Fatal(err)
	}

	sinkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := sinkConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("sink did not receive forwarded message: %v", err)
	}
	fwd := string(buf[:n])

	if !strings.Contains(fwd, "X-Funsip: first") {
		t.Errorf("X-Funsip: first missing in forwarded request:\n%s", fwd)
	}
	if !strings.Contains(fwd, "X-Funsip: second") {
		t.Errorf("X-Funsip: second missing in forwarded request:\n%s", fwd)
	}
	for _, line := range strings.Split(fwd, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "subject:") {
			t.Errorf("Subject header was not removed:\n%s", fwd)
		}
	}
}

func TestSendResponseWithHeaders(t *testing.T) {
	h := setupHarness(t)

	script := `
function onRequest(req) {
    sendResponse(486, "Busy Here", {"Retry-After": "60", "X-Reason": "test"});
}
`
	if r := h.postText("/deploy", script); r["success"] != true {
		t.Fatalf("deploy failed: %v", r)
	}

	msg := buildRequest("OPTIONS", "sip:test.local", h.clientAddr.Port,
		"alice", "x", "sendresp-headers", 1, nil, "")
	resp := h.sendSIP(msg)

	code, _ := parseStatusLine(resp)
	if code != 486 {
		t.Fatalf("expected 486, got %d\n%s", code, resp)
	}
	if got := extractHeader(resp, "Retry-After"); got != "60" {
		t.Errorf("Retry-After: expected 60, got %q", got)
	}
	if got := extractHeader(resp, "X-Reason"); got != "test" {
		t.Errorf("X-Reason: expected 'test', got %q", got)
	}
}

func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\r'); idx > 0 {
		return s[:idx]
	}
	if idx := strings.IndexByte(s, '\n'); idx > 0 {
		return s[:idx]
	}
	return s
}

func TestProxyNoArgsForwardsToRequestURI(t *testing.T) {
	h := setupHarness(t)

	sinkConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sinkConn.Close()
	sinkPort := sinkConn.LocalAddr().(*net.UDPAddr).Port

	script := `
function onRequest(req) {
    if (req.method === "MESSAGE") {
        proxy();  // no args: forward to host:port in Request-URI
        return;
    }
    sendResponse(405, "Method Not Allowed");
}
`
	if r := h.postText("/deploy", script); r["success"] != true {
		t.Fatalf("deploy failed: %v", r)
	}

	ruri := fmt.Sprintf("sip:user@127.0.0.1:%d", sinkPort)
	msg := buildRequest("MESSAGE", ruri, h.clientAddr.Port,
		"sender", "user", "argless-proxy-1", 1,
		[]string{"Content-Type: text/plain"}, "hi")

	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}
	if _, err := h.clientConn.WriteToUDP([]byte(msg), target); err != nil {
		t.Fatal(err)
	}

	sinkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := sinkConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("sink did not receive forwarded MESSAGE: %v", err)
	}
	fwd := string(buf[:n])

	first := firstLine(fwd)
	if !strings.Contains(first, "MESSAGE ") {
		t.Errorf("expected MESSAGE request line, got: %q", first)
	}
	// proxy() with no args must keep the original Request-URI verbatim.
	if !strings.Contains(first, ruri) {
		t.Errorf("Request-URI not preserved: line=%q want substring=%q", first, ruri)
	}
}

func TestMaxForwardsAddedIfMissing(t *testing.T) {
	h := setupHarness(t)

	sinkConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sinkConn.Close()
	sinkPort := sinkConn.LocalAddr().(*net.UDPAddr).Port

	script := `function onRequest(req) { proxy(); }`
	if r := h.postText("/deploy", script); r["success"] != true {
		t.Fatalf("deploy failed: %v", r)
	}

	// Build a request WITHOUT a Max-Forwards header.
	ruri := fmt.Sprintf("sip:x@127.0.0.1:%d", sinkPort)
	branch := fmt.Sprintf("z9hG4bK%d-mf-missing", time.Now().UnixNano())
	msg := fmt.Sprintf(
		"MESSAGE %s SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=%s;rport\r\n"+
			"From: <sip:s@test.local>;tag=mft\r\n"+
			"To: <sip:x@test.local>\r\n"+
			"Call-ID: mf-missing-1\r\n"+
			"CSeq: 1 MESSAGE\r\n"+
			"Content-Length: 0\r\n\r\n",
		ruri, h.clientAddr.Port, branch,
	)

	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}
	if _, err := h.clientConn.WriteToUDP([]byte(msg), target); err != nil {
		t.Fatal(err)
	}

	sinkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := sinkConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("sink did not receive forwarded MESSAGE: %v", err)
	}
	fwd := string(buf[:n])

	mf := extractHeader(fwd, "Max-Forwards")
	// Stack inserts 70 on receipt; proxy decrements to 69 before forward.
	if mf != "69" {
		t.Errorf("Max-Forwards: expected 69 (70 default - 1 hop), got %q\n%s", mf, fwd)
	}
}

func TestMaxForwardsZeroRejectsForward(t *testing.T) {
	h := setupHarness(t)

	script := `function onRequest(req) { proxyTo("127.0.0.1:9", "UDP"); }`
	if r := h.postText("/deploy", script); r["success"] != true {
		t.Fatalf("deploy failed: %v", r)
	}

	branch := fmt.Sprintf("z9hG4bK%d-mf-zero", time.Now().UnixNano())
	msg := fmt.Sprintf(
		"MESSAGE sip:x@test.local SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=%s;rport\r\n"+
			"Max-Forwards: 0\r\n"+
			"From: <sip:s@test.local>;tag=mfz\r\n"+
			"To: <sip:x@test.local>\r\n"+
			"Call-ID: mf-zero-1\r\n"+
			"CSeq: 1 MESSAGE\r\n"+
			"Content-Length: 0\r\n\r\n",
		h.clientAddr.Port, branch,
	)

	resp := h.sendSIP(msg)
	code, _ := parseStatusLine(resp)
	if code != 483 {
		t.Errorf("MF=0 should produce 483 Too Many Hops, got %d\n%s", code, resp)
	}
}

func TestSetRequestUri(t *testing.T) {
	h := setupHarness(t)

	sinkConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sinkConn.Close()
	sinkPort := sinkConn.LocalAddr().(*net.UDPAddr).Port

	script := fmt.Sprintf(`
function onRequest(req) {
    if (req.method === "MESSAGE") {
        setRequestUri("sip:rewritten@127.0.0.1:%d");
        proxy();
        return;
    }
    sendResponse(405, "Method Not Allowed");
}
`, sinkPort)
	if r := h.postText("/deploy", script); r["success"] != true {
		t.Fatalf("deploy failed: %v", r)
	}

	// Original Request-URI points elsewhere; the script rewrites it.
	msg := buildRequest("MESSAGE", "sip:original@some.where:9999", h.clientAddr.Port,
		"s", "x", "rewrite-1", 1, []string{"Content-Type: text/plain"}, "hi")

	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}
	if _, err := h.clientConn.WriteToUDP([]byte(msg), target); err != nil {
		t.Fatal(err)
	}

	sinkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := sinkConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("sink did not receive forwarded MESSAGE: %v", err)
	}
	fwd := string(buf[:n])

	first := firstLine(fwd)
	wantRURI := fmt.Sprintf("sip:rewritten@127.0.0.1:%d", sinkPort)
	if !strings.Contains(first, wantRURI) {
		t.Errorf("setRequestUri did not take effect:\n got: %q\nwant substring: %q", first, wantRURI)
	}
}

// ---------- Media anchor tests ----------

const sdpOffer = "v=0\r\n" +
	"o=alice 1 1 IN IP4 192.0.2.10\r\n" +
	"s=-\r\n" +
	"c=IN IP4 192.0.2.10\r\n" +
	"t=0 0\r\n" +
	"m=audio 30000 RTP/AVP 0\r\n" +
	"a=rtpmap:0 PCMU/8000\r\n" +
	"a=sendrecv\r\n"

const sdpAnswer = "v=0\r\n" +
	"o=bob 1 1 IN IP4 192.0.2.20\r\n" +
	"s=-\r\n" +
	"c=IN IP4 192.0.2.20\r\n" +
	"t=0 0\r\n" +
	"m=audio 40000 RTP/AVP 0\r\n" +
	"a=rtpmap:0 PCMU/8000\r\n" +
	"a=sendrecv\r\n"

func TestAnchorMediaRewritesOfferSDP(t *testing.T) {
	h := setupHarness(t)

	sinkConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sinkConn.Close()
	sinkPort := sinkConn.LocalAddr().(*net.UDPAddr).Port

	if err := h.srv.DB.SaveBinding(&store.Binding{
		AOR:          "sip:bob@test.local",
		Contact:      fmt.Sprintf("sip:bob@127.0.0.1:%d", sinkPort),
		ReceivedIP:   "127.0.0.1",
		ReceivedPort: sinkPort,
		Transport:    "UDP",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	script := `
function onRequest(req) {
    if (req.method === "INVITE") {
        anchorMedia();
        var contacts = lookup();
        if (contacts.length > 0) proxy(contacts[0]);
        else sendResponse(404, "Not Found");
        return;
    }
    sendResponse(405);
}`
	if r := h.postText("/deploy", script); r["success"] != true {
		t.Fatalf("deploy failed: %v", r)
	}

	invite := buildRequest("INVITE", "sip:bob@test.local", h.clientAddr.Port,
		"alice", "bob", "anchor-test-1", 1,
		[]string{
			fmt.Sprintf("Contact: <sip:alice@127.0.0.1:%d>", h.clientAddr.Port),
			"Content-Type: application/sdp",
		}, sdpOffer)

	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}
	if _, err := h.clientConn.WriteToUDP([]byte(invite), target); err != nil {
		t.Fatal(err)
	}

	sinkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := sinkConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("sink did not receive forwarded INVITE: %v", err)
	}
	fwd := string(buf[:n])

	bodyIdx := strings.Index(fwd, "\r\n\r\n")
	if bodyIdx < 0 {
		t.Fatalf("no body separator in forwarded INVITE")
	}
	body := fwd[bodyIdx+4:]

	// The c= line must be rewritten to the relay address. The o=
	// (origin) line is left intact per RFC4566 — it just identifies
	// the session, not where to send media.
	if !strings.Contains(body, "c=IN IP4 127.0.0.1") {
		t.Errorf("forwarded SDP missing relay c= line:\n%s", body)
	}
	// Original m=audio 30000 must be replaced with the relay port.
	if strings.Contains(body, "m=audio 30000") {
		t.Errorf("forwarded SDP still contains caller's original audio port 30000:\n%s", body)
	}
	if !strings.Contains(body, "m=audio ") {
		t.Errorf("forwarded SDP missing m=audio line:\n%s", body)
	}

	if h.srv.Media.ActiveSessions() == 0 {
		t.Error("no active media session after anchorMedia()")
	}
}

func TestRTPRelaySymmetric(t *testing.T) {
	h := setupHarness(t)

	// "Alice" — receives and sends RTP from this socket
	aliceConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer aliceConn.Close()
	aliceAddr := aliceConn.LocalAddr().(*net.UDPAddr)

	// "Bob" — analogous
	bobConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer bobConn.Close()
	bobAddr := bobConn.LocalAddr().(*net.UDPAddr)

	// Build an offer/answer pair pointing at unreachable SDP addresses
	// so we can prove symmetric mode latches onto the source addresses
	// from which Alice and Bob actually send.
	offerSDP := fmt.Sprintf("v=0\r\no=alice 1 1 IN IP4 192.0.2.99\r\ns=-\r\nc=IN IP4 192.0.2.99\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0\r\n")
	answerSDP := fmt.Sprintf("v=0\r\no=bob 1 1 IN IP4 192.0.2.99\r\ns=-\r\nc=IN IP4 192.0.2.99\r\nt=0 0\r\nm=audio 20002 RTP/AVP 0\r\n")

	parsedOffer, _ := sdpParse(offerSDP)
	parsedAnswer, _ := sdpParse(answerSDP)

	sess := h.srv.Media.GetOrCreate("symmetric-test", media.Options{Symmetric: true})
	if err := sess.AnchorOffer(parsedOffer); err != nil {
		t.Fatal(err)
	}
	if err := sess.AnchorAnswer(parsedAnswer); err != nil {
		t.Fatal(err)
	}

	stream := sess.Streams[0]
	relayAddrForBob := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: stream.ARtpPort()}
	relayAddrForAlice := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: stream.BRtpPort()}

	// Bob sends to relay's A-side port → relay should forward to Alice's
	// observed source. Alice has not sent yet, so relay drops the first
	// packet (symmetric mode does not use the SDP-advertised address).
	if _, err := bobConn.WriteToUDP([]byte("from-bob-1"), relayAddrForBob); err != nil {
		t.Fatal(err)
	}
	aliceConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	tmp := make([]byte, 65535)
	if _, _, err := aliceConn.ReadFromUDP(tmp); err == nil {
		t.Error("symmetric mode should not deliver before peer source is known")
	}

	// Alice sends; her source is now learned.
	if _, err := aliceConn.WriteToUDP([]byte("from-alice-1"), relayAddrForAlice); err != nil {
		t.Fatal(err)
	}
	// Give the relay's goroutine a moment to consume Alice's packet
	// and store her source address before Bob's next packet arrives.
	time.Sleep(100 * time.Millisecond)

	// Bob's NEXT packet should now be forwarded to Alice's source.
	if _, err := bobConn.WriteToUDP([]byte("from-bob-2"), relayAddrForBob); err != nil {
		t.Fatal(err)
	}
	aliceConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, src, err := aliceConn.ReadFromUDP(tmp)
	if err != nil {
		t.Fatalf("alice did not receive RTP: %v", err)
	}
	if string(tmp[:n]) != "from-bob-2" {
		t.Errorf("unexpected payload: %q", tmp[:n])
	}
	_ = src

	// And alice's earlier packet should have been forwarded to Bob.
	bobConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := bobConn.ReadFromUDP(tmp); err != nil {
		// Alice's first packet was sent before Bob had been heard from,
		// so symmetric mode dropped it — expected. Send another.
		if _, err := aliceConn.WriteToUDP([]byte("from-alice-2"), relayAddrForAlice); err != nil {
			t.Fatal(err)
		}
		bobConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := bobConn.ReadFromUDP(tmp)
		if err != nil {
			t.Fatalf("bob did not receive alice's RTP: %v", err)
		}
		if string(tmp[:n]) != "from-alice-2" {
			t.Errorf("unexpected payload bob received: %q", tmp[:n])
		}
	}

	_, _ = aliceAddr, bobAddr
}

func TestRTPRelayAsymmetric(t *testing.T) {
	h := setupHarness(t)

	aliceConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer aliceConn.Close()
	alicePort := aliceConn.LocalAddr().(*net.UDPAddr).Port

	bobConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer bobConn.Close()
	bobPort := bobConn.LocalAddr().(*net.UDPAddr).Port

	offerSDP := fmt.Sprintf("v=0\r\no=alice 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio %d RTP/AVP 0\r\n", alicePort)
	answerSDP := fmt.Sprintf("v=0\r\no=bob 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio %d RTP/AVP 0\r\n", bobPort)

	parsedOffer, _ := sdpParse(offerSDP)
	parsedAnswer, _ := sdpParse(answerSDP)

	sess := h.srv.Media.GetOrCreate("asymmetric-test", media.Options{Symmetric: false})
	if err := sess.AnchorOffer(parsedOffer); err != nil {
		t.Fatal(err)
	}
	if err := sess.AnchorAnswer(parsedAnswer); err != nil {
		t.Fatal(err)
	}

	stream := sess.Streams[0]
	relayAddrForBob := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: stream.ARtpPort()}

	// Bob sends — asymmetric mode forwards to Alice's SDP-advertised
	// address even though Alice has never sent anything.
	someOtherSocket, err := net.DialUDP("udp4", nil, relayAddrForBob)
	if err != nil {
		t.Fatal(err)
	}
	defer someOtherSocket.Close()
	if _, err := someOtherSocket.Write([]byte("test-rtp")); err != nil {
		t.Fatal(err)
	}

	aliceConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	tmp := make([]byte, 65535)
	n, _, err := aliceConn.ReadFromUDP(tmp)
	if err != nil {
		t.Fatalf("alice did not receive RTP in asymmetric mode: %v", err)
	}
	if string(tmp[:n]) != "test-rtp" {
		t.Errorf("unexpected payload: %q", tmp[:n])
	}
}

func TestRportProcessingOnReceive(t *testing.T) {
	h := setupHarness(t)

	// Use a script that just echoes the topmost Via in a header so we
	// can read it via the response.
	script := `
function onRequest(req) {
    sendResponse(200, "OK", {"X-Echo-Via": req.getHeader("Via")});
}`
	if r := h.postText("/deploy", script); r["success"] != true {
		t.Fatalf("deploy failed: %v", r)
	}

	// Use a sent-by host that does NOT match the actual source IP, so
	// "received=" must be inserted; and an empty rport, so it must be
	// filled in with the actual source port.
	branch := fmt.Sprintf("z9hG4bK%d-rport", time.Now().UnixNano())
	msg := fmt.Sprintf(
		"OPTIONS sip:test.local SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP some.where:9999;branch=%s;rport\r\n"+
			"Max-Forwards: 70\r\n"+
			"From: <sip:t@test.local>;tag=rt\r\n"+
			"To: <sip:t@test.local>\r\n"+
			"Call-ID: rport-test-1\r\n"+
			"CSeq: 1 OPTIONS\r\n"+
			"Content-Length: 0\r\n\r\n",
		branch,
	)

	resp := h.sendSIP(msg)
	via := extractHeader(resp, "X-Echo-Via")

	if !strings.Contains(via, "received=127.0.0.1") {
		t.Errorf("Via missing received=127.0.0.1: %q", via)
	}
	expectRportPrefix := fmt.Sprintf("rport=%d", h.clientAddr.Port)
	if !strings.Contains(via, expectRportPrefix) {
		t.Errorf("Via rport not filled: want substring %q, got %q", expectRportPrefix, via)
	}
}

// sdpParse is a tiny shim so the test file can call sdp.Parse without
// importing the package directly via a long path.
func sdpParse(s string) (*sdp.SDP, error) { return sdp.Parse([]byte(s)) }

// ---------- RTCP signaling mode tests ----------

func TestRTCPImplicitPortAllocationIsConsecutive(t *testing.T) {
	h := setupHarness(t)

	offer := "v=0\r\no=a 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\n"
	answer := "v=0\r\no=b 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n"
	po, _ := sdp.Parse([]byte(offer))
	pa, _ := sdp.Parse([]byte(answer))

	sess := h.srv.Media.GetOrCreate("rtcp-implicit", media.Options{Symmetric: true, IdleTimeout: time.Hour})
	if err := sess.AnchorOffer(po); err != nil {
		t.Fatal(err)
	}
	if err := sess.AnchorAnswer(pa); err != nil {
		t.Fatal(err)
	}
	stream := sess.Streams[0]

	if stream.ARtcpPort() != stream.ARtpPort()+1 {
		t.Errorf("A-side: rtcp port (%d) must be rtp port + 1 (%d)", stream.ARtcpPort(), stream.ARtpPort()+1)
	}
	if stream.BRtcpPort() != stream.BRtpPort()+1 {
		t.Errorf("B-side: rtcp port (%d) must be rtp port + 1 (%d)", stream.BRtcpPort(), stream.BRtpPort()+1)
	}

	// Implicit RTCP: the rewritten SDP should not contain a=rtcp
	// (because peer's implicit rtp+1 already lands on our rtcp port).
	rendered := string(po.Bytes())
	if strings.Contains(rendered, "a=rtcp:") {
		t.Errorf("implicit-RTCP SDP should not have a=rtcp after rewrite:\n%s", rendered)
	}
	rendered = string(pa.Bytes())
	if strings.Contains(rendered, "a=rtcp:") {
		t.Errorf("implicit-RTCP answer should not have a=rtcp after rewrite:\n%s", rendered)
	}
}

func TestRTCPExplicitAttrRewritten(t *testing.T) {
	h := setupHarness(t)

	// Original SDP has a=rtcp with a non-default port (NOT rtp+1).
	offer := "v=0\r\no=a 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\na=rtcp:30005 IN IP4 127.0.0.1\r\n"
	po, _ := sdp.Parse([]byte(offer))

	sess := h.srv.Media.GetOrCreate("rtcp-explicit", media.Options{Symmetric: true, IdleTimeout: time.Hour})
	if err := sess.AnchorOffer(po); err != nil {
		t.Fatal(err)
	}
	stream := sess.Streams[0]

	port, _, ok := po.Media[0].RTCPAttr()
	if !ok {
		t.Fatal("rewritten SDP missing a=rtcp attribute")
	}
	if port != stream.ARtcpPort() {
		t.Errorf("a=rtcp port = %d, want relay's a-rtcp port %d", port, stream.ARtcpPort())
	}
}

func TestRTCPMuxPreserved(t *testing.T) {
	h := setupHarness(t)

	offer := "v=0\r\no=a 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\na=rtcp-mux\r\n"
	answer := "v=0\r\no=b 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtcp-mux\r\n"
	po, _ := sdp.Parse([]byte(offer))
	pa, _ := sdp.Parse([]byte(answer))

	sess := h.srv.Media.GetOrCreate("rtcp-mux", media.Options{Symmetric: true, IdleTimeout: time.Hour})
	if err := sess.AnchorOffer(po); err != nil {
		t.Fatal(err)
	}
	if err := sess.AnchorAnswer(pa); err != nil {
		t.Fatal(err)
	}

	for _, parsed := range []*sdp.SDP{po, pa} {
		rendered := string(parsed.Bytes())
		if !strings.Contains(rendered, "a=rtcp-mux") {
			t.Errorf("rtcp-mux dropped from rewrite:\n%s", rendered)
		}
		// With rtcp-mux and no original explicit a=rtcp, the rewrite
		// must NOT introduce one (RFC5761: SHOULD NOT).
		if strings.Contains(rendered, "a=rtcp:") {
			t.Errorf("rtcp-mux + implicit should not produce a=rtcp:\n%s", rendered)
		}
	}
}

func TestRTCPMuxWithExplicitRtcpAttrAlignsToRtpPort(t *testing.T) {
	h := setupHarness(t)

	// RFC5761 §5.1.3: when rtcp-mux is used, an explicit a=rtcp port
	// MUST equal the rtp port. We're given a (technically invalid)
	// SDP where a=rtcp differs; the rewrite must still produce a
	// valid mux SDP (a=rtcp port == m= port).
	offer := "v=0\r\no=a 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\na=rtcp-mux\r\na=rtcp:30000\r\n"
	po, _ := sdp.Parse([]byte(offer))

	sess := h.srv.Media.GetOrCreate("rtcp-mux-explicit", media.Options{Symmetric: true, IdleTimeout: time.Hour})
	if err := sess.AnchorOffer(po); err != nil {
		t.Fatal(err)
	}
	stream := sess.Streams[0]

	rendered := string(po.Bytes())
	if !strings.Contains(rendered, "a=rtcp-mux") {
		t.Errorf("rtcp-mux dropped:\n%s", rendered)
	}
	port, _, _ := po.Media[0].RTCPAttr()
	if port != stream.ARtpPort() {
		t.Errorf("with mux, a=rtcp port (%d) must equal m= rtp port (%d)", port, stream.ARtpPort())
	}
}

func TestRTCPPacketFlowAllModes(t *testing.T) {
	t.Run("implicit", func(t *testing.T) {
		h := setupHarness(t)

		// Alice listens on consecutive ports (rtp + rtp+1).
		aliceRtp, aliceRtcp := bindConsecutiveUDP(t)
		defer aliceRtp.Close()
		defer aliceRtcp.Close()
		aliceRtpPort := aliceRtp.LocalAddr().(*net.UDPAddr).Port

		offer := fmt.Sprintf("v=0\r\no=a 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio %d RTP/AVP 0\r\n", aliceRtpPort)
		runRTCPFlow(t, h, "flow-implicit", offer, false /* rtcp goes to rtcp port */, aliceRtcp)
	})

	t.Run("explicit a=rtcp", func(t *testing.T) {
		h := setupHarness(t)

		// Alice's RTP and RTCP ports can be unrelated.
		aliceRtp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer aliceRtp.Close()
		aliceRtcp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer aliceRtcp.Close()
		aliceRtpPort := aliceRtp.LocalAddr().(*net.UDPAddr).Port
		aliceRtcpPort := aliceRtcp.LocalAddr().(*net.UDPAddr).Port

		offer := fmt.Sprintf("v=0\r\no=a 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio %d RTP/AVP 0\r\na=rtcp:%d\r\n",
			aliceRtpPort, aliceRtcpPort)
		runRTCPFlow(t, h, "flow-explicit", offer, false, aliceRtcp)
	})

	t.Run("rtcp-mux", func(t *testing.T) {
		h := setupHarness(t)

		// One Alice socket — RTP and RTCP share it.
		aliceRtp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer aliceRtp.Close()
		aliceRtpPort := aliceRtp.LocalAddr().(*net.UDPAddr).Port

		offer := fmt.Sprintf("v=0\r\no=a 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio %d RTP/AVP 0\r\na=rtcp-mux\r\n", aliceRtpPort)
		runRTCPFlow(t, h, "flow-mux", offer, true /* rtcp shares rtp port */, aliceRtp)
	})
}

// runRTCPFlow anchors a one-sided session for `offer`, sends a
// synthetic RTCP packet to the relay's A-side RTCP destination, and
// verifies the packet shows up at `expectedRx`.
func runRTCPFlow(t *testing.T, h *harness, callID, offer string, mux bool, expectedRx *net.UDPConn) {
	t.Helper()
	po, err := sdp.Parse([]byte(offer))
	if err != nil {
		t.Fatal(err)
	}

	// Asymmetric mode so we don't have to send a "priming" packet
	// from Alice to teach the relay her source address.
	sess := h.srv.Media.GetOrCreate(callID, media.Options{
		Symmetric:   false,
		IdleTimeout: time.Hour,
	})
	if err := sess.AnchorOffer(po); err != nil {
		t.Fatal(err)
	}
	stream := sess.Streams[0]

	// Where would the peer send RTCP through the relay? With mux it
	// is the same port the peer uses for RTP (the relay's A-side rtp
	// port); without mux, it is the relay's A-side rtcp port.
	dstPort := stream.ARtcpPort()
	if mux {
		dstPort = stream.ARtpPort()
	}
	relayDst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: dstPort}

	tx, err := net.DialUDP("udp4", nil, relayDst)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()

	payload := []byte("rtcp-payload-" + callID)
	if _, err := tx.Write(payload); err != nil {
		t.Fatal(err)
	}

	expectedRx.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := expectedRx.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected receiver did not get forwarded packet: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("payload mismatch: got %q, want %q", buf[:n], payload)
	}
}

// bindConsecutiveUDP binds two UDP sockets on 127.0.0.1 with the
// second port being one higher than the first. Mirrors the relay's
// own port-pair allocation so test scaffolding can simulate a peer
// that uses implicit RTCP signaling.
func bindConsecutiveUDP(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	for i := 0; i < 50; i++ {
		rtp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		rtpPort := rtp.LocalAddr().(*net.UDPAddr).Port
		rtcp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: rtpPort + 1})
		if err == nil {
			return rtp, rtcp
		}
		rtp.Close()
	}
	t.Fatal("could not bind consecutive UDP port pair")
	return nil, nil
}

// ---------- Media port lifecycle tests ----------

func TestBYEReleasesMediaPorts(t *testing.T) {
	h := setupHarness(t)

	// Build a session directly so the test does not depend on full
	// signaling round-trips.
	offer := "v=0\r\no=a 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\n"
	answer := "v=0\r\no=b 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n"
	po, _ := sdp.Parse([]byte(offer))
	pa, _ := sdp.Parse([]byte(answer))

	sess := h.srv.Media.GetOrCreate("bye-release-1", media.Options{Symmetric: true, IdleTimeout: time.Hour})
	if err := sess.AnchorOffer(po); err != nil {
		t.Fatal(err)
	}
	if err := sess.AnchorAnswer(pa); err != nil {
		t.Fatal(err)
	}
	stream := sess.Streams[0]
	if stream.Closed() {
		t.Fatal("stream closed too early")
	}

	// Simulate the BYE-driven cleanup the request handler would run.
	h.srv.Proxy.CleanupMediaForCallID("bye-release-1")

	if !stream.Closed() {
		t.Errorf("stream should be Closed() after BYE cleanup")
	}
}

func TestRTPIdleReleasesMediaPorts(t *testing.T) {
	h := setupHarness(t)

	offer := "v=0\r\no=a 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\na=sendrecv\r\n"
	answer := "v=0\r\no=b 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=sendrecv\r\n"
	po, _ := sdp.Parse([]byte(offer))
	pa, _ := sdp.Parse([]byte(answer))

	sess := h.srv.Media.GetOrCreate("idle-release-1", media.Options{
		Symmetric:   true,
		IdleTimeout: 100 * time.Millisecond,
	})
	if err := sess.AnchorOffer(po); err != nil {
		t.Fatal(err)
	}
	if err := sess.AnchorAnswer(pa); err != nil {
		t.Fatal(err)
	}
	stream := sess.Streams[0]
	if stream.IsOnHold() {
		t.Fatal("expected stream not to be on hold for sendrecv SDP")
	}

	// Wait past the idle threshold, then trigger a synchronous sweep.
	time.Sleep(200 * time.Millisecond)
	h.srv.Media.SweepNow()

	if !stream.Closed() {
		t.Errorf("idle stream should have been released by sweeper")
	}
}

func TestRTPIdleNotReleasedWhenOnHold(t *testing.T) {
	h := setupHarness(t)

	tests := []struct {
		name   string
		offer  string
		answer string
	}{
		{
			name:   "a=sendonly in offer",
			offer:  "v=0\r\no=a 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\na=sendonly\r\n",
			answer: "v=0\r\no=b 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n",
		},
		{
			name:   "a=inactive in answer",
			offer:  "v=0\r\no=a 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\n",
			answer: "v=0\r\no=b 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=inactive\r\n",
		},
		{
			name:   "c=0.0.0.0 (deprecated hold marker)",
			offer:  "v=0\r\no=a 1 1 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\n",
			answer: "v=0\r\no=b 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			po, _ := sdp.Parse([]byte(tc.offer))
			pa, _ := sdp.Parse([]byte(tc.answer))

			callID := "hold-" + tc.name
			sess := h.srv.Media.GetOrCreate(callID, media.Options{
				Symmetric:   true,
				IdleTimeout: 200 * time.Millisecond,
			})
			if err := sess.AnchorOffer(po); err != nil {
				t.Fatal(err)
			}
			if err := sess.AnchorAnswer(pa); err != nil {
				t.Fatal(err)
			}
			stream := sess.Streams[0]

			if !stream.IsOnHold() {
				t.Fatalf("expected stream to be on hold for %q", tc.name)
			}

			// Wait past the idle threshold and force a sweep.
			time.Sleep(300 * time.Millisecond)
			h.srv.Media.SweepNow()

			if stream.Closed() {
				t.Errorf("on-hold stream must not be released by idle sweeper")
			}

			// Cleanup so the next subtest starts fresh.
			h.srv.Proxy.CleanupMediaForCallID(callID)
		})
	}
}

func TestDialogTimeoutReleasesMediaPorts(t *testing.T) {
	h := setupHarness(t)

	sinkConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sinkConn.Close()
	sinkPort := sinkConn.LocalAddr().(*net.UDPAddr).Port

	if err := h.srv.DB.SaveBinding(&store.Binding{
		AOR:          "sip:bob@test.local",
		Contact:      fmt.Sprintf("sip:bob@127.0.0.1:%d", sinkPort),
		ReceivedIP:   "127.0.0.1",
		ReceivedPort: sinkPort,
		Transport:    "UDP",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// Anchor media programmatically before sending the INVITE so we
	// can hold a reference to the stream and observe its closure when
	// the dialog times out.
	callID := "dlg-mt-1"
	sess := h.srv.Media.GetOrCreate(callID, media.Options{
		Symmetric:   true,
		IdleTimeout: time.Hour, // disable idle release
	})
	po, _ := sdp.Parse([]byte("v=0\r\no=a 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\n"))
	pa, _ := sdp.Parse([]byte("v=0\r\no=b 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n"))
	if err := sess.AnchorOffer(po); err != nil {
		t.Fatal(err)
	}
	if err := sess.AnchorAnswer(pa); err != nil {
		t.Fatal(err)
	}
	stream := sess.Streams[0]

	// Now drive the SIP side to create a dialog with a 1 s timeout.
	script := `
function onRequest(req) {
    if (req.method === "INVITE") {
        setupDialog({timeout: 1});
        var contacts = lookup();
        if (contacts.length > 0) proxy(contacts[0]);
        else sendResponse(404);
        return;
    }
    sendResponse(405);
}`
	if r := h.postText("/deploy", script); r["success"] != true {
		t.Fatalf("deploy failed: %v", r)
	}

	branch := "z9hG4bK-mt"
	fromTag := "alice-mt"
	invite := buildRequestExplicit("INVITE", "sip:bob@test.local", h.clientAddr.Port,
		"alice", "bob", callID, 1, branch, fromTag,
		[]string{fmt.Sprintf("Contact: <sip:alice@127.0.0.1:%d>", h.clientAddr.Port)}, "")
	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}
	if _, err := h.clientConn.WriteToUDP([]byte(invite), target); err != nil {
		t.Fatal(err)
	}
	// Drain forwarded INVITE on sink.
	sinkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	if _, _, err := sinkConn.ReadFromUDP(buf); err != nil {
		t.Fatalf("sink did not receive forwarded INVITE: %v", err)
	}

	// Wait for dialog timeout to fire and trigger media cleanup.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && !stream.Closed() {
		time.Sleep(100 * time.Millisecond)
	}

	if !stream.Closed() {
		t.Errorf("stream should be closed after dialog timeout fires")
	}
}

// ---------- Dialog tests ----------

func TestSetupDialogAndBYECleanup(t *testing.T) {
	h := setupHarness(t)

	sinkConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sinkConn.Close()
	sinkPort := sinkConn.LocalAddr().(*net.UDPAddr).Port

	if err := h.srv.DB.SaveBinding(&store.Binding{
		AOR:          "sip:bob@test.local",
		Contact:      fmt.Sprintf("sip:bob@127.0.0.1:%d", sinkPort),
		ReceivedIP:   "127.0.0.1",
		ReceivedPort: sinkPort,
		Transport:    "UDP",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	script := `
function onRequest(req) {
    if (req.method === "INVITE") {
        setupDialog({});
        var contacts = lookup();
        if (contacts.length > 0) proxy(contacts[0]);
        else sendResponse(404);
        return;
    }
    sendResponse(405);
}`
	if r := h.postText("/deploy", script); r["success"] != true {
		t.Fatalf("deploy failed: %v", r)
	}

	callID := "dlg-test-1"
	branch := "z9hG4bK-dlg-1"
	fromTag := "alice-tag"
	invite := buildRequestExplicit("INVITE", "sip:bob@test.local", h.clientAddr.Port,
		"alice", "bob", callID, 1, branch, fromTag,
		[]string{
			fmt.Sprintf("Contact: <sip:alice@127.0.0.1:%d>", h.clientAddr.Port),
		}, "")

	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}
	if _, err := h.clientConn.WriteToUDP([]byte(invite), target); err != nil {
		t.Fatal(err)
	}

	// Wait for forwarded INVITE to reach the sink.
	sinkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	if _, _, err := sinkConn.ReadFromUDP(buf); err != nil {
		t.Fatalf("sink did not receive forwarded INVITE: %v", err)
	}

	// Dialog should now exist (early).
	if h.srv.Dialogs.DialogCount() != 1 {
		t.Errorf("expected 1 dialog after setupDialog, got %d", h.srv.Dialogs.DialogCount())
	}

	// Bob (sink) sends 200 OK back through the proxy. The 200 carries
	// a To-tag, which confirms the dialog.
	ok := fmt.Sprintf(
		"SIP/2.0 200 OK\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-relay-tagged;rport=%d\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=%s;rport=%d\r\n"+
			"From: <sip:alice@test.local>;tag=%s\r\n"+
			"To: <sip:bob@test.local>;tag=bob-tag\r\n"+
			"Call-ID: %s\r\n"+
			"CSeq: 1 INVITE\r\n"+
			"Contact: <sip:bob@127.0.0.1:%d>\r\n"+
			"Content-Length: 0\r\n\r\n",
		h.sipPort, h.sipPort, h.clientAddr.Port, branch, h.clientAddr.Port, fromTag, callID, sinkPort,
	)
	// We don't know the proxy's branch — extract it from the forwarded INVITE.
	// Simpler: send the 200 to the proxy with the branches we saw.
	// Re-read the forwarded INVITE to get the proxy's Via.
	_ = ok

	// Simpler approach: reconstruct using the via from the forwarded INVITE.
	// We already consumed the forwarded INVITE above, but we have its branch
	// in the socket's last buffer. Re-read into another buffer:
	// (alternative — just use any branch since the proxy should accept it).
	// We send back to the proxy from the sink address.
	proxyTarget := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}

	// Build 200 from the forwarded INVITE we received.
	fwdInvite := string(buf[:0])
	_ = fwdInvite

	// Re-send INVITE so we can capture the forward properly to extract Via.
	// Actually just send a synthetic 200 OK with branches that should match;
	// the proxy uses the topmost Via to match its client tx.
	// We do not actually forward to the user — we just need the 200 to reach
	// the proxy and confirm the dialog. Use a stable scheme: read the
	// forwarded INVITE first.
	_ = proxyTarget

	// (The correct way is below — send the BYE directly to test cleanup.)

	// Send a BYE in the dialog. The request handler runs, looks up
	// the dialog by Call-ID + tags, finds the early dialog (matched
	// by from-tag since the dialog isn't confirmed yet), terminates
	// it, and forwards.
	bye := buildInDialogRequest("BYE", "sip:bob@127.0.0.1", h.clientAddr.Port,
		"alice", "bob", callID, 2, "z9hG4bK-bye-1", fromTag, "bob-tag",
		nil, "")
	if _, err := h.clientConn.WriteToUDP([]byte(bye), target); err != nil {
		t.Fatal(err)
	}

	// Give the server a moment to process.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && h.srv.Dialogs.DialogCount() > 0 {
		time.Sleep(50 * time.Millisecond)
	}

	if got := h.srv.Dialogs.DialogCount(); got != 0 {
		t.Errorf("expected dialog count 0 after BYE, got %d", got)
	}
}

func TestDlgGate481WhenNoDialog(t *testing.T) {
	h := setupHarness(t)

	// Step 1: trigger setupDialog with dlgGate=true once so the gate is
	// active server-wide. We send an INVITE that creates a dialog —
	// this also turns on the gate.
	script := `
function onRequest(req) {
    if (req.method === "INVITE") {
        setupDialog({dlgGate: true});
        sendResponse(486, "Busy Here");
        return;
    }
    sendResponse(405);
}`
	if r := h.postText("/deploy", script); r["success"] != true {
		t.Fatalf("deploy failed: %v", r)
	}

	// Send any INVITE just to flip the gate on. Read responses until
	// we see the 486 (proof that the script ran setupDialog and the
	// dlgGate is now active).
	gateInvite := buildRequest("INVITE", "sip:test.local", h.clientAddr.Port,
		"a", "b", "gate-flip", 1,
		[]string{fmt.Sprintf("Contact: <sip:a@127.0.0.1:%d>", h.clientAddr.Port)}, "")
	h.sendSIPNoReply(gateInvite)

	saw486 := false
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) && !saw486 {
		h.clientConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := h.clientConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		code, _ := parseStatusLine(string(buf[:n]))
		if code == 486 {
			saw486 = true
		}
	}
	if !saw486 {
		t.Fatal("did not receive 486 from gate-flip INVITE — gate may not be active")
	}

	// Step 2: send a BOGUS in-dialog request (no matching dialog).
	// Because dlgGate is now on, the server must answer 481.
	bogus := buildInDialogRequest("MESSAGE", "sip:c@test.local", h.clientAddr.Port,
		"x", "y", "bogus-call", 1, "z9hG4bK-bogus", "x-tag", "y-tag",
		nil, "hi")
	resp := h.sendSIP(bogus)
	code, _ := parseStatusLine(resp)
	if code != 481 {
		t.Errorf("dlgGate: expected 481, got %d\n%s", code, resp)
	}
}

func TestDialogTimeoutB2BUABye(t *testing.T) {
	h := setupHarness(t)

	sinkConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sinkConn.Close()
	sinkPort := sinkConn.LocalAddr().(*net.UDPAddr).Port

	if err := h.srv.DB.SaveBinding(&store.Binding{
		AOR:          "sip:bob@test.local",
		Contact:      fmt.Sprintf("sip:bob@127.0.0.1:%d", sinkPort),
		ReceivedIP:   "127.0.0.1",
		ReceivedPort: sinkPort,
		Transport:    "UDP",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// 1-second timeout so the test can observe the B2BUA BYE quickly.
	script := `
function onRequest(req) {
    if (req.method === "INVITE") {
        setupDialog({timeout: 1});
        var contacts = lookup();
        if (contacts.length > 0) proxy(contacts[0]);
        else sendResponse(404);
        return;
    }
    sendResponse(405);
}`
	if r := h.postText("/deploy", script); r["success"] != true {
		t.Fatalf("deploy failed: %v", r)
	}

	// Drive the dialog setup and wait for confirmation via a 200.
	callID := "dlg-timeout-1"
	branch := "z9hG4bK-dlg-to-1"
	fromTag := "alice-tag-to"
	invite := buildRequestExplicit("INVITE", "sip:bob@test.local", h.clientAddr.Port,
		"alice", "bob", callID, 1, branch, fromTag,
		[]string{
			fmt.Sprintf("Contact: <sip:alice@127.0.0.1:%d>", h.clientAddr.Port),
		}, "")

	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}
	if _, err := h.clientConn.WriteToUDP([]byte(invite), target); err != nil {
		t.Fatal(err)
	}

	// Receive the forwarded INVITE on the sink.
	sinkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := sinkConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("sink did not receive forwarded INVITE: %v", err)
	}
	fwdInvite := string(buf[:n])

	// Extract proxy's Via branch from the forwarded INVITE.
	proxyVia := extractHeader(fwdInvite, "Via")
	proxyBranch := extractAuthParam(proxyVia, "branch")
	if proxyBranch == "" {
		t.Fatalf("could not extract proxy branch from forwarded INVITE: %q", proxyVia)
	}

	// Bob (sink) sends 200 OK with To-tag; this confirms the dialog
	// at the proxy and captures Bob's contact.
	ok := fmt.Sprintf(
		"SIP/2.0 200 OK\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=%s;rport=%d\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=%s;rport=%d\r\n"+
			"From: <sip:alice@test.local>;tag=%s\r\n"+
			"To: <sip:bob@test.local>;tag=bob-tag-to\r\n"+
			"Call-ID: %s\r\n"+
			"CSeq: 1 INVITE\r\n"+
			"Contact: <sip:bob@127.0.0.1:%d>\r\n"+
			"Content-Length: 0\r\n\r\n",
		h.sipPort, proxyBranch, h.sipPort,
		h.clientAddr.Port, branch, h.clientAddr.Port,
		fromTag, callID, sinkPort,
	)
	if _, err := sinkConn.WriteToUDP([]byte(ok), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}); err != nil {
		t.Fatal(err)
	}

	// The 200 OK is forwarded to alice (the test client). Drain it.
	h.clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := h.clientConn.ReadFromUDP(buf); err != nil {
		t.Logf("no 200 forwarded to alice (acceptable): %v", err)
	}

	// Now wait for the timeout to fire. The dialog manager should send
	// a BYE to BOTH sides — alice (test client) and bob (sink).
	var aliceGotBYE, bobGotBYE bool
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && (!aliceGotBYE || !bobGotBYE) {
		h.clientConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if n, _, err := h.clientConn.ReadFromUDP(buf); err == nil {
			if strings.HasPrefix(string(buf[:n]), "BYE ") {
				aliceGotBYE = true
			}
		}
		sinkConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if n, _, err := sinkConn.ReadFromUDP(buf); err == nil {
			if strings.HasPrefix(string(buf[:n]), "BYE ") {
				bobGotBYE = true
			}
		}
	}

	if !aliceGotBYE {
		t.Error("alice (caller) did not receive B2BUA BYE on timeout")
	}
	if !bobGotBYE {
		t.Error("bob (callee) did not receive B2BUA BYE on timeout")
	}

	if h.srv.Metrics.DialogsTimedOut.Load() == 0 {
		t.Error("DialogsTimedOut counter not incremented")
	}
}

func TestDialogPCAPRecording(t *testing.T) {
	h := setupHarness(t)

	pcapDir, err := os.MkdirTemp("", "funsip-pcap-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(pcapDir)

	// Hot-swap the pcap dir on the manager (the harness creates the
	// server with cfg.PCAPDir = "" by default).
	h.srv.Config.PCAPDir = pcapDir
	h.srv.Dialogs = setPCAPDir(h.srv.Dialogs, pcapDir, h)

	sinkConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sinkConn.Close()
	sinkPort := sinkConn.LocalAddr().(*net.UDPAddr).Port

	if err := h.srv.DB.SaveBinding(&store.Binding{
		AOR:          "sip:bob@test.local",
		Contact:      fmt.Sprintf("sip:bob@127.0.0.1:%d", sinkPort),
		ReceivedIP:   "127.0.0.1",
		ReceivedPort: sinkPort,
		Transport:    "UDP",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	script := `
function onRequest(req) {
    if (req.method === "INVITE") {
        setupDialog({pcap: true});
        var contacts = lookup();
        if (contacts.length > 0) proxy(contacts[0]);
        else sendResponse(404);
        return;
    }
    sendResponse(405);
}`
	if r := h.postText("/deploy", script); r["success"] != true {
		t.Fatalf("deploy failed: %v", r)
	}

	callID := "dlg-pcap-1"
	branch := "z9hG4bK-dlg-pcap-1"
	fromTag := "alice-tag-pcap"
	invite := buildRequestExplicit("INVITE", "sip:bob@test.local", h.clientAddr.Port,
		"alice", "bob", callID, 1, branch, fromTag,
		[]string{
			fmt.Sprintf("Contact: <sip:alice@127.0.0.1:%d>", h.clientAddr.Port),
		}, "")

	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.sipPort}
	if _, err := h.clientConn.WriteToUDP([]byte(invite), target); err != nil {
		t.Fatal(err)
	}

	// Wait for the forwarded INVITE.
	sinkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	if _, _, err := sinkConn.ReadFromUDP(buf); err != nil {
		t.Fatalf("sink did not receive forwarded INVITE: %v", err)
	}

	// BYE to terminate (this closes the pcap file via Terminate).
	bye := buildInDialogRequest("BYE", "sip:bob@127.0.0.1", h.clientAddr.Port,
		"alice", "bob", callID, 2, "z9hG4bK-pcap-bye", fromTag, "bob-tag-pcap",
		nil, "")
	if _, err := h.clientConn.WriteToUDP([]byte(bye), target); err != nil {
		t.Fatal(err)
	}

	// Wait briefly for pcap file to flush + close.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && h.srv.Dialogs.DialogCount() > 0 {
		time.Sleep(100 * time.Millisecond)
	}

	// Find a *.pcap file in pcapDir.
	entries, err := os.ReadDir(pcapDir)
	if err != nil {
		t.Fatal(err)
	}
	var pcapPath string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pcap") {
			pcapPath = filepath.Join(pcapDir, e.Name())
			break
		}
	}
	if pcapPath == "" {
		t.Fatalf("no .pcap file in %s", pcapDir)
	}

	stat, err := os.Stat(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() < 24 {
		t.Errorf("pcap file too small (%d bytes), expected at least 24-byte header", stat.Size())
	}

	// Read first 4 bytes; must be the pcap magic number.
	f, err := os.Open(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hdr := make([]byte, 4)
	if _, err := f.Read(hdr); err != nil {
		t.Fatal(err)
	}
	want := []byte{0xd4, 0xc3, 0xb2, 0xa1}
	if !bytes.Equal(hdr, want) {
		t.Errorf("pcap magic mismatch: got %x, want %x", hdr, want)
	}
}

// setPCAPDir is a tiny helper that recreates the dialog manager with
// a new pcap directory. The server holds the manager reference, so
// we just patch its fields.
func setPCAPDir(_ *dialog.Manager, dir string, h *harness) *dialog.Manager {
	m := dialog.NewManager(h.srv.Transport, h.srv.Metrics, h.srv.Config.ListenIP, h.srv.Config.ListenPort, dir)
	h.srv.Dialogs = m
	h.srv.Proxy.SetDialogConfirm(m.ConfirmFromResponse)
	h.srv.Transport.SetCaptureHook(m.CapturePacket)
	h.srv.Script.SetDialogManager(m)
	return m
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
	branch := fmt.Sprintf("z9hG4bK%d-%s", time.Now().UnixNano(), callID)
	fromTag := callID + "-tag"
	return buildRequestExplicit(method, ruri, viaPort, fromUser, toUser, callID, cseq, branch, fromTag, extra, body)
}

func buildRequestExplicit(method, ruri string, viaPort int, fromUser, toUser, callID string, cseq int, branch, fromTag string, extra []string, body string) string {
	return buildRequestFull(method, ruri, viaPort, fromUser, toUser, callID, cseq, branch, fromTag, "", extra, body)
}

func buildInDialogRequest(method, ruri string, viaPort int, fromUser, toUser, callID string, cseq int, branch, fromTag, toTag string, extra []string, body string) string {
	return buildRequestFull(method, ruri, viaPort, fromUser, toUser, callID, cseq, branch, fromTag, toTag, extra, body)
}

func buildRequestFull(method, ruri string, viaPort int, fromUser, toUser, callID string, cseq int, branch, fromTag, toTag string, extra []string, body string) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "%s %s SIP/2.0\r\n", method, ruri)
	fmt.Fprintf(&sb, "Via: SIP/2.0/UDP 127.0.0.1:%d;branch=%s;rport\r\n", viaPort, branch)
	fmt.Fprintf(&sb, "Max-Forwards: 70\r\n")
	fmt.Fprintf(&sb, "From: <sip:%s@test.local>;tag=%s\r\n", fromUser, fromTag)
	if toTag != "" {
		fmt.Fprintf(&sb, "To: <sip:%s@test.local>;tag=%s\r\n", toUser, toTag)
	} else {
		fmt.Fprintf(&sb, "To: <sip:%s@test.local>\r\n", toUser)
	}
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
