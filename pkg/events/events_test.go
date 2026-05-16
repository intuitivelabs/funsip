package events

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/intuitivelabs/funsip/pkg/sip"
)

func parseReq(t *testing.T, raw string) *sip.Message {
	t.Helper()
	msg, err := sip.ParseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

const sampleInvite = "INVITE sip:bob@test.local SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP 1.1.1.1:5060;branch=z9hG4bK-xxx\r\n" +
	"Max-Forwards: 70\r\n" +
	"From: <sip:alice@test.local>;tag=a-tag\r\n" +
	"To: <sip:bob@test.local>\r\n" +
	"Call-ID: sig-test-1\r\n" +
	"CSeq: 1 INVITE\r\n" +
	"Contact: <sip:alice@1.1.1.1:5060>\r\n" +
	"User-Agent: funsip-tester\r\n" +
	"Content-Length: 0\r\n\r\n"

func TestSignatureIsStableAcrossSameRequest(t *testing.T) {
	a := Signature(parseReq(t, sampleInvite))
	b := Signature(parseReq(t, sampleInvite))
	if a != b {
		t.Errorf("signature is not stable: %q vs %q", a, b)
	}
	if a == "" {
		t.Fatal("signature should not be empty")
	}
}

func TestSignatureFormat(t *testing.T) {
	sig := Signature(parseReq(t, sampleInvite))
	// Expect: <METHOD>:<hdrcodes>:<12-hex>
	parts := strings.Split(sig, ":")
	if len(parts) != 3 {
		t.Fatalf("signature %q must be METHOD:hdrs:hash", sig)
	}
	if parts[0] != "INVITE" {
		t.Errorf("first segment: want INVITE, got %q", parts[0])
	}
	// Header codes must mention Via (V), From (F), To (T), Call-ID
	// (I), CSeq (C), Contact (O), Max-Forwards (M), User-Agent (U)
	for _, c := range "VFTICOMU" {
		if !strings.ContainsRune(parts[1], c) {
			t.Errorf("hdrcodes %q missing %c", parts[1], c)
		}
	}
	if len(parts[2]) != 12 {
		t.Errorf("hash segment length: want 12, got %d (%q)", len(parts[2]), parts[2])
	}
}

func TestSignatureChangesWithRequestChange(t *testing.T) {
	a := Signature(parseReq(t, sampleInvite))
	differentCallID := strings.Replace(sampleInvite, "Call-ID: sig-test-1", "Call-ID: sig-test-2", 1)
	b := Signature(parseReq(t, differentCallID))
	if a == b {
		t.Error("signature should depend on Call-ID")
	}
}

func TestEventFromRequestHasExpectedKeys(t *testing.T) {
	ev := FromRequest("call-attempt", parseReq(t, sampleInvite))

	mustString := []string{
		"@timestamp", "type", "sip.call_id", "sip.request.method",
		"sip.request.sig", "sip.fromtag", "sip.from", "sip.to",
		"client.ip", "client.transport",
		"attrs.method", "attrs.call-id", "attrs.from", "attrs.to",
	}
	for _, k := range mustString {
		if _, ok := ev[k]; !ok {
			t.Errorf("missing key %q in event:\n%+v", k, ev)
		}
	}
	if ev["type"] != "call-attempt" {
		t.Errorf("type: want call-attempt, got %v", ev["type"])
	}
	if ev["sip.request.method"] != "INVITE" {
		t.Errorf("sip.request.method: want INVITE, got %v", ev["sip.request.method"])
	}

	// Verify it round-trips through JSON without any structural
	// changes — Elasticsearch / sipcmbeat expect this exact flat
	// dotted-key layout on the wire.
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var back Event
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back["sip.request.sig"] != ev["sip.request.sig"] {
		t.Errorf("round-trip lost sip.request.sig")
	}
}

func TestEventWithResponseAndDuration(t *testing.T) {
	ev := FromRequest("call-end", parseReq(t, sampleInvite)).
		WithResponse(486, "Busy Here").
		WithDuration(42*1000_000_000, "callee-terminated")

	if ev["sip.response.status"] != 486 {
		t.Errorf("response status: %v", ev["sip.response.status"])
	}
	if ev["sip.response.last"] != 486 {
		t.Errorf("response last: %v", ev["sip.response.last"])
	}
	if ev["sip.originator"] != "callee-terminated" {
		t.Errorf("originator: %v", ev["sip.originator"])
	}
	if ev["event.duration"] != int64(42) {
		t.Errorf("event.duration: want 42, got %v", ev["event.duration"])
	}
}
