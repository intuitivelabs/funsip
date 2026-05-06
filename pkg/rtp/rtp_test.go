package rtp

import "testing"

func TestParseMinimalHeader(t *testing.T) {
	pkt := []byte{
		0x80, 0x00, 0x00, 0x01, // V=2, PT=0, seq=1
		0x00, 0x00, 0x00, 0xa0, // ts=160
		0xde, 0xad, 0xbe, 0xef, // ssrc
		0x11, 0x22, // payload
	}
	h := Parse(pkt)
	if h == nil {
		t.Fatal("Parse returned nil")
	}
	if h.Version != 2 {
		t.Errorf("Version=%d, want 2", h.Version)
	}
	if h.PayloadType != 0 {
		t.Errorf("PT=%d, want 0", h.PayloadType)
	}
	if h.Sequence != 1 {
		t.Errorf("seq=%d, want 1", h.Sequence)
	}
	if h.Timestamp != 160 {
		t.Errorf("ts=%d, want 160", h.Timestamp)
	}
	if h.SSRC != 0xdeadbeef {
		t.Errorf("ssrc=%x, want deadbeef", h.SSRC)
	}
	if h.PayloadOffset != 12 {
		t.Errorf("PayloadOffset=%d, want 12", h.PayloadOffset)
	}
}

func TestParseRejectsV1(t *testing.T) {
	pkt := make([]byte, 12)
	pkt[0] = 0x40 // version 1
	if Parse(pkt) != nil {
		t.Error("Parse accepted RTPv1")
	}
}

func TestParseTelephoneEvent(t *testing.T) {
	// digit 5, end-bit, volume 10, duration 320 (40 ms @ 8kHz)
	payload := []byte{0x05, 0x80 | 10, 0x01, 0x40}
	e := ParseTelephoneEvent(payload)
	if e == nil {
		t.Fatal("nil")
	}
	if e.Event != 5 {
		t.Errorf("event=%d", e.Event)
	}
	if !e.EndBit {
		t.Error("end bit not set")
	}
	if e.Volume != 10 {
		t.Errorf("volume=%d", e.Volume)
	}
	if e.Duration != 320 {
		t.Errorf("duration=%d", e.Duration)
	}
}

func TestEventDigit(t *testing.T) {
	cases := map[uint8]string{
		0:  "0",
		9:  "9",
		10: "*",
		11: "#",
		12: "A",
		15: "D",
		16: "",
	}
	for code, want := range cases {
		if got := EventDigit(code); got != want {
			t.Errorf("EventDigit(%d)=%q, want %q", code, got, want)
		}
	}
}

func TestG711UlawDecodes(t *testing.T) {
	// 0xFF (negative-zero in µ-law) is the lowest-amplitude negative
	// sample — well within ±256.
	if v := DecodePCMU([]byte{0xFF})[0]; v < -256 || v > 256 {
		t.Errorf("0xFF µ-law = %d, want a low-amplitude sample", v)
	}
	// 0x7F (positive-zero in µ-law) is the lowest-amplitude positive.
	if v := DecodePCMU([]byte{0x7F})[0]; v < -256 || v > 256 {
		t.Errorf("0x7F µ-law = %d, want a low-amplitude sample", v)
	}
	// 0x00 / 0x80 are loud (segment 7) — magnitude near full-scale.
	if v := DecodePCMU([]byte{0x00})[0]; abs16(v) < 16000 {
		t.Errorf("0x00 µ-law = %d, expected a loud sample", v)
	}
}

func abs16(v int16) int32 {
	if v < 0 {
		return -int32(v)
	}
	return int32(v)
}

func TestG711AlawDecodes(t *testing.T) {
	// 0xD5 ^ 0x55 = 0x80; the sign bit alone is the lowest-amplitude
	// negative sample, so the decode should be small in magnitude.
	v := DecodePCMA([]byte{0xD5})[0]
	if v < -16 || v > 16 {
		t.Errorf("0xD5 A-law = %d, want low-amplitude near zero", v)
	}
	// 0x55 ^ 0x55 = 0x00 — segment 0 positive, smallest positive.
	if v := DecodePCMA([]byte{0x55})[0]; v <= 0 || v > 16 {
		t.Errorf("0x55 A-law = %d, want small positive", v)
	}
}
