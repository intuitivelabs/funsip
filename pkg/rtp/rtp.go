// Package rtp parses just enough of RFC3550 RTP and RFC4733 named
// telephone events for the media analyzer (DTMF, QoS, WAV recording)
// to do its work. It is NOT a full RTP stack — there is no jitter
// buffer, no SR/RR generation, no RTCP, no SRTP, no extensions.
package rtp

import "encoding/binary"

// Common static RTP/AVP payload types we care about.
const (
	PTPCMU = 0
	PTPCMA = 8
)

// Header is the parsed fixed RTP header (RFC3550 §5.1) plus the
// offset at which the payload starts (after CSRCs and the optional
// header extension).
type Header struct {
	Version       uint8
	Padding       bool
	Extension     bool
	CSRCCount     uint8
	Marker        bool
	PayloadType   uint8
	Sequence      uint16
	Timestamp     uint32
	SSRC          uint32
	PayloadOffset int
}

// Parse returns the parsed header or nil if the buffer is malformed.
// Only RTP version 2 is accepted.
func Parse(buf []byte) *Header {
	if len(buf) < 12 {
		return nil
	}
	h := &Header{
		Version:     buf[0] >> 6,
		Padding:     buf[0]&0x20 != 0,
		Extension:   buf[0]&0x10 != 0,
		CSRCCount:   buf[0] & 0x0f,
		Marker:      buf[1]&0x80 != 0,
		PayloadType: buf[1] & 0x7f,
		Sequence:    binary.BigEndian.Uint16(buf[2:4]),
		Timestamp:   binary.BigEndian.Uint32(buf[4:8]),
		SSRC:        binary.BigEndian.Uint32(buf[8:12]),
	}
	if h.Version != 2 {
		return nil
	}
	offset := 12 + int(h.CSRCCount)*4
	if h.Extension {
		if len(buf) < offset+4 {
			return nil
		}
		extLen := int(binary.BigEndian.Uint16(buf[offset+2 : offset+4]))
		offset += 4 + extLen*4
	}
	if offset > len(buf) {
		return nil
	}
	h.PayloadOffset = offset
	return h
}

// TelephoneEvent is the four-byte payload of an RFC4733 named
// telephone event. Volume is encoded as the dBm0 attenuation
// (0..63) — lower values mean a louder tone.
type TelephoneEvent struct {
	Event    uint8
	EndBit   bool
	Volume   uint8
	Duration uint16 // in RTP timestamp units
}

// ParseTelephoneEvent parses the RFC4733 telephone-event payload.
// Returns nil for short payloads.
func ParseTelephoneEvent(payload []byte) *TelephoneEvent {
	if len(payload) < 4 {
		return nil
	}
	return &TelephoneEvent{
		Event:    payload[0],
		EndBit:   payload[1]&0x80 != 0,
		Volume:   payload[1] & 0x3f,
		Duration: binary.BigEndian.Uint16(payload[2:4]),
	}
}

// EventDigit returns the printable label for a telephone-event code:
// "0".."9", "*", "#", "A".."D" for codes 0..15. Empty string for
// codes outside that range (e.g. flash hook = 16).
func EventDigit(e uint8) string {
	switch {
	case e <= 9:
		return string('0' + rune(e))
	case e == 10:
		return "*"
	case e == 11:
		return "#"
	case e >= 12 && e <= 15:
		return string('A' + rune(e-12))
	}
	return ""
}
