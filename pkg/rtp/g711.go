package rtp

// G.711 µ-law and A-law decoders, used to turn RTP audio payloads
// (1 byte per 8 kHz sample) into 16-bit linear PCM the WAV writer
// understands. Standard ITU-T G.711 inversion — no companding
// changes, no sample-rate conversion.

var (
	ulawTable [256]int16
	alawTable [256]int16
)

func init() {
	for i := 0; i < 256; i++ {
		ulawTable[i] = ulawDecodeOne(byte(i))
		alawTable[i] = alawDecodeOne(byte(i))
	}
}

func ulawDecodeOne(u byte) int16 {
	u = ^u
	sign := u & 0x80
	exponent := (u >> 4) & 0x07
	mantissa := u & 0x0f
	sample := int32(mantissa) << 4
	sample += 8
	sample <<= exponent
	sample -= 0x84
	if sign != 0 {
		sample = -sample
	}
	return int16(sample)
}

func alawDecodeOne(a byte) int16 {
	a ^= 0x55
	sign := a & 0x80
	exponent := (a >> 4) & 0x07
	mantissa := a & 0x0f
	var sample int32
	if exponent != 0 {
		sample = (int32(mantissa)<<4 + 0x108) << (exponent - 1)
	} else {
		sample = int32(mantissa)<<4 + 8
	}
	if sign != 0 {
		sample = -sample
	}
	return int16(sample)
}

// DecodePCMU expands a buffer of µ-law bytes into 16-bit PCM samples.
func DecodePCMU(in []byte) []int16 {
	out := make([]int16, len(in))
	for i, b := range in {
		out[i] = ulawTable[b]
	}
	return out
}

// DecodePCMA expands a buffer of A-law bytes into 16-bit PCM samples.
func DecodePCMA(in []byte) []int16 {
	out := make([]int16, len(in))
	for i, b := range in {
		out[i] = alawTable[b]
	}
	return out
}

// IsAudioPT reports whether the static RTP/AVP payload type is one
// the decoder supports.
func IsAudioPT(pt uint8) bool {
	return pt == PTPCMU || pt == PTPCMA
}
