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

// EncodePCMU compresses a slice of 16-bit linear PCM samples into
// G.711 µ-law bytes (one byte per sample). Used by the audio player
// when reading a 16-bit PCM WAV file and sending it as PT=0 RTP.
func EncodePCMU(in []int16) []byte {
	out := make([]byte, len(in))
	for i, s := range in {
		out[i] = ulawEncodeOne(s)
	}
	return out
}

// EncodePCMA is the A-law counterpart of EncodePCMU.
func EncodePCMA(in []int16) []byte {
	out := make([]byte, len(in))
	for i, s := range in {
		out[i] = alawEncodeOne(s)
	}
	return out
}

func ulawEncodeOne(s int16) byte {
	const bias = 0x84
	const clip = 32635
	sign := byte(0)
	v := int32(s)
	if v < 0 {
		v = -v
		sign = 0x80
	}
	if v > clip {
		v = clip
	}
	v += bias
	exp := byte(7)
	for mask := int32(0x4000); mask&v == 0 && exp > 0; mask >>= 1 {
		exp--
	}
	mantissa := byte((v >> (uint(exp) + 3)) & 0x0F)
	u := ^(sign | (exp << 4) | mantissa)
	return u
}

func alawEncodeOne(s int16) byte {
	v := int32(s)
	sign := byte(0)
	if v < 0 {
		v = -v - 1
		sign = 0x80
	} else {
		sign = 0
	}
	if v > 32767 {
		v = 32767
	}
	var compressed byte
	if v < 256 {
		compressed = byte(v >> 4)
	} else {
		exp := byte(1)
		for x := v >> 8; x > 1; x >>= 1 {
			exp++
		}
		mantissa := byte((v >> (uint(exp) + 3)) & 0x0F)
		compressed = (exp << 4) | mantissa
	}
	return (sign | compressed) ^ 0x55
}

// IsAudioPT reports whether the static RTP/AVP payload type is one
// the decoder supports.
func IsAudioPT(pt uint8) bool {
	return pt == PTPCMU || pt == PTPCMA
}
