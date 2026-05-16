package play

// These thin wrappers exist to keep the WAV reader self-contained
// without pulling in pkg/rtp (which would create an import cycle if
// pkg/rtp ever depends on this package). The encoder/decoder
// implementations live in pkg/rtp/g711.go; we re-implement them
// here byte-for-byte so the play layer can be used standalone.

func decodeALawInline(in []byte) []int16 {
	out := make([]int16, len(in))
	for i, a := range in {
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
		out[i] = int16(sample)
	}
	return out
}

func encodeULawInline(in []int16) []byte {
	const bias = 0x84
	const clip = 32635
	out := make([]byte, len(in))
	for i, s := range in {
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
		out[i] = ^(sign | (exp << 4) | mantissa)
	}
	return out
}
