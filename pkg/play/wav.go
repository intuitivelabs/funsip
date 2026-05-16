// Package play streams an audio file to an RTP destination at 8 kHz
// G.711 µ-law. It is the playback half of the WAV writer in
// pkg/media — see Session for the orchestration that ties it to a
// SIP INVITE answered with a 200 + SDP.
package play

import (
	"encoding/binary"
	"fmt"
	"os"
)

// Wave format codes we recognize.
const (
	wavFmtPCM   uint16 = 1
	wavFmtALaw  uint16 = 6
	wavFmtULaw  uint16 = 7
)

// wavFile is a streaming reader over a RIFF/WAVE file. It exposes
// 160-byte G.711 µ-law payloads (20 ms at 8 kHz) regardless of how
// the underlying file is encoded — 16-bit PCM samples are converted
// on the fly. Only mono 8 kHz audio is supported; other shapes
// fail at Open() time so the script writer gets a clear error.
type wavFile struct {
	f         *os.File
	format    uint16 // 1 = PCM, 6 = A-law, 7 = µ-law
	sampleBytes int  // bytes per sample
	dataLeft  int64  // remaining bytes in the data chunk
	pcmBuf    []int16
}

func openWav(path string) (*wavFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// RIFF header
	hdr := make([]byte, 12)
	if _, err := f.Read(hdr); err != nil {
		f.Close()
		return nil, fmt.Errorf("read RIFF header: %w", err)
	}
	if string(hdr[0:4]) != "RIFF" || string(hdr[8:12]) != "WAVE" {
		f.Close()
		return nil, fmt.Errorf("not a RIFF/WAVE file")
	}

	var (
		format      uint16
		channels    uint16
		sampleRate  uint32
		bitsPerSamp uint16
		dataLen     int64
		seenFmt     bool
		seenData    bool
	)

	for !seenData {
		chunkHdr := make([]byte, 8)
		if _, err := f.Read(chunkHdr); err != nil {
			f.Close()
			return nil, fmt.Errorf("read chunk header: %w", err)
		}
		chunkID := string(chunkHdr[0:4])
		chunkSize := binary.LittleEndian.Uint32(chunkHdr[4:8])

		switch chunkID {
		case "fmt ":
			body := make([]byte, chunkSize)
			if _, err := f.Read(body); err != nil {
				f.Close()
				return nil, fmt.Errorf("read fmt chunk: %w", err)
			}
			if len(body) < 16 {
				f.Close()
				return nil, fmt.Errorf("fmt chunk too short: %d", len(body))
			}
			format = binary.LittleEndian.Uint16(body[0:2])
			channels = binary.LittleEndian.Uint16(body[2:4])
			sampleRate = binary.LittleEndian.Uint32(body[4:8])
			bitsPerSamp = binary.LittleEndian.Uint16(body[14:16])
			seenFmt = true
		case "data":
			dataLen = int64(chunkSize)
			seenData = true
		default:
			// Skip unknown chunks.
			if _, err := f.Seek(int64(chunkSize), 1); err != nil {
				f.Close()
				return nil, fmt.Errorf("skip chunk %s: %w", chunkID, err)
			}
		}
	}

	if !seenFmt {
		f.Close()
		return nil, fmt.Errorf("no fmt chunk")
	}
	if channels != 1 {
		f.Close()
		return nil, fmt.Errorf("only mono is supported (got %d channels)", channels)
	}
	if sampleRate != 8000 {
		f.Close()
		return nil, fmt.Errorf("only 8000 Hz is supported (got %d Hz)", sampleRate)
	}

	w := &wavFile{
		f:        f,
		format:   format,
		dataLeft: dataLen,
	}
	switch format {
	case wavFmtPCM:
		if bitsPerSamp != 16 {
			f.Close()
			return nil, fmt.Errorf("only 16-bit PCM is supported (got %d bits)", bitsPerSamp)
		}
		w.sampleBytes = 2
	case wavFmtULaw, wavFmtALaw:
		w.sampleBytes = 1
	default:
		f.Close()
		return nil, fmt.Errorf("unsupported WAV format code: %d", format)
	}
	return w, nil
}

// nextFrame returns the next 160 µ-law samples (20 ms at 8 kHz). On
// EOF returns (nil, nil).
func (w *wavFile) nextFrame() ([]byte, error) {
	const samplesPerFrame = 160
	const frameBytes = samplesPerFrame // µ-law is one byte per sample
	if w.dataLeft <= 0 {
		return nil, nil
	}

	switch w.format {
	case wavFmtULaw:
		buf := make([]byte, frameBytes)
		n, err := readN(w.f, buf, &w.dataLeft)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil

	case wavFmtALaw:
		// Decode to PCM, then re-encode to µ-law. Simpler than
		// shipping an A-law payload type for our 200 OK.
		buf := make([]byte, frameBytes)
		n, err := readN(w.f, buf, &w.dataLeft)
		if err != nil {
			return nil, err
		}
		pcm := decodeALawInline(buf[:n])
		return encodeULawInline(pcm), nil

	case wavFmtPCM:
		// 16-bit little-endian PCM → µ-law.
		raw := make([]byte, 2*samplesPerFrame)
		n, err := readN(w.f, raw, &w.dataLeft)
		if err != nil {
			return nil, err
		}
		samples := n / 2
		pcm := w.pcmBuf
		if cap(pcm) < samples {
			pcm = make([]int16, samples)
		} else {
			pcm = pcm[:samples]
		}
		for i := 0; i < samples; i++ {
			pcm[i] = int16(binary.LittleEndian.Uint16(raw[i*2 : i*2+2]))
		}
		w.pcmBuf = pcm
		return encodeULawInline(pcm), nil
	}
	return nil, fmt.Errorf("unsupported format %d", w.format)
}

func readN(f *os.File, buf []byte, left *int64) (int, error) {
	want := int64(len(buf))
	if want > *left {
		want = *left
	}
	if want == 0 {
		return 0, nil
	}
	n, err := f.Read(buf[:want])
	if n > 0 {
		*left -= int64(n)
	}
	if err != nil {
		// EOF mid-frame is fine; the caller treats short reads as
		// end of the file.
		return n, nil
	}
	return n, nil
}

func (w *wavFile) Close() {
	if w != nil && w.f != nil {
		w.f.Close()
	}
}
