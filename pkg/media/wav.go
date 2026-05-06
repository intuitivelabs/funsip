package media

import (
	"encoding/binary"
	"log"
	"os"
	"sync/atomic"
)

// wavWriter persists a stream of 16-bit mono PCM samples to a WAV
// (RIFF) file. The hot path (Push) drops sample slices onto a
// bounded channel and returns immediately; a worker goroutine writes
// them to disk so RTP relay is never blocked. On overflow the
// samples are dropped and a counter is bumped.
//
// The header is written with placeholder size fields up front and
// rewritten with the final byte counts when Close runs, after the
// queue has drained.
type wavWriter struct {
	path       string
	f          *os.File
	sampleRate uint32

	queue   chan []int16
	done    chan struct{}
	closed  atomic.Bool
	written atomic.Uint64 // number of samples written
	dropped atomic.Uint64
}

func newWavWriter(path string, sampleRate uint32) (*wavWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	// Reserve 44 bytes for the canonical PCM RIFF header; we'll
	// rewrite it with real sizes at Close time.
	if _, err := f.Write(make([]byte, 44)); err != nil {
		f.Close()
		return nil, err
	}

	w := &wavWriter{
		path:       path,
		f:          f,
		sampleRate: sampleRate,
		queue:      make(chan []int16, 256),
		done:       make(chan struct{}),
	}
	go w.worker()
	return w, nil
}

// Push enqueues PCM samples for asynchronous writing. Never blocks.
// Drops on overflow.
func (w *wavWriter) Push(samples []int16) {
	if w == nil || w.closed.Load() || len(samples) == 0 {
		return
	}
	cp := make([]int16, len(samples))
	copy(cp, samples)
	select {
	case w.queue <- cp:
	default:
		w.dropped.Add(1)
	}
}

func (w *wavWriter) worker() {
	buf := make([]byte, 0, 2048)
	for samples := range w.queue {
		buf = buf[:0]
		for _, s := range samples {
			buf = append(buf, byte(s), byte(s>>8))
		}
		if _, err := w.f.Write(buf); err != nil {
			log.Printf("[media/wav] write error on %s: %v", w.path, err)
			continue
		}
		w.written.Add(uint64(len(samples)))
	}
	w.finalize()
	close(w.done)
}

// finalize rewrites the RIFF header now that the final sample count
// is known, then closes the file.
func (w *wavWriter) finalize() {
	defer w.f.Close()

	samples := w.written.Load()
	dataSize := uint32(samples * 2) // 16-bit
	if dataSize > 0xFFFFFFFF-36 {
		dataSize = 0xFFFFFFFF - 36
	}
	fileSize := 36 + dataSize

	hdr := make([]byte, 44)
	copy(hdr[0:4], "RIFF")
	binary.LittleEndian.PutUint32(hdr[4:8], fileSize)
	copy(hdr[8:12], "WAVE")
	copy(hdr[12:16], "fmt ")
	binary.LittleEndian.PutUint32(hdr[16:20], 16)             // fmt chunk size
	binary.LittleEndian.PutUint16(hdr[20:22], 1)              // PCM
	binary.LittleEndian.PutUint16(hdr[22:24], 1)              // mono
	binary.LittleEndian.PutUint32(hdr[24:28], w.sampleRate)
	binary.LittleEndian.PutUint32(hdr[28:32], w.sampleRate*2) // byte rate
	binary.LittleEndian.PutUint16(hdr[32:34], 2)              // block align
	binary.LittleEndian.PutUint16(hdr[34:36], 16)             // bits/sample
	copy(hdr[36:40], "data")
	binary.LittleEndian.PutUint32(hdr[40:44], dataSize)

	if _, err := w.f.Seek(0, 0); err != nil {
		return
	}
	_, _ = w.f.Write(hdr)
}

// Close drains the queue and finalizes the file. Subsequent Push
// calls become no-ops.
func (w *wavWriter) Close() {
	if w == nil || w.closed.Swap(true) {
		return
	}
	close(w.queue)
	<-w.done
}

// Path returns the filesystem path of the WAV file.
func (w *wavWriter) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}
