// Package pcap implements a minimal asynchronous PCAP (libpcap) writer
// for capturing SIP signaling. The writer's hot path (Capture) is
// non-blocking: packets are pushed onto a bounded channel and the
// actual file writes happen on a dedicated goroutine that batches
// records before fsync. If the channel overflows, the packet is
// dropped — disk I/O never back-pressures into the SIP / RTP path.
//
// The link-layer type is LINKTYPE_RAW (101) — packets start with the
// IPv4 header, no ethernet/loopback wrapping. This keeps the writer
// independent from the OS link layer.
package pcap

import (
	"encoding/binary"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	pcapMagic    = 0xa1b2c3d4
	linktypeRaw  = 101
	defaultQueue = 1024
	flushBatch   = 64
	flushPeriod  = 100 * time.Millisecond
)

type Writer struct {
	path   string
	f      *os.File
	ch     chan capture
	done   chan struct{}
	closed atomic.Bool
	mu     sync.Mutex
	count  atomic.Uint64
	dropped atomic.Uint64
}

type capture struct {
	ts      time.Time
	srcIP   net.IP
	srcPort int
	dstIP   net.IP
	dstPort int
	payload []byte
}

func NewWriter(path string) (*Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], pcapMagic)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[8:], 0)
	binary.LittleEndian.PutUint32(hdr[12:], 0)
	binary.LittleEndian.PutUint32(hdr[16:], 65535)
	binary.LittleEndian.PutUint32(hdr[20:], linktypeRaw)
	if _, err := f.Write(hdr); err != nil {
		f.Close()
		return nil, err
	}

	w := &Writer{
		path: path,
		f:    f,
		ch:   make(chan capture, defaultQueue),
		done: make(chan struct{}),
	}
	go w.flushLoop()
	return w, nil
}

func (w *Writer) Path() string         { return w.path }
func (w *Writer) Captured() uint64     { return w.count.Load() }
func (w *Writer) Dropped() uint64      { return w.dropped.Load() }

// Capture queues a UDP packet to be written. It is safe to call from
// any goroutine and never blocks — overflowing packets are counted as
// dropped and discarded.
func (w *Writer) Capture(ts time.Time, srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, payload []byte) {
	if w.closed.Load() {
		return
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	pkt := capture{
		ts:      ts,
		srcIP:   srcIP,
		srcPort: srcPort,
		dstIP:   dstIP,
		dstPort: dstPort,
		payload: cp,
	}
	select {
	case w.ch <- pkt:
		w.count.Add(1)
	default:
		w.dropped.Add(1)
	}
}

func (w *Writer) flushLoop() {
	ticker := time.NewTicker(flushPeriod)
	defer ticker.Stop()

	pending := make([]capture, 0, flushBatch)

	flush := func() {
		if len(pending) == 0 {
			return
		}
		for _, c := range pending {
			w.writeOne(c)
		}
		_ = w.f.Sync()
		pending = pending[:0]
	}

	for {
		select {
		case c, ok := <-w.ch:
			if !ok {
				flush()
				_ = w.f.Close()
				close(w.done)
				return
			}
			pending = append(pending, c)
			if len(pending) >= flushBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (w *Writer) writeOne(c capture) {
	payload := c.payload
	udpLen := 8 + len(payload)
	ipLen := 20 + udpLen

	pkt := make([]byte, ipLen)

	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:], uint16(ipLen))
	binary.BigEndian.PutUint16(pkt[4:], 0)
	binary.BigEndian.PutUint16(pkt[6:], 0x4000)
	pkt[8] = 64
	pkt[9] = 17
	binary.BigEndian.PutUint16(pkt[10:], 0)

	src4 := c.srcIP.To4()
	dst4 := c.dstIP.To4()
	if src4 == nil {
		src4 = []byte{0, 0, 0, 0}
	}
	if dst4 == nil {
		dst4 = []byte{0, 0, 0, 0}
	}
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)

	binary.BigEndian.PutUint16(pkt[20:], uint16(c.srcPort))
	binary.BigEndian.PutUint16(pkt[22:], uint16(c.dstPort))
	binary.BigEndian.PutUint16(pkt[24:], uint16(udpLen))
	binary.BigEndian.PutUint16(pkt[26:], 0)

	copy(pkt[28:], payload)

	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[0:], uint32(c.ts.Unix()))
	binary.LittleEndian.PutUint32(rec[4:], uint32(c.ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(pkt)))

	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = w.f.Write(rec)
	_, _ = w.f.Write(pkt)
}

// Close drains the queue, fsyncs, and closes the file. After Close
// returns, no further writes will be accepted.
func (w *Writer) Close() {
	if w.closed.Swap(true) {
		return
	}
	close(w.ch)
	<-w.done
}
