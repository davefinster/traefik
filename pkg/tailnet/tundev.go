package tailnet

import (
	"os"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
)

// tunMTU is the MTU both stacks agree on. It matches the tsnet default, so
// the tailnet node's own path and the path through this device fragment
// alike.
const tunMTU = 1500

// tunQueueDepth bounds each direction. A queue rather than a rendezvous, so
// a brief stall on one side does not block the other; deep enough to absorb
// a burst, shallow enough that a wedged reader drops packets instead of
// growing without limit. Dropping is the right failure for a network device.
const tunQueueDepth = 512

// memTUN is an in-memory tun.Device: the seam between the tailnet node's
// network stack and ours.
//
// The tailnet node writes here the packets its own netstack declined —  for a
// Tailscale Service in TUN mode, that is everything addressed to the
// Service's virtual IPs. Those become this device's inbound queue, which the
// local stack picks up. Replies travel the other way: the local stack queues
// them here and the node reads them as though they came from an operating
// system, and sends them to the peer over WireGuard.
//
// A tun.Device is expected to be an operating system's network interface. The
// point of this one is that there is no operating system in the path: both
// ends are in this process, so the Service's traffic is carried entirely in
// userspace with no TUN device, no NET_ADMIN and no host routing.
type memTUN struct {
	// inbound carries packets from the tailnet node towards the local stack.
	inbound chan []byte
	// outbound carries packets from the local stack towards the tailnet node.
	outbound chan []byte

	events chan tun.Event

	closeOnce sync.Once
	closed    chan struct{}
}

func newMemTUN() *memTUN {
	return &memTUN{
		inbound:  make(chan []byte, tunQueueDepth),
		outbound: make(chan []byte, tunQueueDepth),
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
	}
}

// File has no meaning for a device that is not a file. tsnet's own fake TUN
// panics here; returning nil is the same statement without the crash, and
// nothing on this path calls it.
func (t *memTUN) File() *os.File { return nil }

// Read hands the tailnet node packets the local stack has produced. It
// blocks until there is one, which is what wireguard-go's reader expects.
func (t *memTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}

	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case pkt := <-t.outbound:
		n := copy(bufs[0][offset:], pkt)
		sizes[0] = n
		return 1, nil
	}
}

// Write takes the packets the tailnet node's netstack declined. The buffers
// belong to the caller and are reused, so each packet is copied out before
// it is queued.
func (t *memTUN) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	default:
	}

	written := 0
	for _, buf := range bufs {
		if len(buf) <= offset {
			continue
		}

		pkt := make([]byte, len(buf)-offset)
		copy(pkt, buf[offset:])

		select {
		case t.inbound <- pkt:
			written++
		case <-t.closed:
			return written, os.ErrClosed
		default:
			// The local stack is not keeping up. Drop, as a network device
			// does, rather than block the tailnet node's packet loop and
			// stall every other flow it carries.
			written++
		}
	}

	return written, nil
}

func (t *memTUN) MTU() (int, error)        { return tunMTU, nil }
func (t *memTUN) Name() (string, error)    { return "traefik-tailnet", nil }
func (t *memTUN) Events() <-chan tun.Event { return t.events }
func (t *memTUN) BatchSize() int           { return 1 }

func (t *memTUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

// send queues a packet from the local stack for the tailnet node to read.
// It drops rather than blocks, for the same reason Write does.
func (t *memTUN) send(pkt []byte) {
	select {
	case t.outbound <- pkt:
	case <-t.closed:
	default:
	}
}

// receive returns the next packet from the tailnet node, or false once the
// device is closed.
func (t *memTUN) receive() ([]byte, bool) {
	select {
	case pkt := <-t.inbound:
		return pkt, true
	case <-t.closed:
		return nil, false
	}
}
