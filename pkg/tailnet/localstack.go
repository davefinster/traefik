package tailnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/rs/zerolog/log"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// localNICID is the single interface of the local stack. It carries every
// address this node answers for that the tailnet node's own stack will not.
const localNICID tcpip.NICID = 1

// localStack is the network stack that terminates a Tailscale Service's
// traffic in this process.
//
// A Service in TUN mode is advertised on every port and every protocol, and
// in exchange the tailnet node's netstack stops handling it: the packets are
// released towards what would ordinarily be the operating system. There is no
// operating system here, so they arrive at memTUN instead and this stack
// plays the part — it holds the Service's virtual IPs, accepts connections
// on them and answers them, all in userspace.
//
// Traffic for the node's advertised routes takes the same path, because a
// node given a device stops taking subnet traffic into its own netstack, so
// an entryPoint bound to a routed address listens here as well.
//
// It is the only way to serve TCP on a Service VIP from an embedded node.
// tsnet's netstack intercepts VIP TCP only for ports a serve-config handler
// claims, and TUN mode forbids those handlers, so a Service that advertises
// UDP can never also serve TCP through tsnet. Here both are ordinary
// listeners on one stack.
type localStack struct {
	ipstack *stack.Stack
	link    *channel.Endpoint
	dev     *memTUN

	mu        sync.Mutex
	addrs     map[netip.Addr]bool
	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// newLocalStack builds the stack and starts pumping packets between it and
// the device. It holds no addresses until addAddr is called.
func newLocalStack(dev *memTUN) (*localStack, error) {
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})

	// The same three settings tailscale applies to its own gVisor stack, for
	// the same reasons: SACK is off by default; gVisor's RACK handles ACKs
	// poorly and causes spurious retransmissions; and cubic can overflow
	// gVisor's congestion window arithmetic, so reno is pinned rather than
	// left to the default.
	sack := tcpip.TCPSACKEnabled(true)
	if err := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, fmt.Errorf("enabling TCP SACK: %v", err)
	}
	recovery := tcpip.TCPRecovery(0)
	if err := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &recovery); err != nil {
		return nil, fmt.Errorf("disabling TCP RACK: %v", err)
	}
	reno := tcpip.CongestionControlOption("reno")
	if err := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &reno); err != nil {
		return nil, fmt.Errorf("setting reno congestion control: %v", err)
	}

	link := channel.New(tunQueueDepth, tunMTU, "")
	if err := ipstack.CreateNIC(localNICID, link); err != nil {
		return nil, fmt.Errorf("creating NIC: %v", err)
	}

	// The Service's addresses are the only reason a packet reaches this
	// stack, and they are not on any subnet it knows, so everything is
	// routed out of the one interface.
	ipstack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: localNICID},
		{Destination: header.IPv6EmptySubnet, NIC: localNICID},
	})

	// Accept packets addressed to an IP this NIC does not hold. Without it
	// gVisor drops the Service's traffic before a listener ever sees it,
	// because the destination is a virtual IP the stack was not told about
	// until the netmap arrived.
	ipstack.SetPromiscuousMode(localNICID, true)
	ipstack.SetSpoofing(localNICID, true)

	s := &localStack{
		ipstack: ipstack,
		link:    link,
		dev:     dev,
		addrs:   map[netip.Addr]bool{},
		done:    make(chan struct{}),
	}

	s.wg.Add(2)
	go s.pumpToDevice()
	go s.pumpFromDevice()

	return s, nil
}

// pumpToDevice carries packets this stack produces out to the tailnet node.
func (s *localStack) pumpToDevice() {
	defer s.wg.Done()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-s.done
		cancel()
	}()

	for {
		pkt := s.link.ReadContext(ctx)
		if pkt == nil {
			return
		}

		view := pkt.ToView()
		buf := make([]byte, view.Size())
		copy(buf, view.AsSlice())
		view.Release()
		pkt.DecRef()

		s.dev.send(buf)
	}
}

// pumpFromDevice carries packets the tailnet node released into this stack.
func (s *localStack) pumpFromDevice() {
	defer s.wg.Done()

	for {
		// Watching done as well as the device: the stack is released on its
		// own when a join fails, and the device may never be closed then.
		pkt, ok := s.dev.receive(s.done)
		if !ok {
			return
		}

		proto, ok := ipVersion(pkt)
		if !ok {
			continue
		}

		buf := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(pkt),
		})
		s.link.InjectInbound(proto, buf)
		buf.DecRef()
	}
}

// addAddr gives the stack one of the addresses it should answer for.
func (s *localStack) addAddr(addr netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.addrs[addr] {
		return nil
	}

	proto := ipv4.ProtocolNumber
	if addr.Is6() {
		proto = ipv6.ProtocolNumber
	}

	protoAddr := tcpip.ProtocolAddress{
		Protocol: proto,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(addr.AsSlice()),
			PrefixLen: addr.BitLen(),
		},
	}
	if err := s.ipstack.AddProtocolAddress(localNICID, protoAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("adding address %s: %v", addr, err)
	}

	s.addrs[addr] = true
	log.Debug().Stringer("address", addr).Msg("Local tailnet stack holds address")

	return nil
}

// listenTCP accepts TCP on one of the stack's addresses.
func (s *localStack) listenTCP(addr netip.AddrPort) (net.Listener, error) {
	proto := ipv4.ProtocolNumber
	if addr.Addr().Is6() {
		proto = ipv6.ProtocolNumber
	}

	full := tcpip.FullAddress{
		NIC:  localNICID,
		Addr: tcpip.AddrFromSlice(addr.Addr().AsSlice()),
		Port: addr.Port(),
	}

	ln, err := gonet.ListenTCP(s.ipstack, full, proto)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", addr, err)
	}
	return ln, nil
}

// listenUDP accepts UDP on one of the stack's addresses.
func (s *localStack) listenUDP(addr netip.AddrPort) (net.PacketConn, error) {
	proto := ipv4.ProtocolNumber
	if addr.Addr().Is6() {
		proto = ipv6.ProtocolNumber
	}

	full := tcpip.FullAddress{
		NIC:  localNICID,
		Addr: tcpip.AddrFromSlice(addr.Addr().AsSlice()),
		Port: addr.Port(),
	}

	conn, err := gonet.DialUDP(s.ipstack, &full, nil, proto)
	if err != nil {
		return nil, fmt.Errorf("listening for packets on %s: %w", addr, err)
	}
	return conn, nil
}

// release closes the stack and then its device, for a stack whose tailnet
// node never took it. A nil stack is a node that needed none.
func (s *localStack) release() {
	if s == nil {
		return
	}
	s.close()
	_ = s.dev.Close()
}

func (s *localStack) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.link.Close()
		s.ipstack.Close()
	})
	s.wg.Wait()
}

// ipVersion reports the network protocol of a raw packet from its first
// nibble, which is all that is needed to hand it to the right stack.
func ipVersion(pkt []byte) (tcpip.NetworkProtocolNumber, bool) {
	if len(pkt) == 0 {
		return 0, false
	}
	switch pkt[0] >> 4 {
	case 4:
		return ipv4.ProtocolNumber, true
	case 6:
		return ipv6.ProtocolNumber, true
	default:
		return 0, false
	}
}
