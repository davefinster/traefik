package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

// variant is one way of configuring a host to serve a VIP Service. The
// question each answers is the same: with this configuration, does TCP reach
// the host, and does UDP?
type variant struct {
	name string
	// desc says what the variant is testing and what would make it the
	// answer we want.
	desc string
	// servicePorts are the ports the Service is *defined* with, control-side.
	servicePorts []protoPort
	// tun sets TUN mode on the host's serve config, which advertises all
	// ports and all protocols and forbids TCP handlers.
	tun bool
	// tcpPort, if non-zero, gets a serve-config TCP handler forwarding to a
	// local listener. Mutually exclusive with tun, enforced by tailscaled.
	tcpPort uint16
	// udpPort, if non-zero, gets a tsnet ListenPacket bound to the VIP.
	udpPort uint16
}

// variants is the matrix. The decisive one is tcp-and-udp-no-tun: if UDP
// arrives there, a single VIP can carry both protocols into Traefik with
// plain tsnet. If it does not, TCP under TUN mode needs a second netstack.
var variants = []variant{
	{
		name:         "tcp-only-no-tun",
		desc:         "Control. Serve-config TCP handler, no UDP listener. TCP must work; establishes the baseline.",
		servicePorts: []protoPort{"tcp:8443"},
		tcpPort:      8443,
	},
	{
		name: "tcp-and-udp-no-tun",
		desc: "THE QUESTION. TCP handler plus a ListenPacket on the VIP. The data path admits UDP " +
			"(netstack checks for a registered UDP endpoint irrespective of TUN mode); the only doubt " +
			"is whether control forwards UDP to a host advertising TCP ports only.",
		servicePorts: []protoPort{"tcp:8443", "udp:8053"},
		tcpPort:      8443,
		udpPort:      8053,
	},
	{
		name: "udp-only-tun",
		desc: "TUN mode advertises all ports and protocols, so UDP is certainly permitted. " +
			"UDP must work via ListenPacket. TCP is expected to fail: TUN mode forbids TCP handlers " +
			"and netstack has no endpoint fallback for TCP, so it drains to the (fake) TUN device.",
		servicePorts: []protoPort{"*"},
		tun:          true,
		tcpPort:      8443, // probed, expected to fail
		udpPort:      8053,
	},
	{
		name: "tcp-and-udp-no-tun-wildcard-service",
		desc: "As tcp-and-udp-no-tun, but the Service is defined with all ports. Distinguishes " +
			"'control filters on the Service definition' from 'control filters on what the host advertises'.",
		servicePorts: []protoPort{"*"},
		tcpPort:      8443,
		udpPort:      8053,
	},
}

// result is what one variant produced.
type result struct {
	variant  variant
	vips     []netip.Addr
	tcpOK    bool
	tcpErr   error
	udpOK    bool
	udpErr   error
	setupErr error

	// nodeToNode records whether the client can reach the host on its own
	// tailnet address, which tells a VIP problem apart from a tailnet one.
	nodeToNodeOK  bool
	nodeToNodeErr error
}

// reset returns the host to a blank slate: no serve configuration and no
// advertisement. A variant that inherited either would be testing the
// previous one — and tailscaled refuses outright to move a Service between
// TUN mode and TCP handlers without passing through empty.
func reset(ctx context.Context, host *node, svc tailcfg.ServiceName) error {
	if err := host.unadvertiseService(ctx, svc); err != nil {
		return fmt.Errorf("withdrawing advertisement: %w", err)
	}
	if err := host.clearServeConfig(ctx); err != nil {
		return fmt.Errorf("clearing serve config: %w", err)
	}
	return nil
}

// run configures the host for the variant and probes it from the client.
func (v variant) run(ctx context.Context, host, client *node, svc tailcfg.ServiceName) result {
	res := result{variant: v}

	// The Service definition is recreated per variant because its declared
	// ports are part of what is under test.
	sc := &ipn.ServeConfig{
		Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{svc: {}},
	}

	if v.tun {
		sc.Services[svc].Tun = true
	} else if v.tcpPort != 0 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			res.setupErr = fmt.Errorf("local TCP listener: %w", err)
			return res
		}
		defer ln.Close()

		go serveTCPEcho(ln)

		sc.Services[svc].TCP = map[uint16]*ipn.TCPPortHandler{
			v.tcpPort: {TCPForward: ln.Addr().String()},
		}
	}

	if err := host.setServeConfig(ctx, sc); err != nil {
		res.setupErr = fmt.Errorf("setting serve config: %w", err)
		return res
	}
	if err := host.advertiseService(ctx, svc); err != nil {
		res.setupErr = fmt.Errorf("advertising service: %w", err)
		return res
	}

	vips, err := host.awaitServiceVIPs(ctx, svc, 90*time.Second)
	if err != nil {
		res.setupErr = err
		return res
	}
	res.vips = vips

	// Bind UDP directly on the VIP. tsnet registers a gVisor endpoint, which
	// is what netstack looks for when deciding whether to intercept UDP
	// addressed to a Service VIP.
	if v.udpPort != 0 {
		for _, vip := range vips {
			pc, err := host.srv.ListenPacket("udp", net.JoinHostPort(vip.String(), fmt.Sprint(v.udpPort)))
			if err != nil {
				res.setupErr = fmt.Errorf("ListenPacket on VIP %s: %w", vip, err)
				return res
			}
			defer pc.Close()
			go serveUDPEcho(pc)
		}
	}

	target := vips[0]
	if v.tcpPort != 0 {
		res.tcpOK, res.tcpErr = probeTCP(ctx, client, netip.AddrPortFrom(target, v.tcpPort))
	}
	if v.udpPort != 0 {
		res.udpOK, res.udpErr = probeUDP(ctx, client, netip.AddrPortFrom(target, v.udpPort))
	}

	return res
}
