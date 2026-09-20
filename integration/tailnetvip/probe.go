package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

// probePayload is what every echo exchange carries, so a reply that is not
// ours is not mistaken for success.
var probePayload = []byte("traefik-tailnet-vip-probe")

const probeTimeout = 10 * time.Second

// serveTCPEcho echoes one payload per connection until the listener closes.
func serveTCPEcho(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			buf := make([]byte, len(probePayload))
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			_, _ = conn.Write(buf)
		}()
	}
}

// serveUDPEcho echoes datagrams until the conn closes.
func serveUDPEcho(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(buf[:n], addr)
	}
}

// probeTCP dials the VIP from the client node and checks the echo, retrying
// while the client's netmap catches up: the grant and the Service's addresses
// reach it a round after the host advertises, and a single dial would read
// that delay as a failure.
func probeTCP(ctx context.Context, client *node, target netip.AddrPort) (bool, error) {
	var lastErr error
	deadline := time.Now().Add(propagationWindow)
	for attempt := 1; time.Now().Before(deadline); attempt++ {
		ok, err := probeTCPOnce(ctx, client, target)
		if ok {
			return true, nil
		}
		lastErr = fmt.Errorf("attempt %d: %w", attempt, err)
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return false, lastErr
}

func probeTCPOnce(ctx context.Context, client *node, target netip.AddrPort) (bool, error) {
	conn, err := client.dialTCP(ctx, target.String(), probeTimeout)
	if err != nil {
		return false, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(probeTimeout)); err != nil {
		return false, err
	}
	if _, err := conn.Write(probePayload); err != nil {
		return false, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, len(probePayload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false, fmt.Errorf("read: %w", err)
	}
	if !bytes.Equal(buf, probePayload) {
		return false, fmt.Errorf("echo mismatch: got %q", buf)
	}
	return true, nil
}

// propagationWindow bounds how long a probe keeps retrying while control
// distributes the netmap that makes the Service reachable.
const propagationWindow = 90 * time.Second

// probeUDP sends a datagram to the VIP from the client node and waits for the
// echo. UDP gives no connection error, so a failure here shows up as a
// timeout, which is exactly what a dropped or unrouted datagram looks like.
func probeUDP(ctx context.Context, client *node, target netip.AddrPort) (bool, error) {
	conn, err := client.dialUDP(ctx, target.String(), probeTimeout)
	if err != nil {
		return false, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(probeTimeout)); err != nil {
		return false, err
	}

	// Retry: the first datagram after a netmap change is easily lost, and a
	// single drop would read as "UDP does not work".
	var lastErr error
	deadline := time.Now().Add(propagationWindow)
	for attempt := 0; time.Now().Before(deadline); attempt++ {
		if _, err := conn.Write(probePayload); err != nil {
			lastErr = fmt.Errorf("write: %w", err)
			continue
		}

		buf := make([]byte, 1500)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			lastErr = fmt.Errorf("attempt %d: read: %w", attempt+1, err)
			continue
		}
		if !bytes.Equal(buf[:n], probePayload) {
			lastErr = fmt.Errorf("echo mismatch: got %q", buf[:n])
			continue
		}
		return true, nil
	}
	return false, lastErr
}

// probeNodeToNode checks the plainest thing that must work: the client
// reaching a listener on the host's own tailnet address. If this fails, the
// tailnet itself is the problem and no VIP result means anything.
func probeNodeToNode(ctx context.Context, host, client *node) (bool, error) {
	ln, err := host.srv.Listen("tcp", ":18443")
	if err != nil {
		return false, fmt.Errorf("host listen: %w", err)
	}
	defer ln.Close()
	go serveTCPEcho(ln)

	st, err := host.lc.Status(ctx)
	if err != nil {
		return false, err
	}
	if st.Self == nil || len(st.Self.TailscaleIPs) == 0 {
		return false, fmt.Errorf("host has no tailnet address")
	}

	// Retried like the VIP probe: first contact between two nodes has to
	// find a path (direct or DERP), and a single dial reads that setup as a
	// failure.
	target := netip.AddrPortFrom(st.Self.TailscaleIPs[0], 18443)
	return probeTCP(ctx, client, target)
}
