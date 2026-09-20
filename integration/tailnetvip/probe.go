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

// probeTCP dials the VIP from the client node and checks the echo.
func probeTCP(ctx context.Context, client *node, target netip.AddrPort) (bool, error) {
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
	for attempt := range 3 {
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
