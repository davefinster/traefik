package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// mintKey writes an ephemeral auth key to a file, for something other than
// this harness to join with — Traefik, when it is the one hosting the
// Service. It goes to a file rather than to stdout so the key does not end
// up in a terminal, a log or a shell history.
func mintKey(ctx context.Context, api *api, tags []string, path string) error {
	key, err := api.mintAuthKey(ctx, tags)
	if err != nil {
		return fmt.Errorf("minting auth key for %v: %w", tags, err)
	}

	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		return fmt.Errorf("writing auth key: %w", err)
	}

	fmt.Printf("[ok] wrote an ephemeral auth key for %v to %s (mode 0600, 1h)\n", tags, path)
	return nil
}

// probeService dials a Service by its MagicDNS name, which is how a real
// client reaches one: no VIP discovery, no serve configuration, just the
// name the tailnet publishes. It is the other half of a run where Traefik
// hosts the Service.
func probeService(ctx context.Context, api *api, clientTag, fqdn string, tcpPort, udpPort uint16) error {
	key, err := api.mintAuthKey(ctx, []string{clientTag})
	if err != nil {
		return fmt.Errorf("minting client auth key: %w", err)
	}

	stateDir, err := os.MkdirTemp("", "tailnetvip-probe-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stateDir)

	fmt.Printf("[..] bringing up a client node tagged %s\n", clientTag)
	client, err := startNode(ctx, stateDir, "vip-probe-client", key, []string{clientTag})
	if err != nil {
		return err
	}
	defer client.close()

	fmt.Printf("[ok] client up; probing %s\n\n", fqdn)

	var failed bool
	if tcpPort != 0 {
		target := fmt.Sprintf("%s:%d", fqdn, tcpPort)
		ok, err := probeTCPName(ctx, client, target)
		fmt.Printf("  TCP %-40s %s\n", target, outcome(ok, err))
		failed = failed || !ok
	}
	if udpPort != 0 {
		target := fmt.Sprintf("%s:%d", fqdn, udpPort)
		ok, err := probeUDPName(ctx, client, target)
		fmt.Printf("  UDP %-40s %s\n", target, outcome(ok, err))
		failed = failed || !ok
	}

	fmt.Println()
	if failed {
		return fmt.Errorf("one or more probes failed")
	}
	fmt.Println("Both protocols answered on one Service.")
	return nil
}

// resolveFQDN turns a Service name and tailnet domain into the name clients
// use, so the caller can pass either "svc:myapp" or the full name.
func resolveFQDN(service, domain string) string {
	name := strings.TrimPrefix(service, "svc:")
	if strings.Contains(name, ".") {
		return name
	}
	return name + "." + strings.TrimPrefix(domain, ".")
}

// probeTCPName is probeTCP against a name rather than an address, retrying
// while the client's netmap catches up.
func probeTCPName(ctx context.Context, client *node, target string) (bool, error) {
	var lastErr error
	deadline := time.Now().Add(propagationWindow)
	for attempt := 1; time.Now().Before(deadline); attempt++ {
		// A real HTTP request, so a pass means the traffic crossed the
		// tailnet, the Service, the entryPoint and the router and came back
		// from the backend — not merely that a socket opened.
		body, err := httpGet(ctx, client, target)
		if err == nil {
			fmt.Printf("      backend said: %q\n", body)
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

// probeUDPName sends datagrams to a name and waits for any reply.
func probeUDPName(ctx context.Context, client *node, target string) (bool, error) {
	conn, err := client.dialUDP(ctx, target, probeTimeout)
	if err != nil {
		return false, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	var lastErr error
	deadline := time.Now().Add(propagationWindow)
	for attempt := 1; time.Now().Before(deadline); attempt++ {
		if _, err := conn.Write(probePayload); err != nil {
			lastErr = fmt.Errorf("attempt %d: write: %w", attempt, err)
			continue
		}

		buf := make([]byte, 1500)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			lastErr = fmt.Errorf("attempt %d: read: %w", attempt, err)
			continue
		}
		fmt.Printf("      backend said: %q\n", buf[:n])
		return true, nil
	}
	return false, lastErr
}

// httpGet issues a real request over the tailnet and returns the body, so a
// TCP pass is evidence the whole path worked rather than that a connection
// was accepted.
func httpGet(ctx context.Context, client *node, target string) (string, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return client.srv.Dial(ctx, network, addr)
			},
		},
		Timeout: probeTimeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target+"/", http.NoBody)
	if err != nil {
		return "", err
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 256))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}
