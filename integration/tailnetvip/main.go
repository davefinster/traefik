// Command tailnetvip answers one question against a live tailnet: can a
// single Tailscale Service VIP carry both TCP and UDP into a userspace
// (tsnet) host, which is what Traefik would need to terminate both on one
// Service.
//
// It is a harness, not a test: it creates a Service, brings up two ephemeral
// tagged nodes, tries each configuration in turn and prints a matrix. Every
// resource it creates is ephemeral or removed on the way out.
//
// Credentials come from the environment and are never written anywhere:
//
//	TS_OAUTH_CLIENT_ID, TS_OAUTH_CLIENT_SECRET   the tailnet's own admin client
//
// See README.md for the tailnet policy the harness needs in place first.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"tailscale.com/tailcfg"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nFAILED: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		serviceName = flag.String("service", "svc:traefik-vip-harness", "Tailscale Service to create and host")
		tag         = flag.String("tag", "tag:traefik-vip-harness", "ACL tag the harness nodes carry")
		keep        = flag.Bool("keep", false, "leave the Service in place on exit, for inspection")
		only        = flag.String("only", "", "run only the named variant")
	)
	flag.Parse()

	clientID := os.Getenv("TS_OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("TS_OAUTH_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		return errors.New("TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET must be set to the tailnet's own OAuth client")
	}

	svc := tailcfg.ServiceName(*serviceName)
	if err := svc.Validate(); err != nil {
		return fmt.Errorf("service name: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Println("== Tailscale Service VIP harness ==")
	fmt.Printf("service: %s   tag: %s\n\n", svc, *tag)

	api, err := newAPI(ctx, clientID, clientSecret)
	if err != nil {
		return err
	}
	fmt.Println("[ok] exchanged OAuth client for an API token")

	if err := checkPolicy(ctx, api, svc, *tag); err != nil {
		return err
	}

	authKey, err := api.mintAuthKey(ctx, []string{*tag})
	if err != nil {
		return fmt.Errorf("minting auth key (is %s owned by the OAuth client's tag in tagOwners?): %w", *tag, err)
	}
	fmt.Printf("[ok] minted an ephemeral auth key for %s\n", *tag)

	stateDir, err := os.MkdirTemp("", "tailnetvip-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stateDir)

	fmt.Println("[..] bringing up host and client nodes")
	host, err := startNode(ctx, stateDir+"/host", "vip-harness-host", authKey, []string{*tag})
	if err != nil {
		return err
	}
	defer host.close()

	client, err := startNode(ctx, stateDir+"/client", "vip-harness-client", authKey, []string{*tag})
	if err != nil {
		return err
	}
	defer client.close()

	tagged, tags, err := host.tagged(ctx)
	if err != nil {
		return fmt.Errorf("reading host status: %w", err)
	}
	if !tagged {
		return errors.New("host node came up untagged; only tagged nodes may host a Service")
	}
	fmt.Printf("[ok] both nodes up, host tagged %v\n\n", tags)

	var results []result
	for _, v := range variants {
		if *only != "" && v.name != *only {
			continue
		}

		fmt.Printf("---- %s ----\n%s\n", v.name, wrap(v.desc, 76))

		// Recreate the Service with this variant's declared ports.
		_ = api.deleteService(ctx, svc.String())
		if err := api.createService(ctx, vipService{
			Name:    svc.String(),
			Ports:   v.servicePorts,
			Tags:    []string{*tag},
			Comment: "ephemeral: created by the traefik tailnetvip harness",
		}); err != nil {
			return fmt.Errorf("creating Service for %s: %w", v.name, err)
		}

		res := v.run(ctx, host, client, svc)
		results = append(results, res)
		printResult(res)
		fmt.Println()

		if ctx.Err() != nil {
			break
		}
	}

	if !*keep {
		if err := api.deleteService(ctx, svc.String()); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not delete Service %s: %v\n", svc, err)
		} else {
			fmt.Printf("[ok] removed Service %s\n\n", svc)
		}
	}

	printMatrix(results)
	return nil
}

// checkPolicy reports what the tailnet policy needs rather than editing it:
// a live policy is not a harness's to rewrite.
func checkPolicy(ctx context.Context, api *api, svc tailcfg.ServiceName, tag string) error {
	policy, err := api.acl(ctx)
	if err != nil {
		return fmt.Errorf("reading tailnet policy: %w", err)
	}

	var missing []string
	if !strings.Contains(policy, tag) {
		missing = append(missing, fmt.Sprintf("tagOwners must declare %q (owned by the OAuth client's own tag, or autogroup:admin)", tag))
	}
	if !strings.Contains(policy, svc.String()) {
		missing = append(missing, fmt.Sprintf("autoApprovers.services must auto-approve %q for %q, or the advertisement waits on an admin", svc, tag))
	}

	if len(missing) > 0 {
		fmt.Println("\n[!!] the tailnet policy looks incomplete for this harness:")
		for _, m := range missing {
			fmt.Printf("     - %s\n", m)
		}
		fmt.Println("     Add them through the usual path (infralife's policy), then re-run.")
		fmt.Println("     Continuing anyway; an advertisement that is not auto-approved will simply never")
		fmt.Println("     get VIP addresses, which shows up below as a setup timeout.")
		fmt.Println()
		return nil
	}

	fmt.Println("[ok] tailnet policy mentions the tag and the Service")
	return nil
}

func printResult(r result) {
	if r.setupErr != nil {
		fmt.Printf("  SETUP FAILED: %v\n", r.setupErr)
		return
	}
	fmt.Printf("  VIPs: %v\n", r.vips)
	if r.variant.tcpPort != 0 {
		fmt.Printf("  TCP :%d  %s\n", r.variant.tcpPort, outcome(r.tcpOK, r.tcpErr))
	}
	if r.variant.udpPort != 0 {
		fmt.Printf("  UDP :%d  %s\n", r.variant.udpPort, outcome(r.udpOK, r.udpErr))
	}
}

func outcome(ok bool, err error) string {
	if ok {
		return "PASS"
	}
	if err != nil {
		return "FAIL (" + err.Error() + ")"
	}
	return "FAIL"
}

func printMatrix(results []result) {
	fmt.Println("================ SUMMARY ================")
	fmt.Printf("%-38s %-6s %-6s\n", "VARIANT", "TCP", "UDP")
	for _, r := range results {
		tcp, udp := "-", "-"
		if r.setupErr != nil {
			tcp, udp = "setup", "setup"
		} else {
			if r.variant.tcpPort != 0 {
				tcp = passFail(r.tcpOK)
			}
			if r.variant.udpPort != 0 {
				udp = passFail(r.udpOK)
			}
		}
		fmt.Printf("%-38s %-6s %-6s\n", r.variant.name, tcp, udp)
	}
	fmt.Println()

	for _, r := range results {
		if r.variant.name == "tcp-and-udp-no-tun" && r.setupErr == nil {
			switch {
			case r.tcpOK && r.udpOK:
				fmt.Println("VERDICT: one VIP carries both TCP and UDP with plain tsnet.")
				fmt.Println("         Traefik needs no second netstack: a serve-config TCP handler for the")
				fmt.Println("         TCP entryPoints, and ListenPacket on the VIP for the UDP ones.")
			case r.tcpOK && !r.udpOK:
				fmt.Println("VERDICT: control does not forward UDP to a host advertising TCP ports only.")
				fmt.Println("         A single VIP carrying both then needs TUN-mode advertisement, and TUN")
				fmt.Println("         mode forbids TCP handlers, so the TCP half needs an in-process TUN")
				fmt.Println("         device and a second gVisor stack. Check udp-only-tun above: if its UDP")
				fmt.Println("         passes, only TCP is missing and only TCP needs that machinery.")
			default:
				fmt.Println("VERDICT: inconclusive; see the per-variant errors above.")
			}
		}
	}
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

// wrap is a small word-wrapper so variant descriptions read in a terminal.
func wrap(s string, width int) string {
	var out strings.Builder
	line := 0
	for _, word := range strings.Fields(s) {
		if line > 0 && line+len(word)+1 > width {
			out.WriteString("\n")
			line = 0
		}
		if line > 0 {
			out.WriteString(" ")
			line++
		}
		out.WriteString(word)
		line += len(word)
	}
	return out.String()
}
