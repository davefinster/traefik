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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/tailscale/hujson"
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
		hostTags    = flag.String("host-tags", "tag:traefik-vip-harness", "comma-separated ACL tags for the host node. One must be in autoApprovers.services for the Service, and one must be reachable from the client's tag, or the host never enters the client's netmap and even its VIP cannot be resolved")
		clientTag   = flag.String("client-tag", "", "ACL tag the client node carries; must be granted access to the Service. Defaults to the first host tag")
		keep        = flag.Bool("keep", false, "leave the Service in place on exit, for inspection")
		showPolicy  = flag.Bool("policy", false, "print the tailnet policy's tag and service grants, then exit")
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

	hostTagList := strings.Split(*hostTags, ",")
	for i := range hostTagList {
		hostTagList[i] = strings.TrimSpace(hostTagList[i])
	}
	if len(hostTagList) == 0 || hostTagList[0] == "" {
		return errors.New("-host-tags must name at least one tag")
	}
	if *clientTag == "" {
		*clientTag = hostTagList[0]
	}

	fmt.Println("== Tailscale Service VIP harness ==")
	fmt.Printf("service: %s\nhost tags: %v   client tag: %s\n\n", svc, hostTagList, *clientTag)

	api, err := newAPI(ctx, clientID, clientSecret)
	if err != nil {
		return err
	}
	fmt.Println("[ok] exchanged OAuth client for an API token")

	if *showPolicy {
		return describePolicy(ctx, api)
	}

	if err := checkPolicy(ctx, api, svc, hostTagList[0]); err != nil {
		return err
	}

	hostKey, err := api.mintAuthKey(ctx, hostTagList)
	if err != nil {
		return fmt.Errorf("minting host auth key (are %v owned by the OAuth client's tag in tagOwners?): %w", hostTagList, err)
	}
	clientKey, err := api.mintAuthKey(ctx, []string{*clientTag})
	if err != nil {
		return fmt.Errorf("minting client auth key for %s: %w", *clientTag, err)
	}
	fmt.Printf("[ok] minted ephemeral auth keys for %v and %s\n", hostTagList, *clientTag)

	stateDir, err := os.MkdirTemp("", "tailnetvip-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stateDir)

	fmt.Println("[..] bringing up host and client nodes")
	host, err := startNode(ctx, stateDir+"/host", "vip-harness-host", hostKey, hostTagList)
	if err != nil {
		return err
	}
	defer host.close()

	client, err := startNode(ctx, stateDir+"/client", "vip-harness-client", clientKey, []string{*clientTag})
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

		// Each variant starts from a blank host and a Service carrying its
		// own declared ports, so nothing carries over from the last one.
		if err := reset(ctx, host, svc); err != nil {
			return fmt.Errorf("resetting host before %s: %w", v.name, err)
		}
		_ = api.deleteService(ctx, svc.String())
		if err := api.createService(ctx, vipService{
			Name:    svc.String(),
			Ports:   v.servicePorts,
			Tags:    hostTagList,
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
	fmt.Printf("  node-to-node TCP  %s\n", outcome(r.nodeToNodeOK, r.nodeToNodeErr))
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

	fmt.Println("Read the matrix against README.md: the question is whether any single")
	fmt.Println("row passes both columns. As of 2026-09-21 against global-infrastructure,")
	fmt.Println("none does: TCP needs a serve-config handler, UDP needs TUN-mode")
	fmt.Println("advertisement, and tailscaled forbids both on one Service.")
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

// describePolicy prints the parts of the tailnet policy that decide whether
// the harness can run: which tags exist and who owns them, and which
// services are auto-approved for which tags.
func describePolicy(ctx context.Context, api *api) error {
	policy, err := api.acl(ctx)
	if err != nil {
		return fmt.Errorf("reading tailnet policy: %w", err)
	}

	stripped, err := hujson.Standardize([]byte(policy))
	if err != nil {
		return fmt.Errorf("parsing policy: %w", err)
	}

	var doc struct {
		TagOwners     map[string][]string `json:"tagOwners"`
		AutoApprovers struct {
			Services map[string][]string `json:"services"`
			Routes   map[string][]string `json:"routes"`
		} `json:"autoApprovers"`
		ACLs []struct {
			Action string   `json:"action"`
			Src    []string `json:"src"`
			Dst    []string `json:"dst"`
		} `json:"acls"`
		Grants []struct {
			Src []string `json:"src"`
			Dst []string `json:"dst"`
			IP  []string `json:"ip"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(stripped, &doc); err != nil {
		return fmt.Errorf("decoding policy: %w", err)
	}

	fmt.Println("tagOwners:")
	for _, tag := range sortedKeys(doc.TagOwners) {
		fmt.Printf("  %-46s %v\n", tag, doc.TagOwners[tag])
	}

	fmt.Println("\nautoApprovers.services:")
	if len(doc.AutoApprovers.Services) == 0 {
		fmt.Println("  (none)")
	}
	for _, svc := range sortedKeys(doc.AutoApprovers.Services) {
		fmt.Printf("  %-46s %v\n", svc, doc.AutoApprovers.Services[svc])
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(stripped, &top); err == nil {
		fmt.Println("\npolicy top-level keys:")
		for _, k := range sortedKeys(top) {
			fmt.Printf("  %-20s %d bytes\n", k, len(top[k]))
		}
	}

	fmt.Println("\ngrants:")
	for _, g := range doc.Grants {
		fmt.Printf("  %v -> %v  ip=%v\n", g.Src, g.Dst, g.IP)
	}
	if len(doc.Grants) == 0 {
		fmt.Println("  (none)")
	}

	fmt.Println("\nautoApprovers.routes:")
	if len(doc.AutoApprovers.Routes) == 0 {
		fmt.Println("  (none)")
	}
	for _, r := range sortedKeys(doc.AutoApprovers.Routes) {
		fmt.Printf("  %-46s %v\n", r, doc.AutoApprovers.Routes[r])
	}

	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
