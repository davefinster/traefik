# Tailscale Service VIP harness

Answers one question against a live tailnet, because the client source does
not settle it:

> Can a single Tailscale Service VIP carry **both TCP and UDP** into a
> userspace (tsnet) host?

That is what Traefik needs in order to terminate both protocols on one
Service. Everything else about the tailnet work is covered by unit tests; this
needs a real control plane, so it is a command rather than a test.

## Why the question is open

Three facts from `tailscale.com@v1.102.4`, all verified in the source:

1. **The data path admits UDP on a VIP regardless of TUN mode.**
   `netstack.shouldProcessInbound` intercepts UDP addressed to a Service VIP
   whenever a gVisor UDP endpoint is registered for it — the comment there
   names `tsnet.ListenPacket` explicitly. VIPs are registered as bindable
   netstack addresses unconditionally (`UpdateNetstackIPs`).

2. **TCP on a VIP has no such fallback.** It is gated solely on
   `ShouldInterceptVIPServiceTCPPort`, which is populated from the serve
   config's TCP handlers. There is no endpoint check for TCP.

3. **A host advertises one of three port shapes**
   (`vipServicesFromPrefsLocked` + `ServiceConfig.ServicePortRange`): the TCP
   ports in its serve config, *or* all ports and protocols (TUN mode), *or*
   nothing at all. No client path emits "TCP 443 + UDP 53".

Since TUN mode is mutually exclusive with TCP handlers, the only shape that
could serve both is a **non-TUN** host with TCP handlers that *also* binds UDP
on the VIP. Whether the datagrams arrive depends on whether control forwards
UDP to a host advertising TCP ports only — a control-plane behaviour that
cannot be read off the client.

## What it does

Creates a Service, brings up two ephemeral tagged tsnet nodes (a host and a
client), and for each variant configures the host, probes it from the client
over TCP and UDP, and prints a matrix.

| Variant | What it settles |
| --- | --- |
| `tcp-only-no-tun` | Baseline: serve-config TCP forwarding works at all. |
| `tcp-and-udp-no-tun` | **The question.** TCP handler plus `ListenPacket` on the VIP. |
| `udp-only-tun` | TUN mode certainly advertises UDP; confirms UDP works, and that TCP does not. |
| `tcp-and-udp-no-tun-wildcard-service` | Whether control filters on the *Service definition* or on what the *host* advertises. |

The summary ends with a verdict naming which implementation Traefik needs.

## Prerequisites

The harness **does not edit the tailnet policy**; a live policy is not a
harness's to rewrite. It checks and reports. Add these through the usual path
(infralife's generated policy) before running:

```jsonc
{
  "tagOwners": {
    // owned by the OAuth client's own tag, or autogroup:admin
    "tag:traefik-vip-harness": ["autogroup:admin"],
  },
  "autoApprovers": {
    "services": {
      // without this the advertisement waits on an admin and the harness
      // times out waiting for VIP addresses
      "svc:traefik-vip-harness": ["tag:traefik-vip-harness"],
    },
  },
  "acls": [
    {
      "action": "accept",
      "src": ["tag:traefik-vip-harness"],
      "dst": ["svc:traefik-vip-harness:*"],
    },
  ],
}
```

The ACL grant must be wide (`:*`, both protocols); a grant that permits only
TCP would answer the question with its own restriction rather than with
control's behaviour.

## Running

```sh
export TS_OAUTH_CLIENT_ID=...       # the tailnet's OWN admin OAuth client,
export TS_OAUTH_CLIENT_SECRET=...   # not the org-level one
go run .
```

Flags: `-service`, `-tag`, `-only <variant>`, `-keep` (leave the Service in
place for inspection).

Credentials are read from the environment and never written to disk. Both
nodes are ephemeral and their state directories are temporary, so an
interrupted run leaves nothing behind but the Service, which `-keep` aside is
deleted on the way out.

## Scope

This is a separate Go module on purpose. Go excludes a directory with its own
`go.mod` from the parent, so nothing here reaches Traefik's dependency graph
and `./...` in the repo root never builds or tests it.
