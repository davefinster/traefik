---
title: "Traefik Tailnets Documentation"
description: "Learn how to configure Traefik to listen on, and dial backends over, a Tailscale tailnet with embedded tsnet nodes. Read the technical documentation."
---

# Tailnets

Join a Tailscale network from inside Traefik, for entryPoints and backends alike.
{: .subtitle }

A `tailnets` entry is one embedded [Tailscale](https://tailscale.com) node, joined
in-process with [tsnet](https://tailscale.com/kb/1244/tsnet). It is a userspace
node: there is no TUN device, and no routing-table or netfilter entry, so it
coexists with a `tailscaled` running on the same host and needs no
`NET_ADMIN` capability.

One node serves both directions:

- An **entryPoint** referencing a tailnet accepts connections on it instead of on
  the host network, so a service is reachable at the node's MagicDNS name and
  nowhere else.
- A **serversTransport** referencing a tailnet dials that transport's backends
  over it, resolving their names through the tailnet's MagicDNS.

!!! info "Not the Tailscale certificate resolver"

    This is unrelated to the
    [Tailscale certificate resolver](./tls/certificate-resolvers/tailscale.md),
    which obtains TLS certificates from a `tailscaled` already running on the
    host. Tailnets are about carrying the traffic; the certificate resolver is
    about certifying it. They can be used together, but neither needs the other.

## Configuration Example

```yaml tab="File (YAML)"
## Static configuration
tailnets:
  corp:
    hostname: traefik
    stateDir: /var/lib/traefik/tsnet/corp
    authKeyFile: /run/secrets/tailscale-authkey

entryPoints:
  # Reachable only from the tailnet, at traefik.<tailnet>.ts.net:443
  internal:
    address: ":443"
    tailnet: corp

  # An ordinary host entryPoint, unaffected
  web:
    address: ":80"
```

```toml tab="File (TOML)"
## Static configuration
[tailnets.corp]
  hostname = "traefik"
  stateDir = "/var/lib/traefik/tsnet/corp"
  authKeyFile = "/run/secrets/tailscale-authkey"

[entryPoints.internal]
  address = ":443"
  tailnet = "corp"

[entryPoints.web]
  address = ":80"
```

```bash tab="CLI"
## Static configuration
--tailnets.corp.hostname=traefik
--tailnets.corp.stateDir=/var/lib/traefik/tsnet/corp
--tailnets.corp.authKeyFile=/run/secrets/tailscale-authkey
--entryPoints.internal.address=:443
--entryPoints.internal.tailnet=corp
--entryPoints.web.address=:80
```

## Configuration Options

| Field | Description | Default | Required |
|:------|:------------|:--------|:---------|
| <a id="opt-tailnets-name-hostname" href="#opt-tailnets-name-hostname" title="#opt-tailnets-name-hostname">`tailnets.<name>.`<br />`hostname`</a> | Device name on the tailnet, and the basis of its MagicDNS name. Defaults to the tsnet default, derived from the binary name. | - | No |
| <a id="opt-tailnets-name-stateDir" href="#opt-tailnets-name-stateDir" title="#opt-tailnets-name-stateDir">`tailnets.<name>.`<br />`stateDir`</a> | Directory holding the node identity and WireGuard state. <br /> Required: tsnet derives a single default directory from the binary name, which several nodes in one process cannot share. | - | Yes |
| <a id="opt-tailnets-name-authKey" href="#opt-tailnets-name-authKey" title="#opt-tailnets-name-authKey">`tailnets.<name>.`<br />`authKey`</a> | Auth key for the first join, unused once `stateDir` holds an identity. <br /> Also accepts an OAuth client secret (`tskey-client-...`), which requires `advertiseTags`. <br /> Mutually exclusive with `authKeyFile`; with both empty, tsnet falls back to the `TS_AUTHKEY` environment variable. | - | No |
| <a id="opt-tailnets-name-authKeyFile" href="#opt-tailnets-name-authKeyFile" title="#opt-tailnets-name-authKeyFile">`tailnets.<name>.`<br />`authKeyFile`</a> | File to read the auth key from. <br /> Read at the first join attempt rather than at startup, so a key delivered by an external system after Traefik starts is picked up by a retry. | - | No |
| <a id="opt-tailnets-name-controlURL" href="#opt-tailnets-name-controlURL" title="#opt-tailnets-name-controlURL">`tailnets.<name>.`<br />`controlURL`</a> | Coordination server URL, for Headscale and other self-hosted control planes. <br /> Empty means the Tailscale control plane. | - | No |
| <a id="opt-tailnets-name-ephemeral" href="#opt-tailnets-name-ephemeral" title="#opt-tailnets-name-ephemeral">`tailnets.<name>.`<br />`ephemeral`</a> | Registers the node as ephemeral, so the control plane removes it shortly after it goes offline. <br /> Suited to replicas that come and go; with it set, `stateDir` need not outlive the process. | false | No |
| <a id="opt-tailnets-name-advertiseTags" href="#opt-tailnets-name-advertiseTags" title="#opt-tailnets-name-advertiseTags">`tailnets.<name>.`<br />`advertiseTags`</a> | ACL tags the node advertises (`tag:...`). <br /> Required when `authKey` is an OAuth client secret: Tailscale refuses such a join without explicit tags. | - | No |
| <a id="opt-tailnets-name-port" href="#opt-tailnets-name-port" title="#opt-tailnets-name-port">`tailnets.<name>.`<br />`port`</a> | Local UDP port for WireGuard and peer-to-peer traffic. <br /> Zero picks one automatically, which is what most deployments want; pin it when a firewall has to be opened for direct connections. | 0 | No |

## EntryPoints on a Tailnet

Set `tailnet` on an entryPoint and its listener comes from the tailnet node
rather than from a host socket. The `address` is interpreted within the
tailnet, so `:443` means port 443 on the node's tailnet addresses, and nothing
is bound on the host.

TCP, UDP and HTTP/3 entryPoints are all supported.

```yaml tab="File (YAML)"
## Static configuration
tailnets:
  corp:
    stateDir: /var/lib/traefik/tsnet/corp

entryPoints:
  websecure:
    address: ":443"
    tailnet: corp
    http3: {}

  dns:
    address: ":53/udp"
    tailnet: corp
```

```toml tab="File (TOML)"
## Static configuration
[tailnets.corp]
  stateDir = "/var/lib/traefik/tsnet/corp"

[entryPoints.websecure]
  address = ":443"
  tailnet = "corp"
  [entryPoints.websecure.http3]

[entryPoints.dns]
  address = ":53/udp"
  tailnet = "corp"
```

TLS behaves exactly as it does on a host entryPoint: certificates, TLS options
and certificate resolvers are all still Traefik's, and a tailnet entryPoint can
terminate TLS in the usual way.

!!! note "HTTP/3 and UDP on a tailnet"

    Packets on a tailnet entryPoint come from the in-process network stack
    rather than from a host socket, so the kernel UDP optimizations QUIC uses
    on an ordinary socket (segmentation offload, out-of-band data, the
    don't-fragment bit) are unavailable. `quic-go` says so once at startup and
    falls back to plain reads and writes. It may also warn that it could not
    size the socket buffers; that warning does not apply to a tailnet
    entryPoint and can be silenced with
    `QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING=true`.

    An address such as `:443` becomes one listener per tailnet address, so
    both address families are served.

An entryPoint naming a tailnet that is not configured is a startup error: the
entryPoint could never serve, and the static configuration is known in full at
boot. A serversTransport naming one is only a warning, because dynamic
configuration arrives and changes while Traefik runs, and one bad transport
must not take the proxy down with it. It still fails every request through it
(see [Backends over a Tailnet](#backends-over-a-tailnet)).

!!! info "Options that do not apply"

    - `reusePort` is rejected on a tailnet entryPoint. The listener is a socket
      on the in-process network stack, so there is no host socket for
      `SO_REUSEPORT` to apply to, and nothing for a second process to share.
    - Systemd socket activation is ignored for a tailnet entryPoint: the
      listener comes from the tailnet, not from an inherited file descriptor.

    `proxyProtocol` does still apply, for a PROXY-protocol-speaking peer on the
    tailnet.

## Backends over a Tailnet

Set `tailnet` on a [serversTransport](../routing-configuration/http/load-balancing/serverstransport.md)
(or a [TCP serversTransport](../routing-configuration/tcp/serverstransport.md))
and every backend dial made through it goes over the tailnet. Backend host
names resolve through the tailnet's MagicDNS, so a service can be addressed by
its Tailscale name.

```yaml tab="File (YAML)"
## Dynamic configuration
http:
  serversTransports:
    corp:
      tailnet: corp

  services:
    internal-app:
      loadBalancer:
        serversTransport: corp
        servers:
          - url: "http://app.tailnet-name.ts.net:8080"
```

```yaml tab="Kubernetes"
apiVersion: traefik.io/v1alpha1
kind: ServersTransport
metadata:
  name: corp
  namespace: default
spec:
  tailnet: corp
```

A transport naming a tailnet never falls back to the host network. If the
tailnet is unknown or unavailable, requests through that transport fail, rather
than quietly reaching the backend some other way. For the same reason, a
transport with `tailnet` set always uses the standard proxy implementation,
even when the [FastProxy](./experimental/fastproxy.md) experimental option is
enabled, because the fast proxy dials with its own dialer.

## Startup and Failure Behaviour

Nodes join lazily, on their first use, and Traefik never waits for a tailnet in
order to start:

- A tailnet entryPoint binds on its first accept and retries with a capped
  backoff until it succeeds. Other entryPoints serve normally throughout.
- A tailnet backend dial joins on the first request through that transport.

A tailnet that cannot reach its control plane therefore degrades only the
routes that depend on it, and heals without a restart once the tailnet answers.
An auth key that has not been delivered yet behaves the same way, which is why
`authKeyFile` is read at the join attempt and not at startup.

```text
WARN  Cannot listen on tailnet yet, retrying  tailnet=corp retryIn=1s
INFO  EntryPoint "web" started
INFO  Listening on tailnet  tailnet=corp address=100.64.0.7:443
```

## State and Identity

`stateDir` holds the node's identity and WireGuard keys. Keep it on persistent
storage so that a restart rejoins as the same device rather than consuming a
new auth key and appearing as a new node. Each tailnet needs its own directory.

For a node that is meant to be short-lived, set `ephemeral: true` instead: the
control plane removes it shortly after it goes offline, and the state directory
does not need to survive the process.

{!traefik-for-business-applications.md!}
