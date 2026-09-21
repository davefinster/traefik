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
| <a id="opt-tailnets-name-routes" href="#opt-tailnets-name-routes" title="#opt-tailnets-name-routes">`tailnets.<name>.`<br />`routes`</a> | CIDR prefixes the node advertises into the tailnet, subject to approval by an admin or an ACL auto-approver. <br /> Traefik answers only on the addresses its entryPoints bind; this is not a subnet router. <br /> More information [here](#advertising-routes). | -     | No       |
| <a id="opt-tailnets-name-services-name" href="#opt-tailnets-name-services-name" title="#opt-tailnets-name-services-name">`tailnets.<name>.`<br />`services.<name>`</a> | A Tailscale Service this node can host, keyed by the name entryPoints reference it as. <br /> More information [here](#hosting-tailscale-services). | -     | No       |
| <a id="opt-tailnets-name-services-name-mode" href="#opt-tailnets-name-services-name-mode" title="#opt-tailnets-name-services-name-mode">`tailnets.<name>.`<br />`services.<name>.mode`</a> | How the Service is served: `tcp` (Tailscale forwards TCP to the entryPoint) or `tun` (Traefik takes the Service's packets directly). <br /> Only `tun` carries UDP, and so HTTP/3, and only `tun` gives the entryPoint the client's real address without the PROXY protocol. <br /> More information [here](#serving-tcp-and-udp-on-one-service). | tcp   | No       |
| <a id="opt-tailnets-name-services-name-name" href="#opt-tailnets-name-services-name-name" title="#opt-tailnets-name-services-name-name">`tailnets.<name>.`<br />`services.<name>.name`</a> | The Tailscale Service name, which must start with `svc:`. <br /> Defaults to `svc:` followed by the key the Service is configured under. | -     | No       |
| <a id="opt-tailnets-name-services-name-terminateTLS" href="#opt-tailnets-name-services-name-terminateTLS" title="#opt-tailnets-name-services-name-terminateTLS">`tailnets.<name>.`<br />`services.<name>.terminateTLS`</a> | Lets Tailscale terminate TLS before forwarding to the entryPoint, in which case the Service's own fully-qualified name is the only permitted SNI. <br /> Off by default: TLS is Traefik's, as on any other entryPoint. | false | No       |
| <a id="opt-tailnets-name-services-name-proxyProtocol" href="#opt-tailnets-name-services-name-proxyProtocol" title="#opt-tailnets-name-services-name-proxyProtocol">`tailnets.<name>.`<br />`services.<name>.proxyProtocol`</a> | The PROXY protocol version Tailscale uses when forwarding a connection to the entryPoint, or `0` to disable it. <br /> It carries the client's tailnet address, which is otherwise lost. <br /> More information [here](#client-addresses-on-a-service). | 2     | No       |

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

## Advertising Routes

`routes` advertises CIDR prefixes from the node, which lets an entryPoint bind
an address that is not the node's own — an alias address on the tailnet, which
survives the node being replaced and can be moved between nodes.

```yaml tab="File (YAML)"
## Static configuration
tailnets:
  corp:
    stateDir: /var/lib/traefik/tsnet/corp
    routes:
      - 100.64.30.0/24

entryPoints:
  vip:
    address: "100.64.30.5:443"
    tailnet: corp
```

```toml tab="File (TOML)"
## Static configuration
[tailnets.corp]
  stateDir = "/var/lib/traefik/tsnet/corp"
  routes = ["100.64.30.0/24"]

[entryPoints.vip]
  address = "100.64.30.5:443"
  tailnet = "corp"
```

An advertised route still has to be approved, by an admin or by an ACL
auto-approver, before the tailnet sends any traffic over it.

A node that advertises routes answers them from Traefik's in-process network
stack, the one that serves [Services in TUN mode](#serving-tcp-and-udp-on-one-service),
so routed addresses carry TCP and UDP on both address families alike.

!!! warning "This is not a subnet router"

    Traefik answers on an advertised address only where an entryPoint binds
    it. The embedded node accepts packets for an advertised prefix but has
    nothing to forward them with, so traffic to an address no entryPoint binds
    goes unanswered rather than being passed to the host behind it.

    Give the entryPoint an explicit address inside the route, as above. An
    entryPoint written as `:443` binds the node's own addresses only, not the
    advertised ones. For genuine subnet routing, run a `tailscaled` subnet
    router beside Traefik.

Because the routes exist only while the node is joined, a tailnet that
advertises any is brought up at startup even when no entryPoint or
serversTransport references it. That happens in the background with the same
retry as everything else here, so it never delays startup.

## Hosting Tailscale Services

A [Tailscale Service](https://tailscale.com/kb/1552/tailscale-services) has its
own name and virtual IPs, separate from any node's. `services` declares the
Services a tailnet node may host, and an entryPoint hosts one by naming it:

```yaml tab="File (YAML)"
## Static configuration
tailnets:
  corp:
    stateDir: /var/lib/traefik/tsnet/corp
    # Only tagged nodes may host a Service.
    advertiseTags:
      - tag:proxy
    services:
      myapp:
        # Defaults to svc:myapp
        name: svc:myapp

entryPoints:
  web:
    address: ":80"
    tailnet: corp
    tailnetService: myapp

  websecure:
    address: ":443"
    tailnet: corp
    tailnetService: myapp
```

```toml tab="File (TOML)"
## Static configuration
[tailnets.corp]
  stateDir = "/var/lib/traefik/tsnet/corp"
  advertiseTags = ["tag:proxy"]
  [tailnets.corp.services.myapp]
    name = "svc:myapp"

[entryPoints.web]
  address = ":80"
  tailnet = "corp"
  tailnetService = "myapp"

[entryPoints.websecure]
  address = ":443"
  tailnet = "corp"
  tailnetService = "myapp"
```

Such an entryPoint accepts the Service's traffic instead of traffic addressed
to the node, so clients reach `myapp.<tailnet>.ts.net` rather than this
particular Traefik. A Service spanning several ports is expressed by naming it
on one entryPoint per port, as above; the port advertised is the entryPoint's
own, so the two cannot disagree.

Hosting a Service requires:

- the node to be **tagged** (`advertiseTags`), which Traefik checks at startup
  rather than leaving to the first connection;
- the advertisement to be **approved** in the tailnet, by an admin or an ACL
  auto-approver;
- the entryPoint to name a **port**, so `:0` is refused.

With `terminateTLS`, Tailscale terminates TLS itself and the entryPoint
receives plaintext, so the routers on it must not also expect TLS. Left off, as
it is by default, the connection arrives encrypted and Traefik terminates it
with its own certificates and TLS options, exactly as on any other entryPoint.

### Serving TCP and UDP on one Service

A Service in the default `tcp` mode carries TCP only. That is not a choice
Traefik makes: a host advertises UDP for a Service only in Tailscale's TUN
mode, TUN mode forbids the TCP handlers that Tailscale forwards TCP through,
and the two are mutually exclusive. One Service therefore cannot carry both
through Tailscale's own forwarding.

`mode: tun` sidesteps that by taking delivery of the Service's packets
instead of having them forwarded:

```yaml tab="File (YAML)"
## Static configuration
tailnets:
  corp:
    stateDir: /var/lib/traefik/tsnet/corp
    advertiseTags:
      - tag:proxy
    services:
      myapp:
        mode: tun

entryPoints:
  websecure:
    address: ":443"
    tailnet: corp
    tailnetService: myapp

  dns:
    address: ":53/udp"
    tailnet: corp
    tailnetService: myapp
```

```toml tab="File (TOML)"
## Static configuration
[tailnets.corp]
  stateDir = "/var/lib/traefik/tsnet/corp"
  advertiseTags = ["tag:proxy"]
  [tailnets.corp.services.myapp]
    mode = "tun"

[entryPoints.websecure]
  address = ":443"
  tailnet = "corp"
  tailnetService = "myapp"

[entryPoints.dns]
  address = ":53/udp"
  tailnet = "corp"
  tailnetService = "myapp"
```

In TUN mode the Service is advertised on every port and protocol, and
Tailscale's own network stack stops handling its traffic — it releases the
packets towards what would ordinarily be the operating system. Traefik puts
an in-process network stack there instead, holding the Service's virtual IPs
and answering on them. Nothing reaches the host: there is still no TUN
device, no `NET_ADMIN` and no host routing.

Two consequences follow, both improvements on `tcp` mode:

- **Both protocols on one Service.** TCP and UDP entryPoints may name the
  same Service, as above.
- **Real client addresses.** The packets arrive as they were sent, so
  connections carry the peer's tailnet address without the PROXY protocol,
  and the entryPoint's own `proxyProtocol` option means what it usually does.
  `services.<name>.proxyProtocol` applies to `tcp` mode only.
- **HTTP/3 on a Service.** `http3` on an entryPoint hosting the Service is
  served on the Service's virtual IPs, since its UDP arrives too.

!!! note "TUN mode and routes"

    Giving the node a network device also stops it taking subnet traffic into
    its own stack: packets for [advertised routes](#advertising-routes) are
    released alongside the Service's. The in-process stack answers for them
    as well, so an entryPoint bound to an address inside an advertised route
    is served from it, over TCP and UDP alike, and one tailnet can host
    Services in TUN mode and advertise routes at the same time.

### Client addresses on a Service

Tailscale delivers a Service's traffic to a loopback socket that Traefik
listens on, rather than to the tailnet address directly. Without a PROXY
protocol header every connection would appear to come from `127.0.0.1`, and
the client's tailnet address would be lost to access logs, IP allow-lists and
`X-Forwarded-For` alike.

`proxyProtocol` therefore defaults to version `2`, and Traefik reads the header
itself; nothing needs configuring on the entryPoint. Set it to `0` to turn it
off, accepting that the client address goes with it.

The entryPoint's own `proxyProtocol` option is refused on a Service entryPoint.
It decides which *peers* to trust a header from, and the only peer here is
Tailscale's local forwarder, so it has nothing to judge.

!!! info "What a Service in tcp mode cannot do"

    In `tcp` mode a Service is forwarded as TCP, so `http3` on its entryPoint
    and `tailnetService` on a UDP entryPoint are both refused at startup.
    [`mode: tun`](#serving-tcp-and-udp-on-one-service) lifts both.

## One EntryPoint, Several Listeners

An entryPoint listens on its own `address`, and `tailnetListeners` adds more
places for it to accept on, each on a tailnet. Every listener feeds the same
entryPoint, so the routers attached to it serve all of them alike. An edge that
takes public traffic on a host port and tailnet traffic on a Service and on
routed addresses keeps one entryPoint name for its routers, rather than one
per way in.

```yaml tab="File (YAML)"
## Static configuration
tailnets:
  corp:
    stateDir: /var/lib/traefik/tsnet/corp
    advertiseTags:
      - tag:proxy
    routes:
      - 100.64.30.5/32
      - fd7a:115c:a1e0:ab12::5/128
    services:
      edge:
        mode: tun

entryPoints:
  websecure:
    # Public traffic, from a load balancer that speaks the PROXY protocol.
    address: ":443"
    proxyProtocol:
      trustedIPs:
        - 172.16.0.0/12
    http3: {}
    tailnetListeners:
      - tailnet: corp
        service: edge
      - tailnet: corp
        address: 100.64.30.5
      - tailnet: corp
        address: fd7a:115c:a1e0:ab12::5
```

```toml tab="File (TOML)"
## Static configuration
[tailnets.corp]
  stateDir = "/var/lib/traefik/tsnet/corp"
  advertiseTags = ["tag:proxy"]
  routes = ["100.64.30.5/32", "fd7a:115c:a1e0:ab12::5/128"]
  [tailnets.corp.services.edge]
    mode = "tun"

[entryPoints.websecure]
  address = ":443"
  [entryPoints.websecure.proxyProtocol]
    trustedIPs = ["172.16.0.0/12"]
  [entryPoints.websecure.http3]

  [[entryPoints.websecure.tailnetListeners]]
    tailnet = "corp"
    service = "edge"

  [[entryPoints.websecure.tailnetListeners]]
    tailnet = "corp"
    address = "100.64.30.5"

  [[entryPoints.websecure.tailnetListeners]]
    tailnet = "corp"
    address = "fd7a:115c:a1e0:ab12::5"
```

Each listener names its `tailnet`, and then either:

- a `service`, whose traffic it accepts on the entryPoint's port, exactly as
  [`tailnetService`](#hosting-tailscale-services) would; or
- an `address`: an IP on the entryPoint's port, typically one inside an
  [advertised route](#advertising-routes); an IP and port; or a port alone,
  for the node's own addresses. Left empty, it means the node's own addresses
  on the entryPoint's port.

The entryPoint's own `address` stays what it was, on the host or, with
`tailnet` set, on a tailnet, and may be combined with any number of listeners.

**The PROXY protocol applies to the entryPoint's own address only.** On a
tailnet listener the peer is the client itself or, for a Service in `tcp`
mode, Tailscale's forwarder, whose header is the Service's own
`proxyProtocol` option. Honoring the entryPoint's option there would let a
tailnet client claim any address it liked.

**Every listener binds on its own schedule.** A host address binds at startup
as usual; a tailnet listener binds once its tailnet allows and retries until
it does, so a tailnet that is slow or unreachable holds up only its own
listeners. A listener that fails for good is dropped and logged while the
others keep accepting.

**HTTP/3 and UDP** are served on every listener that carries UDP. A Service in
`tcp` mode carries none: on an entryPoint with `http3` it is left out, with a
log line saying so, and clients reaching it simply stay on TCP; on a UDP
entryPoint it is refused at startup.

A source taken twice, by two listeners or by a listener and the entryPoint's
own address, is refused at startup: the second could never bind.

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
