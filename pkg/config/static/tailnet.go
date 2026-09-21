package static

// Tailnet is one embedded Tailscale node (tailscale.com/tsnet), joined
// in-process in userspace: no TUN device, and no routing-table or netfilter
// footprint, so it coexists with a tailscaled running on the same host.
//
// EntryPoints reference a tailnet by name to accept connections on it instead
// of on the host network, and serversTransports reference one to dial their
// backends over it. The same tailnet may serve both at once: one node, one
// device on the tailnet.
type Tailnet struct {
	// Hostname is the device name on the tailnet, and the basis of its
	// MagicDNS name. Defaults to the tsnet default, which is derived from
	// the binary name.
	Hostname string `description:"Device hostname on the tailnet." json:"hostname,omitempty" toml:"hostname,omitempty" yaml:"hostname,omitempty" export:"true"`

	// StateDir persists the node identity and WireGuard state across
	// restarts. Required: tsnet derives a single default directory from the
	// binary name, which several nodes in one process cannot share.
	StateDir string `description:"Directory holding the node state and identity. Required." json:"stateDir,omitempty" toml:"stateDir,omitempty" yaml:"stateDir,omitempty" export:"true"`

	// AuthKey authenticates the first join, and is unused once StateDir
	// holds a node identity. It also accepts an OAuth client secret
	// (tskey-client-...), which requires AdvertiseTags to be set.
	// AuthKeyFile takes precedence. With both empty, tsnet falls back to the
	// TS_AUTHKEY environment variable.
	AuthKey string `description:"Tailscale auth key, or OAuth client secret, for the first join." json:"authKey,omitempty" toml:"authKey,omitempty" yaml:"authKey,omitempty" loggable:"false"`

	// AuthKeyFile reads the auth key from a file. The file is read at the
	// first join attempt rather than at startup, so an auth key delivered
	// by an external system after Traefik starts is picked up on a retry
	// instead of holding up the whole process.
	AuthKeyFile string `description:"File containing the Tailscale auth key for the first join." json:"authKeyFile,omitempty" toml:"authKeyFile,omitempty" yaml:"authKeyFile,omitempty"`

	// ControlURL overrides the coordination server, for Headscale and other
	// self-hosted control planes. Empty means the Tailscale default.
	ControlURL string `description:"Coordination server URL. Defaults to the Tailscale control plane." json:"controlURL,omitempty" toml:"controlURL,omitempty" yaml:"controlURL,omitempty" export:"true"`

	// Ephemeral registers the node as ephemeral, so the control plane removes
	// it shortly after it goes offline. Suited to replicas that come and go;
	// with it set, StateDir need not outlive the process.
	Ephemeral bool `description:"Register the node as ephemeral, so it is removed from the tailnet after going offline." json:"ephemeral,omitempty" toml:"ephemeral,omitempty" yaml:"ephemeral,omitempty" export:"true"`

	// AdvertiseTags are the ACL tags the node advertises (tag:...).
	// Required when AuthKey is an OAuth client secret: Tailscale refuses such
	// a join without explicit tags.
	AdvertiseTags []string `description:"ACL tags advertised by the node (tag:...). Required when the auth key is an OAuth client secret." json:"advertiseTags,omitempty" toml:"advertiseTags,omitempty" yaml:"advertiseTags,omitempty" export:"true"`

	// Port is the local UDP port for WireGuard and peer-to-peer traffic.
	// Zero picks one automatically, which is what most deployments want;
	// pin it when a firewall has to be opened for direct connections.
	Port uint16 `description:"Local UDP port for WireGuard traffic. Zero selects one automatically." json:"port,omitempty" toml:"port,omitempty" yaml:"port,omitempty" export:"true"`

	// Routes are CIDR prefixes the node advertises into the tailnet, subject
	// to approval by an admin or an ACL auto-approver.
	//
	// The node answers for an advertised address only where an entryPoint
	// binds it: this gives Traefik additional addresses on the tailnet, and
	// is not a subnet router. Traffic to an advertised address that no
	// entryPoint binds is not answered.
	Routes []string `description:"CIDR prefixes advertised into the tailnet. Traefik answers only on the addresses its entryPoints bind." json:"routes,omitempty" toml:"routes,omitempty" yaml:"routes,omitempty" export:"true"`

	// Services are the Tailscale Services this node can host, keyed by the
	// name entryPoints reference them as.
	Services map[string]*TailnetService `description:"Tailscale Services this node can host, by the name entryPoints reference them as." json:"services,omitempty" toml:"services,omitempty" yaml:"services,omitempty" export:"true"`
}

// SetDefaults sets the default values.
func (t *Tailnet) SetDefaults() {}

// TailnetService is one Tailscale Service hosted by a tailnet node. An
// entryPoint referencing it accepts that Service's traffic instead of
// traffic addressed to the node itself, so the Service's name and virtual
// IPs are what clients reach rather than this particular node.
//
// Hosting a Service requires the node to be tagged (see AdvertiseTags), and
// the advertisement to be approved by an admin or an ACL auto-approver.
type TailnetService struct {
	// Mode is how the Service is served.
	//
	// "tcp" (the default) forwards TCP to the entryPoint through Tailscale's
	// own serve configuration. It carries TCP only, on the ports entryPoints
	// name, and arrives over a loopback socket, so the client's address
	// comes from the PROXY protocol header below.
	//
	// "tun" advertises the Service on every port and protocol and takes
	// delivery of its packets directly, in an in-process network stack. It
	// is the only way to serve TCP, UDP and HTTP/3 on one Service, and
	// connections carry the peer's real address without the PROXY protocol.
	// It changes how the whole node handles packets: the same stack then
	// answers for the node's routed addresses too.
	Mode string `description:"How the Service is served: tcp (Tailscale forwards TCP to the entryPoint) or tun (Traefik takes the Service's packets directly, carrying TCP and UDP)." json:"mode,omitempty" toml:"mode,omitempty" yaml:"mode,omitempty" export:"true"`

	// Name is the Tailscale Service name, which must start with "svc:".
	// Defaults to "svc:" followed by the key this Service is configured
	// under.
	Name string `description:"Tailscale Service name (svc:...). Defaults to svc: followed by the configuration key." json:"name,omitempty" toml:"name,omitempty" yaml:"name,omitempty" export:"true"`

	// TerminateTLS lets Tailscale terminate TLS before forwarding to the
	// entryPoint, in which case the Service's own fully-qualified name is
	// the only permitted SNI. Off by default: TLS is Traefik's, as it is on
	// any other entryPoint.
	TerminateTLS bool `description:"Let Tailscale terminate TLS before forwarding to the entryPoint, instead of Traefik terminating it." json:"terminateTLS,omitempty" toml:"terminateTLS,omitempty" yaml:"terminateTLS,omitempty" export:"true"`

	// ProxyProtocol is the PROXY protocol version Tailscale uses when it
	// forwards a connection to the entryPoint, or 0 to disable it.
	//
	// It defaults to 2 because a Service is delivered over a loopback
	// socket: without the header every connection appears to come from
	// 127.0.0.1, and the client's tailnet address is lost to access logs,
	// IP allow-lists and X-Forwarded-For alike.
	ProxyProtocol int `description:"PROXY protocol version Tailscale uses to forward connections, carrying the client address. 0 disables it." json:"proxyProtocol,omitempty" toml:"proxyProtocol,omitempty" yaml:"proxyProtocol,omitempty" export:"true"`
}

// Service modes.
const (
	// TailnetServiceModeTCP forwards TCP through Tailscale's serve
	// configuration. TCP only.
	TailnetServiceModeTCP = "tcp"
	// TailnetServiceModeTUN takes delivery of the Service's packets in an
	// in-process network stack. TCP and UDP.
	TailnetServiceModeTUN = "tun"
)

// SetDefaults sets the default values.
func (t *TailnetService) SetDefaults() {
	t.Mode = TailnetServiceModeTCP
	t.ProxyProtocol = 2
}

// TailnetListener is one more place an entryPoint accepts on, on a tailnet,
// beside the entryPoint's own address. Every listener feeds the same
// entryPoint, so the routers attached to it serve all of them alike: an edge
// taking public traffic on a host port and tailnet traffic on a Service and a
// routed address keeps one entryPoint name for its routers to use.
//
// The entryPoint's proxyProtocol applies to its own address only. On a
// tailnet listener the peer is the client itself or, for a Service in tcp
// mode, Tailscale's forwarder, whose header is the Service's own
// proxyProtocol option; honoring the entryPoint's here would let a tailnet
// client claim any address it liked.
type TailnetListener struct {
	// Tailnet names the tailnet to accept on, as configured under tailnets.
	Tailnet string `description:"Tailnet to accept on, by its name in the static configuration." json:"tailnet,omitempty" toml:"tailnet,omitempty" yaml:"tailnet,omitempty" export:"true"`

	// Service accepts the named Tailscale Service's traffic, on the port of
	// the entryPoint's own address. Mutually exclusive with Address.
	Service string `description:"Tailscale Service whose traffic to accept, on the entryPoint's port." json:"service,omitempty" toml:"service,omitempty" yaml:"service,omitempty" export:"true"`

	// Address is where on the tailnet to accept: an IP, typically one inside
	// an advertised route, or an IP and port, or a port alone for the node's
	// own addresses. The port defaults to the entryPoint's, and an empty
	// address means the node's own addresses on it. Mutually exclusive with
	// Service.
	Address string `description:"Address on the tailnet to accept on: an IP, an IP and port, or a port alone for the node's own addresses. Defaults to the node's own addresses on the entryPoint's port." json:"address,omitempty" toml:"address,omitempty" yaml:"address,omitempty" export:"true"`
}
