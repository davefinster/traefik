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
}

// SetDefaults sets the default values.
func (t *Tailnet) SetDefaults() {}
