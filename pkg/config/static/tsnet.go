package static

// TsnetConfig is the static configuration for the embedded Tailscale (tsnet)
// nodes. Each entry joins one tailnet in-process; a ServersTransport (HTTP or
// TCP) selects one by name with its `tailnet` option, and every backend dial
// through that transport then goes over the tailnet instead of the host
// network stack.
type TsnetConfig struct {
	Tailnets map[string]*TsnetTailnet `description:"Tailnets to join, by the name serversTransports reference them as." json:"tailnets,omitempty" toml:"tailnets,omitempty" yaml:"tailnets,omitempty" export:"true"`
}

// TsnetTailnet is one embedded Tailscale node.
type TsnetTailnet struct {
	// Hostname is the device name on the tailnet. Defaults to the tsnet
	// default (derived from the binary name) when empty.
	Hostname string `description:"Device hostname on the tailnet." json:"hostname,omitempty" toml:"hostname,omitempty" yaml:"hostname,omitempty" export:"true"`
	// StateDir persists the node identity and WireGuard state. Required:
	// multiple embedded nodes cannot share tsnet's single default directory.
	StateDir string `description:"Directory holding the node state and identity." json:"stateDir,omitempty" toml:"stateDir,omitempty" yaml:"stateDir,omitempty" export:"true"`
	// AuthKey authenticates the first join; unneeded once StateDir holds a
	// node identity. AuthKeyFile takes precedence; with both empty tsnet
	// falls back to the TS_AUTHKEY environment variable.
	AuthKey     string `description:"Tailscale auth key for the first join." json:"authKey,omitempty" toml:"authKey,omitempty" yaml:"authKey,omitempty"`
	AuthKeyFile string `description:"File containing the Tailscale auth key for the first join." json:"authKeyFile,omitempty" toml:"authKeyFile,omitempty" yaml:"authKeyFile,omitempty"`
	// ControlURL overrides the coordination server (Headscale etc.); empty
	// means the Tailscale default.
	ControlURL string `description:"Coordination server URL." json:"controlURL,omitempty" toml:"controlURL,omitempty" yaml:"controlURL,omitempty"`
	// Ephemeral registers the node as ephemeral: it is removed from the
	// tailnet after going offline.
	Ephemeral bool `description:"Register the node as ephemeral." json:"ephemeral,omitempty" toml:"ephemeral,omitempty" yaml:"ephemeral,omitempty" export:"true"`
}
