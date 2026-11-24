# Tailnets

This directory is a Go module of its own, `github.com/traefik/traefik/tailnet`.
It holds the implementation behind the `tailnets` options: an embedded
Tailscale node ([tsnet](https://tailscale.com/kb/1244/tsnet)) per tailnet,
handed to Traefik as its [network extension](../pkg/network/network.go).

It is a separate module so that the traefik module does not depend on
Tailscale. The `traefik` binary built from the repository root has the tailnet
options and refuses a configuration that sets them; the one built from here is
the same command with the tailnets linked in.

```bash
# From the repository root.
make binary FLAGS="-C tailnet"    # tailnet/dist/<os>/<arch>/traefik
go -C tailnet test ./...
(cd tailnet && golangci-lint run --config ../.golangci.yml --disable gomoddirectives)
```

The module always builds against the traefik module it sits in, through a
`replace` directive, and repeats that module's own `replace` and `exclude`
directives, which only apply from the main module of a build. Its `go`
directive follows `tailscale.com`, which is why the linter's `go.mod` rules
are left to the traefik module.
