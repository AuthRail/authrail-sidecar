# Contributing

We welcome fixes and improvements to AuthRail Sidecar. For a larger change,
open an issue first so we can agree on how it should fit the Runtime protocol.
For a small fix, a pull request is fine.

## Before opening a pull request

Use Go 1.26 or later and run these commands from the repository root:

```bash
go test ./...
go vet ./...
go build -o /tmp/authrail-sidecar ./cmd/authrail-sidecar
```

Describe what changed, why it matters, and how you checked it. Add tests when
you change a security check, a decision, or recovery behavior. The sidecar
owns Rail decisions; adapters should use the shared Runtime protocol instead
of making their own decisions.

Please keep credentials, customer data, and local state files out of code,
tests, issues, and logs. Send security concerns to the maintainers privately
so they can be handled before public discussion.

[Architecture](ARCHITECTURE.md) explains the current boundaries.
