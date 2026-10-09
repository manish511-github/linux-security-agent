# Linux Security Agent

The first milestone is a small policy engine. It loads domain rules from JSON and returns an `allow` or `block` decision.

Run it from this directory:

```bash
go run ./cmd/agent blocked.example
go run ./cmd/agent allowed.example
go test ./...
```

Expected decisions:

```text
domain=blocked.example action=block reason="Blocked by company policy"
domain=allowed.example action=allow
```

Next, this policy engine will be connected to an explicit HTTP proxy.
