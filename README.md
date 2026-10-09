# Linux Security Agent

The current milestone is an explicit HTTP/HTTPS proxy backed by a JSON domain policy. HTTP requests are forwarded or answered with a block page. Allowed HTTPS connections use a byte-for-byte `CONNECT` tunnel and remain encrypted.

Run it from this directory:

```bash
GOCACHE=/tmp/linux-security-agent-go-cache go run ./cmd/agent blocked.example
GOCACHE=/tmp/linux-security-agent-go-cache go run ./cmd/agent allowed.example
GOCACHE=/tmp/linux-security-agent-go-cache go test ./...
```

Expected decisions:

```text
domain=blocked.example action=block reason="Blocked by company policy"
domain=allowed.example action=allow
```

Start the proxy:

```bash
GOCACHE=/tmp/linux-security-agent-go-cache go run ./cmd/agent -listen 127.0.0.1:8080
```

In another terminal, test allowed HTTP and HTTPS traffic:

```bash
curl --proxy http://127.0.0.1:8080 http://example.com
curl --proxy http://127.0.0.1:8080 https://example.com
```

Test a blocked request:

```bash
curl --proxy http://127.0.0.1:8080 http://blocked.example
```

The proxy needs no root privileges. It handles only applications explicitly configured to use it; transparent interception with nftables and TPROXY is a later milestone.
