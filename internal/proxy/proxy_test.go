package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zooptics/linux-security-agent/internal/policy"
)

func TestHTTPAllowAndBlock(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("upstream response"))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	engine := &policy.Engine{
		Version:       1,
		DefaultAction: policy.Allow,
		Rules: []policy.Rule{
			{Domain: "blocked.example", Action: policy.Block, Reason: "test policy"},
		},
	}
	proxyServer := httptest.NewServer(New(engine, nil))
	defer proxyServer.Close()

	client := proxyClient(t, proxyServer.URL)
	response, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("allowed request: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "upstream response" {
		t.Fatalf("allowed response = %d %q", response.StatusCode, body)
	}

	blockedURL := fmt.Sprintf("http://blocked.example:%s/private", upstreamURL.Port())
	response, err = client.Get(blockedURL)
	if err != nil {
		t.Fatalf("blocked request: %v", err)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked status = %d, want 403", response.StatusCode)
	}
	if !strings.Contains(string(body), "test policy") {
		t.Fatalf("block page does not contain policy reason: %q", body)
	}
}

func TestConnectTunnelAllowAndBlock(t *testing.T) {
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	go runEchoServer(echoListener)

	engine := &policy.Engine{
		Version:       1,
		DefaultAction: policy.Allow,
		Rules:         []policy.Rule{{Domain: "blocked.example", Action: policy.Block}},
	}
	proxyServer := httptest.NewServer(New(engine, nil))
	defer proxyServer.Close()
	proxyAddress := strings.TrimPrefix(proxyServer.URL, "http://")

	connection, response := connect(t, proxyAddress, echoListener.Addr().String())
	if response.StatusCode != http.StatusOK {
		t.Fatalf("allowed CONNECT status = %d", response.StatusCode)
	}
	if _, err := connection.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(connection, reply); err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if string(reply) != "hello" {
		t.Fatalf("tunnel reply = %q", reply)
	}

	connection, response = connect(t, proxyAddress, "blocked.example:443")
	defer connection.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked CONNECT status = %d, want 403", response.StatusCode)
	}
}

func proxyClient(t *testing.T, address string) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
}

func connect(t *testing.T, proxyAddress, target string) (net.Conn, *http.Response) {
	t.Helper()
	connection, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodConnect})
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}
	return connection, response
}

func runEchoServer(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer connection.Close()
			_, _ = io.Copy(connection, connection)
		}()
	}
}

func TestRequestDomain(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "http://EXAMPLE.com:80/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := requestDomain(request); got != "example.com" {
		t.Fatalf("requestDomain() = %q", got)
	}
}
