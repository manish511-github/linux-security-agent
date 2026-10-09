package proxy

import (
	"context"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zooptics/linux-security-agent/internal/policy"
)

var blockPage = template.Must(template.New("block-page").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Access blocked</title></head>
<body style="font-family:system-ui,sans-serif;max-width:680px;margin:80px auto;padding:0 24px;color:#202124">
  <h1>Access blocked</h1>
  <p>The security policy blocked access to <strong>{{.Domain}}</strong>.</p>
  {{if .Reason}}<p>Reason: {{.Reason}}</p>{{end}}
</body>
</html>`))

type Server struct {
	engine    *policy.Engine
	transport http.RoundTripper
	dialer    func(context.Context, string, string) (net.Conn, error)
	logger    *log.Logger
}

func New(engine *policy.Engine, logger *log.Logger) *Server {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	return &Server{
		engine: engine,
		transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		dialer: dialer.DialContext,
		logger: logger,
	}
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	domain := requestDomain(request)
	if domain == "" {
		http.Error(writer, "missing destination host", http.StatusBadRequest)
		return
	}

	decision := s.engine.Evaluate(domain)
	s.logger.Printf("method=%s domain=%s action=%s", request.Method, domain, decision.Action)
	if decision.Action == policy.Block {
		s.writeBlocked(writer, domain, decision.Reason)
		return
	}

	if request.Method == http.MethodConnect {
		s.serveTunnel(writer, request, domain)
		return
	}
	s.serveHTTP(writer, request)
}

func (s *Server) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	outbound := request.Clone(request.Context())
	outbound.RequestURI = ""
	if outbound.URL.Scheme == "" {
		outbound.URL.Scheme = "http"
	}
	if outbound.URL.Host == "" {
		outbound.URL.Host = outbound.Host
	}
	removeHopByHopHeaders(outbound.Header)

	response, err := s.transport.RoundTrip(outbound)
	if err != nil {
		s.logger.Printf("forward domain=%s error=%v", requestDomain(request), err)
		http.Error(writer, "upstream connection failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()

	removeHopByHopHeaders(response.Header)
	copyHeaders(writer.Header(), response.Header)
	writer.WriteHeader(response.StatusCode)
	if _, err := io.Copy(writer, response.Body); err != nil {
		s.logger.Printf("response copy domain=%s error=%v", requestDomain(request), err)
	}
}

func (s *Server) serveTunnel(writer http.ResponseWriter, request *http.Request, domain string) {
	target := request.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(domain, "443")
	}

	upstream, err := s.dialer(request.Context(), "tcp", target)
	if err != nil {
		s.logger.Printf("tunnel domain=%s error=%v", domain, err)
		http.Error(writer, "upstream connection failed", http.StatusBadGateway)
		return
	}

	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(writer, "connection tunneling is unavailable", http.StatusInternalServerError)
		return
	}

	client, buffered, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		return
	}

	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	if err := buffered.Flush(); err != nil {
		client.Close()
		upstream.Close()
		return
	}

	done := make(chan struct{}, 2)
	go copyConnection(upstream, client, done)
	go copyConnection(client, upstream, done)
	<-done
	client.Close()
	upstream.Close()
}

func copyConnection(destination net.Conn, source net.Conn, done chan<- struct{}) {
	_, _ = io.Copy(destination, source)
	done <- struct{}{}
}

func (s *Server) writeBlocked(writer http.ResponseWriter, domain, reason string) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusForbidden)
	if err := blockPage.Execute(writer, struct {
		Domain string
		Reason string
	}{Domain: domain, Reason: reason}); err != nil {
		s.logger.Printf("render block page: %v", err)
	}
}

func requestDomain(request *http.Request) string {
	authority := request.Host
	if request.URL != nil && request.URL.Host != "" {
		authority = request.URL.Host
	}
	parsed, err := url.Parse("//" + authority)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

func removeHopByHopHeaders(headers http.Header) {
	if connection := headers.Get("Connection"); connection != "" {
		for value := range strings.SplitSeq(connection, ",") {
			headers.Del(strings.TrimSpace(value))
		}
	}
	for _, header := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		headers.Del(header)
	}
}

func copyHeaders(destination, source http.Header) {
	for key, values := range source {
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}
