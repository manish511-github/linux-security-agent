package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zooptics/linux-security-agent/internal/policy"
	"github.com/zooptics/linux-security-agent/internal/proxy"
)

func main() {
	configPath := flag.String("config", "configs/policy.json", "path to the policy file")
	listenAddress := flag.String("listen", "127.0.0.1:8080", "proxy listen address")
	flag.Parse()

	if flag.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: agent [-config path] [-listen address] [domain]")
		os.Exit(2)
	}

	engine, err := policy.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load policy: %v\n", err)
		os.Exit(1)
	}

	if flag.NArg() == 1 {
		printDecision(flag.Arg(0), engine.Evaluate(flag.Arg(0)))
		return
	}

	logger := log.New(os.Stdout, "agent ", log.LstdFlags|log.LUTC)
	server := &http.Server{
		Addr:              *listenAddress,
		Handler:           proxy.New(engine, logger),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-shutdownContext.Done()
		context, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(context); err != nil {
			logger.Printf("shutdown error: %v", err)
		}
	}()

	logger.Printf("proxy listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("proxy server: %v", err)
	}
}

func printDecision(domain string, decision policy.Decision) {
	fmt.Printf("domain=%s action=%s", domain, decision.Action)
	if decision.Reason != "" {
		fmt.Printf(" reason=%q", decision.Reason)
	}
	fmt.Println()
}
