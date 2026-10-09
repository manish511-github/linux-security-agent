package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/zooptics/linux-security-agent/internal/policy"
)

func main() {
	configPath := flag.String("config", "configs/policy.json", "path to the policy file")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: agent [-config path] <domain>")
		os.Exit(2)
	}

	engine, err := policy.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load policy: %v\n", err)
		os.Exit(1)
	}

	decision := engine.Evaluate(flag.Arg(0))
	fmt.Printf("domain=%s action=%s", flag.Arg(0), decision.Action)
	if decision.Reason != "" {
		fmt.Printf(" reason=%q", decision.Reason)
	}
	fmt.Println()
}
