package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	licensesentinel "github.com/green-signal/license-sentinel-go-client"
)

func main() {
	baseURL := flag.String("base-url", "http://127.0.0.1:8080", "license-sentinel base URL")
	clientID := flag.String("client-id", "test-client", "license-sentinel client id")
	nonce := flag.String("nonce", "demo-nonce", "client nonce for check request")
	timeout := flag.Duration("timeout", 5*time.Second, "request timeout")
	flag.Parse()

	client, err := licensesentinel.New(licensesentinel.Config{
		BaseURL:  *baseURL,
		ClientID: *clientID,
	})
	if err != nil {
		log.Fatalf("create client failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := client.Init(ctx); err != nil {
		log.Fatalf("init failed: %v", err)
	}

	result, err := client.Check(ctx, *nonce)
	if err != nil {
		log.Fatalf("check failed: %v", err)
	}
	if !result.OK {
		log.Fatalf("check returned non-ok result code=%s", result.Code)
	}

	fmt.Printf("OK: code=%s checked_at=%s\n", result.Code, result.CheckedAt.Format(time.RFC3339))
	fmt.Printf("Challenge: %s\n", result.Challenge)
}
