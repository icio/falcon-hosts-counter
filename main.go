package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var (
	clientID     = flag.String("client-id", "", "oauth client `id` (required)")
	clientSecret = flag.String("client-secret", "", "oauth client `secret` (required)")
	apiBase      = flag.String("api-base", "https://api.us-2.crowdstrike.com", "api base `url`")
	interval     = flag.Duration("interval", time.Minute, "sleep `1m` between checks")
	quiet        = flag.Bool("q", false, "quiet 'same' logs")
)

func main() {
	flag.Parse()

	if *clientID == "" {
		fmt.Fprintln(flag.CommandLine.Output(), "-client-id is required")
	}
	if *clientSecret == "" {
		fmt.Fprintln(flag.CommandLine.Output(), "-client-secret is required")
	}
	if *clientID == "" || *clientSecret == "" {
		flag.CommandLine.Usage()
		os.Exit(2)
	}

	config := clientcredentials.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		TokenURL:     *apiBase + "/oauth2/token",
	}

	scrollURL := *apiBase + "/devices/queries/devices-scroll/v1"
	if _, err := url.Parse(scrollURL); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	client := oauth2.NewClient(ctx, config.TokenSource(ctx))

	var maxDevices int
	attempt := func() error {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET", scrollURL, nil)
		if err != nil {
			log.Fatal(err)
		}

		const ua = "tailscale_falconhosts_0.1"
		req.Header.Add("User-Agent", ua)
		req.Header.Add("CrowdStrike-SDK", ua)

		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("reading body: %w", err)
		}

		if res.StatusCode != 200 {
			return fmt.Errorf("unexpected status code: %s  body=%q", res.Status, body)
		}

		var resbody struct {
			Resources []string `json:"resources"`
		}
		if err := json.Unmarshal(body, &resbody); err != nil {
			return fmt.Errorf("unmarshalling body: %w  body=%q", err, body)
		}

		if len(resbody.Resources) < maxDevices {
			return fmt.Errorf("missing %d devices! body=%q", maxDevices-len(resbody.Resources), body)
		}
		if len(resbody.Resources) > maxDevices {
			maxDevices = len(resbody.Resources)
			return fmt.Errorf("new max: %d devices  body=%q", maxDevices, body)
		}
		return nil
	}

	for {
		err := attempt()
		if err != nil {
			log.Println(err)
		} else if !*quiet {
			log.Println("same")
		}
		time.Sleep(*interval)
	}
}
