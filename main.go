package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"
)

func main() {
	hostnames := getHostnames()
	DNSServer := getDNSServer()
	logger.Info("config read success", "dnsServer", DNSServer, "hostnames", hostnames)
	resolver := getResolver(DNSServer)
	logger.Info("got DNS resolver")
	ipAddresses, err := resolveHostnames(hostnames, resolver)
	if err != nil{
		logger.Error("cannot resolve IP Addresses")
	}
	logger.Info("got IP addresses", "addresses", ipAddresses)
}

// TODO: Use net URL hostname?
type hostname string

var logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))

type config struct {
	Resolver  string     `json:"resolver"`
	Hostnames []hostname `json:"hostnames"`
}

// TODO: Take parameter
func parseConfig() (*config, error) {
	file, fileErr := os.ReadFile("config.json")
	if fileErr != nil {
		return nil, fileErr
	}

	var config config
	if err := json.Unmarshal(file, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func getHostnames() []hostname {
	config, err := parseConfig()
	if err != nil {
		logger.Error("cannot get hostnames", "error", err)
		os.Exit(1)
	}
	return config.Hostnames
}

func getDNSServer() net.IP {
	config, err := parseConfig()
	if err != nil {
		logger.Error("cannot get resolver", "error", err)
		os.Exit(1)
	}
	resolver := net.ParseIP(config.Resolver)
	if resolver == nil {
		logger.Error("cannot get resolver", "error", err)
		os.Exit(1)
	}
	return resolver
}

func getResolver(DNSServer net.IP) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout: time.Second * 5,
			}
			return dialer.DialContext(ctx, network, fmt.Sprintf("%v:53", DNSServer))
		},
	}
}

func resolveHostnames(hostnames []hostname, resolver *net.Resolver) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var results []net.IP
	for _, hostname := range hostnames {
		addresses, err := resolver.LookupIPAddr(ctx, string(hostname))
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			results = append(results, address.IP)
		}
	}
	return results, nil
}
