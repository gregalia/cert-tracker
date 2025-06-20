package main

import (
	"cert-tracker/cfg"
	"cert-tracker/logger"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"log/slog"
	"net"
	"os"
	"runtime"
	"time"
)

var log *slog.Logger

func main() {
	config := loadConfig()
	run := func() {
		// TODO: loop through all resolvers
		netResolver := resolver(config.DNSresolvers[0], config.Timeout)
		// TODO: move logging to called functions to make main more readable
		nameAddressMappings, err := resolve(config.Hostnames, netResolver, config.Timeout)
		if err != nil {
			log.Warn("cannot resolve IP Addresses", "error", err)
			return
		}
		// retry on next scan
		if len(nameAddressMappings) == 0 {
			log.Warn("no name to address mappings")
			return
		}
		log.Info("resolved IP addresses",
			"addresses", nameAddressMappings,
		)
		for _, mapping := range nameAddressMappings {
			for _, ipAddress := range mapping.IPAddresses {
				certificates(mapping.Hostname, ipAddress, config.Timeout)
			}
		}
	}

	run()
	ticker := time.NewTicker(time.Duration(config.ScanInterval))
	defer ticker.Stop()
	for range ticker.C {
		run()
	}
}

type nameAddressMap struct {
	Hostname    cfg.Hostname `json:"hostname"`
	IPAddresses []net.IP     `json:"ipAddresses"`
}

func loadConfig() cfg.Params {
	config, err := cfg.Load()
	if err != nil {
		// doesn't use config params
		log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
		buf := make([]byte, 4096)
		n := runtime.Stack(buf, false) // false = current goroutine only
		stackTrace := string(buf[:n])
		log.Error(
			"failed to load configuration parameters",
			"error", err.Error(),
			"stackTrace", stackTrace,
		)
		os.Exit(1)
	}
	log = logger.New(config)
	log.Info(
		"application configuration loaded",
		"config", config,
	)
	return config
}

func certificates(hostname cfg.Hostname, ipAddress net.IP, timeout cfg.Duration) {
	dialer := &net.Dialer{Timeout: time.Duration(timeout)}
	// TODO: concurrency
	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		net.JoinHostPort(ipAddress.String(), "443"),
		&tls.Config{
			InsecureSkipVerify: true,
			ServerName:         string(hostname),
		})
	if err != nil {
		log.Error("connection error",
			"error", err,
		)
		return
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Warn("no certificates",
			"hostname", hostname,
			"ipAddress", ipAddress,
		)
		return
	}
	for i, cert := range state.PeerCertificates {
		handle(cert, i, hostname, ipAddress)
	}
}

func handle(cert *x509.Certificate, index int, hostname cfg.Hostname, ipAddress net.IP) {
	c := make(map[string]any)

	c["hostname"] = hostname
	c["ipAddress"] = ipAddress
	c["index"] = index

	if index == 0 {
		c["target"] = "leaf"
	} else {
		c["target"] = "intermediate"
	}

	sha256Hash := sha256.Sum256(cert.Raw)
	c["sha256Fingerprint"] = hex.EncodeToString(sha256Hash[:])

	log.Info("certificate scanned",
		"details", c,
	)
}

func resolver(dnsServer net.IP, timeout cfg.Duration) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout: time.Duration(timeout),
			}
			return dialer.DialContext(
				ctx,
				network,
				net.JoinHostPort(dnsServer.String(), "53"),
			)
		},
	}
}

func resolve(hostnames []cfg.Hostname, resolver *net.Resolver, timeout cfg.Duration) ([]nameAddressMap, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout))
	defer cancel()

	mappings := make(chan nameAddressMap, len(hostnames))
	errors := make(chan error, len(hostnames))

	for _, hostname := range hostnames {
		go func() {
			ipAddrs, err := resolver.LookupIPAddr(ctx, string(hostname))
			if err != nil {
				errors <- err
				return
			}
			var addresses []net.IP
			for _, address := range ipAddrs {
				addresses = append(addresses, address.IP)
				ptrs, err := resolver.LookupAddr(ctx, address.String())
				if err != nil {
					log.Warn("reverse lookup error",
						"addr", address.String(),
					)
				}
				for _, ptr := range ptrs {
					log.Info("reverse DNS lookup",
						"addr", address.String(),
						"ptr", ptr,
					)
				}
			}
			mappings <- nameAddressMap{
				Hostname:    hostname,
				IPAddresses: addresses,
			}
		}()
	}

	var results []nameAddressMap
	var errs []error
	for range hostnames {
		select {
		case result := <-mappings:
			results = append(results, result)
		case err := <-errors:
			errs = append(errs, err)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if len(errs) > 0 && len(results) == 0 {
		log.Warn(
			"all DNS lookups failed; logging only first error",
			"error", errs[0],
		)
		for _, err := range errs {
			log.Debug(
				"debug logging all DNS lookup errors",
				"error", err,
			)
		}
	}

	return results, nil
}
