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
	"reflect"
	"strings"
	"time"
)

var DNSresolvers = cfg.DNSresolvers
var Hostnames = cfg.Hostnames
var Timeout = cfg.Timeout
var ScanInterval = cfg.ScanInterval

var log = logger.Log

func main() {
	log.Info("start")

	run := func() {
		hostnames := Hostnames
		// TODO: loop through all resolvers
		DNSServer := DNSresolvers[0]
		log.Info("configuration", "dnsServer", DNSServer, "hostnames", hostnames)
		netResolver := resolver(DNSServer)
		log.Info("DNS resolver")
		nameAddressMappings, err := resolve(hostnames, netResolver)
		if err != nil {
			log.Warn("cannot resolve IP Addresses", "error", err)
			return
		}
		if len(nameAddressMappings) == 0 {
			log.Warn("no name: address mappings")
			return
		}
		log.Info("got IP addresses", "addresses", nameAddressMappings)
		for _, mapping := range nameAddressMappings {
			for _, ipAddress := range mapping.IPAddresses {
				certificates(mapping.Hostname, ipAddress)
			}
		}
	}

	run()
	ticker := time.NewTicker(time.Duration(ScanInterval))
	defer ticker.Stop()
	for range ticker.C {
		run()
	}
}

type nameAddressMap struct {
	Hostname    cfg.Hostname
	IPAddresses []net.IP
}

func certificates(hostname cfg.Hostname, ipAddress net.IP) {
	dialer := &net.Dialer{Timeout: time.Duration(Timeout)}
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
		log.Error("connection error", "error", err)
		return
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Warn("no certificates", "hostname", hostname, "ipAddress", ipAddress)
		return
	}
	for i, cert := range state.PeerCertificates {
		log.Info("cert info", "hostname", hostname, "ipAddress", ipAddress)
		logCertDetails(cert, i)
	}
}

func logCertDetails(cert *x509.Certificate, index int) {
	v := reflect.ValueOf(*cert)
	t := v.Type()
	c := make(map[string]any)

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)

		// Skip unexported fields
		// if !field.IsExported() {
		// 	continue
		// }
		if strings.HasPrefix(field.Name, "Raw") {
			continue
		}

		c["foo"] = "bar"
		c[field.Name] = value.Interface()
	}
	sha256Hash := sha256.Sum256(cert.Raw)
	sha256HashString := hex.EncodeToString(sha256Hash[:])
	c["sha256Fingerprint"] = sha256HashString
	certType := "intermediate"
	if index == 0 {
		certType = "leaf"
	}
	log.Info("certificate", certType, c)
}


func resolver(dnsServer net.IP) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout: time.Duration(Timeout),
			}
			return dialer.DialContext(
				ctx,
				network,
				net.JoinHostPort(dnsServer.String(), "53"),
			)
		},
	}
}

func resolve(hostnames []cfg.Hostname, resolver *net.Resolver) ([]nameAddressMap, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Timeout))
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
					log.Warn("reverse lookup error", "addr", address.String())
				}
				for _, ptr := range ptrs {
					log.Info("reverse DNS lookup", "addr", address.String(), "ptr", ptr)
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
		if log.Enabled(context.Background(), slog.LevelDebug) {
			for _, err := range errs {
				log.Debug(
					"debug logging all DNS lookup errors",
					"error", err,
				)
			}
		}
	}

	return results, nil
}
