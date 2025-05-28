package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"
)

const timeout = time.Second * 30
const interval = time.Minute * 5
const logLevel = slog.LevelInfo
const logLocationAt = slog.LevelWarn // add file + line + function to logs

func main() {
	logger.Info("start")

	run := func() {
		hostnames := hostnames()
		DNSServer := dnsServer()
		logger.Info("configuration", "dnsServer", DNSServer, "hostnames", hostnames)
		netResolver := resolver(DNSServer)
		logger.Info("DNS resolver")
		nameAddressMappings, err := resolve(hostnames, netResolver)
		if err != nil {
			logger.Warn("cannot resolve IP Addresses", "error", err)
			return
		}
		if len(nameAddressMappings) == 0 {
			logger.Warn("no name: address mappings")
			return
		}
		logger.Info("got IP addresses", "addresses", nameAddressMappings)
		for _, mapping := range nameAddressMappings {
			for _, ipAddress := range mapping.IPAddresses {
				certificates(mapping.Hostname, ipAddress)
			}
		}
	}

	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		run()
	}
}

// TODO: Use net URL hostname?
type hostname string

type config struct {
	Resolver  string     `json:"resolver"`
	Hostnames []hostname `json:"hostnames"`
}

type nameAddressMap struct {
	Hostname    hostname
	IPAddresses []net.IP
}

type hexHandler struct {
	slog.Handler
}

type locationHandler struct {
	handler slog.Handler
}

func (h *locationHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *locationHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= logLocationAt {
		// Skip 3 frames: Handle + log function + user code
		pc, file, line, ok := runtime.Caller(3)
		if ok {
			r.Add(
				"file", slog.StringValue(file),
				"line", slog.IntValue(line),
				"function", slog.StringValue(runtime.FuncForPC(pc).Name()),
			)
		}
	}
	return h.handler.Handle(ctx, r)
}

func (h *locationHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &locationHandler{h.handler.WithAttrs(attrs)}
}

func (h *locationHandler) WithGroup(name string) slog.Handler {
	return &locationHandler{h.handler.WithGroup(name)}
}

// Replace binary values with hex strings
func (h *hexHandler) Handle(ctx context.Context, r slog.Record) error {
	// safe to modify clone
	r2 := r.Clone()
	r2.Attrs(func(a slog.Attr) bool {
		if v := a.Value; v.Kind() == slog.KindAny {
			if b, ok := v.Any().([]byte); ok {
				r2.Add(a.Key, slog.StringValue(hex.EncodeToString(b)))
				return false
			}
		}
		return true
	})

	return h.Handler.Handle(ctx, r2)
}

var logger = slog.New(&locationHandler{
	handler: &hexHandler{
		Handler: slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: logLevel,
		}),
	},
})

func certificates(hostname hostname, ipAddress net.IP) {
	dialer := &net.Dialer{Timeout: timeout}
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
		logger.Error("connection error", "error", err)
		return
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		logger.Warn("no certificates", "hostname", hostname, "ipAddress", ipAddress)
		return
	}
	for i, cert := range state.PeerCertificates {
		logger.Info("cert info", "hostname", hostname, "ipAddress", ipAddress)
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
	logger.Info("certificate", certType, c)
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

func hostnames() []hostname {
	config, err := parseConfig()
	if err != nil {
		logger.Error("cannot get hostnames", "error", err)
		os.Exit(1)
	}
	return config.Hostnames
}

func dnsServer() net.IP {
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

func resolver(dnsServer net.IP) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout: timeout,
			}
			return dialer.DialContext(
				ctx,
				network,
				net.JoinHostPort(dnsServer.String(), "53"),
			)
		},
	}
}

func resolve(hostnames []hostname, resolver *net.Resolver) ([]nameAddressMap, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
		logger.Warn(
			"all DNS lookups failed; logging only first error",
			"error", errs[0],
		)
		if logger.Enabled(context.Background(), slog.LevelDebug) {
			for _, err := range errs {
				logger.Debug(
					"debug logging all DNS lookup errors",
					"error", err,
				)
			}
		}
	}

	return results, nil
}
