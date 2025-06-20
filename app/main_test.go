package main

import (
	"cert-tracker/cfg"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Initialize a test logger to avoid nil pointer panics during tests
	log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	os.Exit(m.Run())
}

func TestNameAddressMap(t *testing.T) {
	// Test the nameAddressMap struct
	hostname := cfg.Hostname("example.com")
	ipAddresses := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")}

	mapping := nameAddressMap{
		Hostname:    hostname,
		IPAddresses: ipAddresses,
	}

	if mapping.Hostname != hostname {
		t.Errorf("Expected hostname %s, got %s", hostname, mapping.Hostname)
	}
	if len(mapping.IPAddresses) != 2 {
		t.Errorf("Expected 2 IP addresses, got %d", len(mapping.IPAddresses))
	}
}

func TestResolver(t *testing.T) {
	tests := []struct {
		name      string
		dnsServer net.IP
		timeout   cfg.Duration
	}{
		{
			name:      "valid DNS server and timeout",
			dnsServer: net.ParseIP("8.8.8.8"),
			timeout:   cfg.Duration(30 * time.Second),
		},
		{
			name:      "IPv6 DNS server",
			dnsServer: net.ParseIP("2001:4860:4860::8888"),
			timeout:   cfg.Duration(10 * time.Second),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := resolver(tt.dnsServer, tt.timeout)

			if resolver == nil {
				t.Error("Expected resolver to be non-nil")
				return
			}

			if !resolver.PreferGo {
				t.Error("Expected PreferGo to be true")
			}

			if resolver.Dial == nil {
				t.Error("Expected Dial function to be set")
			}
		})
	}
}

func TestHandle(t *testing.T) {
	// Create a test certificate
	cert := createTestCertificate(t)

	tests := []struct {
		name       string
		cert       *x509.Certificate
		index      int
		hostname   cfg.Hostname
		ipAddress  net.IP
		wantTarget string
	}{
		{
			name:       "leaf certificate",
			cert:       cert,
			index:      0,
			hostname:   cfg.Hostname("example.com"),
			ipAddress:  net.ParseIP("192.168.1.1"),
			wantTarget: "leaf",
		},
		{
			name:       "intermediate certificate",
			cert:       cert,
			index:      1,
			hostname:   cfg.Hostname("test.com"),
			ipAddress:  net.ParseIP("10.0.0.1"),
			wantTarget: "intermediate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture log output by redirecting to a test logger
			var logOutput strings.Builder
			testLog := slog.New(slog.NewTextHandler(&logOutput, &slog.HandlerOptions{Level: slog.LevelDebug}))
			originalLog := log
			log = testLog
			defer func() { log = originalLog }()

			handle(tt.cert, tt.index, tt.hostname, tt.ipAddress)

			// Verify the log output contains expected information
			output := logOutput.String()
			if !strings.Contains(output, "certificate scanned") {
				t.Error("Expected log message 'certificate scanned'")
			}
			if !strings.Contains(output, string(tt.hostname)) {
				t.Errorf("Expected hostname %s in log output", tt.hostname)
			}
			if !strings.Contains(output, tt.ipAddress.String()) {
				t.Errorf("Expected IP address %s in log output", tt.ipAddress)
			}
			if !strings.Contains(output, tt.wantTarget) {
				t.Errorf("Expected target %s in log output", tt.wantTarget)
			}

			// Verify SHA256 fingerprint format
			expectedHash := sha256.Sum256(tt.cert.Raw)
			expectedFingerprint := hex.EncodeToString(expectedHash[:])
			if !strings.Contains(output, expectedFingerprint) {
				t.Errorf("Expected SHA256 fingerprint %s in log output", expectedFingerprint)
			}
		})
	}
}

func TestResolveWithMockResolver(t *testing.T) {
	// Use the system resolver for these tests
	// Mocking network connections properly is complex and error-prone
	resolver := &net.Resolver{}

	tests := []struct {
		name      string
		hostnames []cfg.Hostname
		timeout   cfg.Duration
		wantErr   bool
	}{
		{
			name:      "empty hostnames",
			hostnames: []cfg.Hostname{},
			timeout:   cfg.Duration(30 * time.Second),
			wantErr:   false,
		},
		{
			name:      "single hostname with short timeout",
			hostnames: []cfg.Hostname{"example.com"},
			timeout:   cfg.Duration(1 * time.Nanosecond), // Very short timeout to trigger timeout
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture log output
			var logOutput strings.Builder
			testLog := slog.New(slog.NewTextHandler(&logOutput, &slog.HandlerOptions{Level: slog.LevelDebug}))
			originalLog := log
			log = testLog
			defer func() { log = originalLog }()

			results, err := resolve(tt.hostnames, resolver, tt.timeout)

			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if len(tt.hostnames) == 0 && len(results) != 0 {
				t.Errorf("Expected 0 results for empty hostnames, got %d", len(results))
			}
		})
	}
}

func TestResolveTimeout(t *testing.T) {
	// Test timeout behavior with a very short timeout
	hostnames := []cfg.Hostname{"nonexistent.example.invalid"}
	timeout := cfg.Duration(1 * time.Nanosecond) // Extremely short timeout

	// Use system resolver for this test
	resolver := &net.Resolver{}

	_, err := resolve(hostnames, resolver, timeout)

	// Should get a timeout error
	if err == nil {
		t.Error("Expected timeout error but got none")
	}
	if err != nil && !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("Expected context deadline exceeded error, got: %v", err)
	}
}

func TestLoadConfigFlow(t *testing.T) {
	// Test the config loading flow without calling the actual loadConfig() function
	// which has side effects (sets global logger, calls logger.New)

	// Create a temporary valid config file
	validConfigContent := `{
		"dnsResolvers": ["8.8.8.8"],
		"hostnames": ["example.com"],
		"timeout": "30s",
		"scanInterval": "5m",
		"logLevel": "info",
		"logAddSource": true
	}`

	tmpFile, err := os.CreateTemp("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write([]byte(validConfigContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Test the config loading logic directly using cfg.Load functionality
	var params cfg.Params
	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	// Test JSON unmarshaling (this is what loadConfig does internally)
	err = json.Unmarshal(data, &params)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify config was loaded correctly
	if len(params.DNSresolvers) != 1 {
		t.Errorf("Expected 1 DNS resolver, got %d", len(params.DNSresolvers))
	}
	if params.DNSresolvers[0].String() != "8.8.8.8" {
		t.Errorf("Expected DNS resolver 8.8.8.8, got %s", params.DNSresolvers[0].String())
	}
	if len(params.Hostnames) != 1 {
		t.Errorf("Expected 1 hostname, got %d", len(params.Hostnames))
	}
	if params.Hostnames[0] != "example.com" {
		t.Errorf("Expected hostname example.com, got %s", params.Hostnames[0])
	}
}

// Helper function to create a test certificate
func createTestCertificate(t *testing.T) *x509.Certificate {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"example.com", "test.com"},
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func BenchmarkHandle(b *testing.B) {
	cert := createTestCertificate(&testing.T{})
	hostname := cfg.Hostname("example.com")
	ipAddress := net.ParseIP("192.168.1.1")

	// Redirect log output to discard
	log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handle(cert, 0, hostname, ipAddress)
	}
}

func BenchmarkResolver(b *testing.B) {
	dnsServer := net.ParseIP("8.8.8.8")
	timeout := cfg.Duration(30 * time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolver(dnsServer, timeout)
	}
}
