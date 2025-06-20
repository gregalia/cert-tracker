package cfg

import (
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"
)

func TestHostname_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Hostname
		wantErr bool
	}{
		{
			name:    "valid hostname",
			input:   `"example.com"`,
			want:    Hostname("example.com"),
			wantErr: false,
		},
		{
			name:    "valid subdomain",
			input:   `"api.example.com"`,
			want:    Hostname("api.example.com"),
			wantErr: false,
		},
		{
			name:    "valid hyphenated hostname",
			input:   `"my-server.example.com"`,
			want:    Hostname("my-server.example.com"),
			wantErr: false,
		},
		{
			name:    "invalid - IP address",
			input:   `"192.168.1.1"`,
			want:    Hostname(""),
			wantErr: true,
		},
		{
			name:    "invalid - empty string",
			input:   `""`,
			want:    Hostname(""),
			wantErr: true,
		},
		{
			name:    "invalid - spaces",
			input:   `"example .com"`,
			want:    Hostname(""),
			wantErr: true,
		},
		{
			name:    "invalid - starts with hyphen",
			input:   `"-example.com"`,
			want:    Hostname(""),
			wantErr: true,
		},
		{
			name:    "invalid - invalid JSON",
			input:   `example.com`,
			want:    Hostname(""),
			wantErr: true,
		},
		{
			name:    "invalid - malformed JSON",
			input:   `{"broken": json}`,
			want:    Hostname(""),
			wantErr: true,
		},
		{
			name:    "invalid - non-string JSON",
			input:   `123`,
			want:    Hostname(""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h Hostname
			err := json.Unmarshal([]byte(tt.input), &h)

			if (err != nil) != tt.wantErr {
				t.Errorf("Hostname.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && h != tt.want {
				t.Errorf("Hostname.UnmarshalJSON() = %v, want %v", h, tt.want)
			}
		})
	}
}

func TestDuration_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Duration
		wantErr bool
	}{
		{
			name:    "seconds",
			input:   `"30s"`,
			want:    Duration(30 * time.Second),
			wantErr: false,
		},
		{
			name:    "minutes",
			input:   `"5m"`,
			want:    Duration(5 * time.Minute),
			wantErr: false,
		},
		{
			name:    "hours",
			input:   `"2h"`,
			want:    Duration(2 * time.Hour),
			wantErr: false,
		},
		{
			name:    "complex duration",
			input:   `"1h30m45s"`,
			want:    Duration(1*time.Hour + 30*time.Minute + 45*time.Second),
			wantErr: false,
		},
		{
			name:    "invalid - no unit",
			input:   `"30"`,
			want:    Duration(0),
			wantErr: true,
		},
		{
			name:    "invalid - bad format",
			input:   `"abc"`,
			want:    Duration(0),
			wantErr: true,
		},
		{
			name:    "invalid - invalid JSON",
			input:   `30s`,
			want:    Duration(0),
			wantErr: true,
		},
		{
			name:    "invalid - malformed JSON",
			input:   `{"broken": json}`,
			want:    Duration(0),
			wantErr: true,
		},
		{
			name:    "invalid - non-string JSON",
			input:   `123`,
			want:    Duration(0),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d Duration
			err := json.Unmarshal([]byte(tt.input), &d)

			if (err != nil) != tt.wantErr {
				t.Errorf("Duration.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && d != tt.want {
				t.Errorf("Duration.UnmarshalJSON() = %v, want %v", d, tt.want)
			}
		})
	}
}

func TestParamsUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Params
		wantErr bool
	}{
		{
			name: "valid config",
			input: `{
				"dnsResolvers": ["8.8.8.8", "1.1.1.1"],
				"hostnames": ["example.com", "test.com"],
				"timeout": "30s",
				"scanInterval": "5m",
				"logLevel": "info",
				"logAddSource": true
			}`,
			want: Params{
				DNSresolvers: []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1")},
				Hostnames:    []Hostname{"example.com", "test.com"},
				Timeout:      Duration(30 * time.Second),
				ScanInterval: Duration(5 * time.Minute),
				LogLevel:     slog.LevelInfo,
				LogAddSource: true,
			},
			wantErr: false,
		},
		{
			name: "invalid hostname in config",
			input: `{
				"dnsResolvers": ["8.8.8.8"],
				"hostnames": ["192.168.1.1"],
				"timeout": "30s",
				"scanInterval": "5m",
				"logLevel": "info",
				"logAddSource": false
			}`,
			want:    Params{},
			wantErr: true,
		},
		{
			name: "invalid duration in config",
			input: `{
				"dnsResolvers": ["8.8.8.8"],
				"hostnames": ["example.com"],
				"timeout": "invalid",
				"scanInterval": "5m",
				"logLevel": "info",
				"logAddSource": false
			}`,
			want:    Params{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var params Params
			err := json.Unmarshal([]byte(tt.input), &params)

			if (err != nil) != tt.wantErr {
				t.Errorf("Params unmarshal error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Compare fields individually for better error messages
				if len(params.DNSresolvers) != len(tt.want.DNSresolvers) {
					t.Errorf("DNSresolvers length = %v, want %v", len(params.DNSresolvers), len(tt.want.DNSresolvers))
				}
				for i, dns := range params.DNSresolvers {
					if !dns.Equal(tt.want.DNSresolvers[i]) {
						t.Errorf("DNSresolvers[%d] = %v, want %v", i, dns, tt.want.DNSresolvers[i])
					}
				}

				if len(params.Hostnames) != len(tt.want.Hostnames) {
					t.Errorf("Hostnames length = %v, want %v", len(params.Hostnames), len(tt.want.Hostnames))
				}
				for i, hostname := range params.Hostnames {
					if hostname != tt.want.Hostnames[i] {
						t.Errorf("Hostnames[%d] = %v, want %v", i, hostname, tt.want.Hostnames[i])
					}
				}

				if params.Timeout != tt.want.Timeout {
					t.Errorf("Timeout = %v, want %v", params.Timeout, tt.want.Timeout)
				}

				if params.ScanInterval != tt.want.ScanInterval {
					t.Errorf("ScanInterval = %v, want %v", params.ScanInterval, tt.want.ScanInterval)
				}

				if params.LogLevel != tt.want.LogLevel {
					t.Errorf("LogLevel = %v, want %v", params.LogLevel, tt.want.LogLevel)
				}

				if params.LogAddSource != tt.want.LogAddSource {
					t.Errorf("LogAddSource = %v, want %v", params.LogAddSource, tt.want.LogAddSource)
				}
			}
		})
	}
}

func TestLoad(t *testing.T) {
	// Create a temporary config file with valid content
	validConfigContent := `{
		"dnsResolvers": ["8.8.8.8", "1.1.1.1"],
		"hostnames": ["example.com", "test.org"],
		"timeout": "30s",
		"scanInterval": "5m",
		"logLevel": "info",
		"logAddSource": true
	}`

	// Create temporary valid config file
	validFile, err := os.CreateTemp("", "valid_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(validFile.Name())
	defer validFile.Close()

	if _, err := validFile.Write([]byte(validConfigContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Create temporary invalid config file
	invalidConfigContent := `{
		"dnsResolvers": ["8.8.8.8"],
		"hostnames": ["192.168.1.1"],
		"timeout": "30s",
		"scanInterval": "5m",
		"logLevel": "info",
		"logAddSource": false
	}`

	invalidFile, err := os.CreateTemp("", "invalid_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(invalidFile.Name())
	defer invalidFile.Close()

	if _, err := invalidFile.Write([]byte(invalidConfigContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Create malformed JSON file
	malformedFile, err := os.CreateTemp("", "malformed_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(malformedFile.Name())
	defer malformedFile.Close()

	if _, err := malformedFile.Write([]byte(`{"broken": json}`)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	tests := []struct {
		name         string
		setupFunc    func() string
		wantErr      bool
		validateFunc func(t *testing.T, params Params)
	}{
		{
			name: "valid config file",
			setupFunc: func() string {
				return validFile.Name()
			},
			wantErr: false,
			validateFunc: func(t *testing.T, params Params) {
				if len(params.DNSresolvers) != 2 {
					t.Errorf("Expected 2 DNS resolvers, got %d", len(params.DNSresolvers))
				}
				if len(params.Hostnames) != 2 {
					t.Errorf("Expected 2 hostnames, got %d", len(params.Hostnames))
				}
				if params.Timeout != Duration(30*time.Second) {
					t.Errorf("Expected timeout 30s, got %v", params.Timeout)
				}
				if !params.LogAddSource {
					t.Error("Expected LogAddSource to be true")
				}
			},
		},
		{
			name: "non-existent file",
			setupFunc: func() string {
				return "nonexistent_config.json"
			},
			wantErr: true,
		},
		{
			name: "invalid hostname in config",
			setupFunc: func() string {
				return invalidFile.Name()
			},
			wantErr: true,
		},
		{
			name: "malformed JSON",
			setupFunc: func() string {
				return malformedFile.Name()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Temporarily modify the const configFilePath for testing
			// We'll use a test helper that accepts the file path
			configPath := tt.setupFunc()
			
			var params Params
			err := loadFile(configPath, &params)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.validateFunc != nil {
				tt.validateFunc(t, params)
			}
		})
	}
}

func TestLoadWithActualLoad(t *testing.T) {
	// Test the actual Load() function by temporarily creating config.json
	validConfigContent := `{
		"dnsResolvers": ["9.9.9.9"],
		"hostnames": ["example.com"],
		"timeout": "45s",
		"scanInterval": "10m",
		"logLevel": "debug",
		"logAddSource": false
	}`

	// Check if config.json already exists
	_, err := os.Stat("config.json")
	configExists := err == nil

	var backupContent []byte
	if configExists {
		// Backup existing config.json
		backupContent, err = os.ReadFile("config.json")
		if err != nil {
			t.Fatalf("Failed to backup existing config.json: %v", err)
		}
	}

	// Create test config.json
	err = os.WriteFile("config.json", []byte(validConfigContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config.json: %v", err)
	}

	// Cleanup function
	cleanup := func() {
		if configExists {
			// Restore backup
			os.WriteFile("config.json", backupContent, 0644)
		} else {
			// Remove test file
			os.Remove("config.json")
		}
	}
	defer cleanup()

	// Test the actual Load() function
	params, err := Load()
	if err != nil {
		t.Errorf("Load() returned error: %v", err)
		return
	}

	// Validate loaded parameters
	if len(params.DNSresolvers) != 1 {
		t.Errorf("Expected 1 DNS resolver, got %d", len(params.DNSresolvers))
	}
	if params.DNSresolvers[0].String() != "9.9.9.9" {
		t.Errorf("Expected DNS resolver 9.9.9.9, got %s", params.DNSresolvers[0].String())
	}
	if len(params.Hostnames) != 1 {
		t.Errorf("Expected 1 hostname, got %d", len(params.Hostnames))
	}
	if params.Hostnames[0] != "example.com" {
		t.Errorf("Expected hostname example.com, got %s", params.Hostnames[0])
	}
	if params.Timeout != Duration(45*time.Second) {
		t.Errorf("Expected timeout 45s, got %v", params.Timeout)
	}
	if params.LogAddSource {
		t.Error("Expected LogAddSource to be false")
	}
}

func BenchmarkHostnameUnmarshal(b *testing.B) {
	data := []byte(`"example.com"`)
	for i := 0; i < b.N; i++ {
		var h Hostname
		json.Unmarshal(data, &h)
	}
}

func BenchmarkDurationUnmarshal(b *testing.B) {
	data := []byte(`"30s"`)
	for i := 0; i < b.N; i++ {
		var d Duration
		json.Unmarshal(data, &d)
	}
}
