package cfg

import (
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/go-playground/validator/v10"
)

const configFilePath = "config.json"

type Hostname string
type Duration time.Duration
type Params struct {
	DNSresolvers []net.IP   `json:"dnsResolvers"`
	Hostnames    []Hostname `json:"hostnames"`
	Timeout      Duration   `json:"timeout"`
	ScanInterval Duration   `json:"scanInterval"`
	LogLevel     slog.Level `json:"logLevel"`
	LogAddSource bool       `json:"logAddSource"`
}

func (h *Hostname) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Var(s, "hostname_rfc1123"); err != nil {
		return err
	}

	*h = Hostname(s)
	return nil
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	*d = Duration(dur)
	return err
}

func loadFile(configFilePath string, p *Params) error {
	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &p)
	return err
}

func Load() (Params, error){
	var Current Params
	err := loadFile(configFilePath, &Current)
	return Current, err
}
