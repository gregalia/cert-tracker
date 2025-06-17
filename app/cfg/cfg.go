package config

import (
	"encoding/json"
	"os"
)

// TODO: Use net URL hostname?
type Hostname string

type config struct {
	Resolver  string     `json:"resolver"`
	Hostnames []Hostname `json:"hostnames"`
}

// TODO: Take parameter
func Parse() (*config, error) {
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
