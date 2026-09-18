// Package ocm acquires and transfers short-lived OCM access tokens.
package ocm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Environment is an approved OCM API destination.
type Environment struct {
	Name string
	URL  string
}

var environments = map[string]Environment{
	"production":   {Name: "production", URL: ProductionURL},
	"prod":         {Name: "production", URL: ProductionURL},
	"prd":          {Name: "production", URL: ProductionURL},
	ProductionURL:  {Name: "production", URL: ProductionURL},
	"staging":      {Name: "staging", URL: StagingURL},
	"stage":        {Name: "staging", URL: StagingURL},
	"stg":          {Name: "staging", URL: StagingURL},
	StagingURL:     {Name: "staging", URL: StagingURL},
	"integration":  {Name: "integration", URL: IntegrationURL},
	"int":          {Name: "integration", URL: IntegrationURL},
	IntegrationURL: {Name: "integration", URL: IntegrationURL},
}

// ResolveEnvironment resolves aliases and permits only approved canonical URLs.
// If value is empty, it reads only the URL field from the local OCM config.
func ResolveEnvironment(value string) (Environment, error) {
	if value == "" {
		localURL, err := readLocalURL()
		if err != nil {
			return Environment{}, err
		}
		value = localURL
	}

	environment, ok := environments[strings.ToLower(strings.TrimSpace(value))]
	if !ok {
		return Environment{}, fmt.Errorf("unsupported OCM environment %q; use production, staging, integration, or an approved canonical URL", value)
	}
	return environment, nil
}

// readLocalURL decodes only the non-secret URL field and never returns token data.
func readLocalURL() (localURL string, err error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("determine home directory for OCM configuration: %w", err)
		}
		base = filepath.Join(home, ".config")
	}
	configPath := filepath.Join(base, "ocm", "ocm.json")

	file, err := os.Open(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errors.New("OCM environment is required; set --ocm-url because the local OCM configuration has no URL")
		}
		return "", fmt.Errorf("open local OCM configuration: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			localURL = ""
			err = fmt.Errorf("close local OCM configuration: %w", closeErr)
		}
	}()

	var local struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(file).Decode(&local); err != nil {
		return "", fmt.Errorf("read URL from local OCM configuration: %w", err)
	}
	if strings.TrimSpace(local.URL) == "" {
		return "", errors.New("OCM environment is required; set --ocm-url because the local OCM configuration has no URL")
	}
	return local.URL, nil
}
