package ocm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveEnvironmentAliasesAndCanonicalURLs(t *testing.T) {
	tests := map[string]Environment{
		"production":   {Name: "production", URL: ProductionURL},
		"PROD":         {Name: "production", URL: ProductionURL},
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
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			got, err := ResolveEnvironment(input)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("ResolveEnvironment(%q) = %#v, want %#v", input, got, want)
			}
		})
	}
}

func TestResolveEnvironmentRejectsUnapprovedDestinations(t *testing.T) {
	for _, input := range []string{"https://attacker.example", "http://api.openshift.com", "production.example", ""} {
		t.Run(input, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			if _, err := ResolveEnvironment(input); err == nil {
				t.Fatalf("ResolveEnvironment(%q) succeeded", input)
			}
		})
	}
}

func TestResolveEnvironmentReadsOnlyLocalURL(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	directory := filepath.Join(configHome, "ocm")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := "local-refresh-token-canary"
	content := `{"url":"https://api.stage.openshift.com","refresh_token":"` + secret + `","access_token":"other-secret"}`
	if err := os.WriteFile(filepath.Join(directory, "ocm.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	environment, err := ResolveEnvironment("")
	if err != nil {
		t.Fatal(err)
	}
	if environment.URL != StagingURL {
		t.Fatalf("resolved URL = %q", environment.URL)
	}
	if strings.Contains(environment.Name+environment.URL, secret) {
		t.Fatal("resolved environment contains local token material")
	}
}
