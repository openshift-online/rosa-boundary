package main

import (
	"strings"
	"testing"
)

// The --dsn flag wins over the environment; neither set is a loud error.
func TestResolveBootstrapDSN(t *testing.T) {
	flagDSN := "postgres://master:pw-flag@db:5432/app?sslmode=disable" // #nosec G101
	envDSN := "postgres://master:pw-env@db:5432/app?sslmode=disable"   // #nosec G101

	for _, tc := range []struct {
		name    string
		flag    string
		env     string
		want    string
		wantErr string
	}{
		{"flag wins", flagDSN, envDSN, flagDSN, ""},
		{"env fallback", "", envDSN, envDSN, ""},
		{"neither set", "", "", "", "bootstrap needs master credentials"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveBootstrapDSN(tc.flag, tc.env)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("DSN = %q, want %q", got, tc.want)
			}
		})
	}
}
