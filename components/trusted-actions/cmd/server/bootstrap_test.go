package main

import (
	"strings"
	"testing"
)

var testCoords = dsnCoordinates{
	host:    "db.example.com",
	port:    "5432",
	dbname:  "trusted_actions",
	sslmode: "verify-full",
	sslroot: "/etc/ssl/certs/rds-global-bundle.pem",
}

// The --dsn flag wins over the environment; neither set is a loud error.
func TestResolveBootstrapDSN(t *testing.T) {
	flagDSN := "postgres://master:pw-flag@db:5432/app?sslmode=disable" // #nosec G101
	envDSN := "postgres://master:pw-env@db:5432/app?sslmode=disable"   // #nosec G101
	secretJSON := `{"username":"trusted_actions","password":"pw-secret"}`

	for _, tc := range []struct {
		name    string
		flag    string
		env     string
		secret  string
		want    string
		wantErr string
	}{
		{"flag wins", flagDSN, envDSN, secretJSON, flagDSN, ""},
		{"dsn env fallback", "", envDSN, secretJSON, envDSN, ""},
		{"secret env fallback", "", "", secretJSON, "host='db.example.com' port='5432' dbname='trusted_actions' user='trusted_actions' password='pw-secret' sslmode='verify-full' sslrootcert='/etc/ssl/certs/rds-global-bundle.pem'", ""},
		{"neither set", "", "", "", "", "bootstrap needs master credentials"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveBootstrapDSN(tc.flag, tc.env, tc.secret, testCoords)
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

// The RDS-managed secret's value is a JSON object; its username and password
// fields land in pgx keyword arguments. Passwords containing single quotes,
// backslashes, or spaces must survive — shell-quoted DSN composition cannot
// carry them, which is why this lives in Go.
func TestBuildDSNFromMasterSecret(t *testing.T) {
	for _, tc := range []struct {
		name       string
		secretJSON string
		want       string
		wantErr    string
	}{
		{
			name:       "plain values",
			secretJSON: `{"username":"trusted_actions","password":"plain"}`,
			want:       "host='db.example.com' port='5432' dbname='trusted_actions' user='trusted_actions' password='plain'",
		},
		{
			name:       "password with special characters",
			secretJSON: `{"username":"trusted_actions","password":"qu'ote \\ back\"slash space"}`,
			want:       "host='db.example.com' port='5432' dbname='trusted_actions' user='trusted_actions' password='qu'ote \\\\ back\"slash space'",
		},
		{
			name:       "not json",
			secretJSON: "bare-password",
			wantErr:    "parsing ROSA_TA_DB_MASTER_SECRET as JSON",
		},
		{
			name:       "missing password field",
			secretJSON: `{"username":"trusted_actions"}`,
			wantErr:    "missing username or password",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coords := dsnCoordinates{host: "db.example.com", port: "5432", dbname: "trusted_actions"}
			got, err := buildDSNFromMasterSecret(tc.secretJSON, coords)
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
