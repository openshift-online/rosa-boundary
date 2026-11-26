package store

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/sirupsen/logrus"
)

func staticCredsForTest(key, secret, session string) aws.CredentialsProvider {
	return awscreds.NewStaticCredentialsProvider(key, secret, session)
}

// mintAuthToken is exercised against the SDK's documented presigned-token
// shape: "host:port?Action=connect&DBUser=...&X-Amz-Signature=..." — a
// SigV4-signed query string carrying no password or user-info component,
// which is the whole point of the IAM database-auth path.
func TestMintAuthToken_PresignedShape(t *testing.T) {
	m := iamAuth{region: "us-east-1", credentials: staticCredsForTest("test-key", "test-secret", "")}

	token, err := m.mintAuthToken(context.Background(), "db.example.com", "5432", "trusted_actions_app")
	if err != nil {
		t.Fatalf("mintAuthToken() error = %v", err)
	}

	// The token is "host:port?<signed query>" — split off the endpoint,
	// then parse the query.
	endpoint, query, ok := strings.Cut(token, "?")
	if !ok {
		t.Fatalf("token has no query component: %q", token)
	}
	if endpoint != "db.example.com:5432" {
		t.Errorf("token endpoint = %q, want %q", endpoint, "db.example.com:5432")
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		t.Fatalf("token query does not parse: %v", err)
	}
	if strings.Contains(token, "@") {
		t.Error("token contains '@' — must carry no user-info or password")
	}

	if q.Get("Action") != "connect" {
		t.Errorf("Action = %q, want %q", q.Get("Action"), "connect")
	}
	if q.Get("DBUser") != "trusted_actions_app" {
		t.Errorf("DBUser = %q, want %q", q.Get("DBUser"), "trusted_actions_app")
	}
	if !strings.HasPrefix(q.Get("X-Amz-Credential"), "test-key/") {
		t.Errorf("X-Amz-Credential = %q, want access-key-prefixed credential", q.Get("X-Amz-Credential"))
	}
	if q.Get("X-Amz-Signature") == "" {
		t.Error("X-Amz-Signature is empty — token is not signed")
	}
	if q.Get("X-Amz-Expires") == "" {
		t.Error("X-Amz-Expires is empty — token has no validity")
	}
}

// The minted token's validity window is what ConnMaxLifetime is capped
// against: it must be positive and at most the 15-minute RDS maximum.
func TestMintAuthToken_ValidityWindow(t *testing.T) {
	m := iamAuth{region: "us-east-1", credentials: staticCredsForTest("test-key", "test-secret", "")}

	token, err := m.mintAuthToken(context.Background(), "h", "5432", "u")
	if err != nil {
		t.Fatalf("mintAuthToken() error = %v", err)
	}
	q, err := url.ParseQuery(strings.TrimPrefix(token, "?"))
	if err != nil {
		t.Fatalf("token is not a query string: %v", err)
	}
	expires, err := time.ParseDuration(q.Get("X-Amz-Expires") + "s")
	if err != nil {
		t.Fatalf("X-Amz-Expires not a duration: %v", err)
	}
	if expires <= 0 || expires > 15*time.Minute {
		t.Errorf("token validity = %v, want within (0, 15m]", expires)
	}
}

// buildIAMTokenDSN composes the pgx URL the pool connects with: the minted
// token rides in the password slot at connect time only, sslmode comes from
// config, and no static password exists anywhere.
func TestBuildIAMTokenDSN(t *testing.T) {
	dsn := buildIAMTokenDSN("db.example.com", "5432", "trusted_actions", "trusted_actions_app", "the-token", "verify-full", "/etc/ssl/rds/global-bundle.pem")

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("DSN is not a URL: %v", err)
	}
	if u.Host != "db.example.com:5432" {
		t.Errorf("host = %q, want db.example.com:5432", u.Host)
	}
	if u.Path != "/trusted_actions" {
		t.Errorf("path = %q, want /trusted_actions", u.Path)
	}
	if u.User.Username() != "trusted_actions_app" {
		t.Errorf("user = %q, want trusted_actions_app", u.User.Username())
	}
	if pw, _ := u.User.Password(); pw != "the-token" {
		t.Errorf("password slot = %q, want the minted token", pw)
	}
	if got := u.Query().Get("sslmode"); got != "verify-full" {
		t.Errorf("sslmode = %q, want verify-full", got)
	}
	if got := u.Query().Get("sslrootcert"); got != "/etc/ssl/rds/global-bundle.pem" {
		t.Errorf("sslrootcert = %q, want the RDS CA bundle path", got)
	}
}

// An empty sslrootcert must stay absent from the DSN: an empty query value
// would make pgx look for a file named "" and fail the connection.
func TestBuildIAMTokenDSN_NoRootCert(t *testing.T) {
	dsn := buildIAMTokenDSN("db.example.com", "5432", "trusted_actions", "trusted_actions_app", "the-token", "verify-full", "")

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("DSN is not a URL: %v", err)
	}
	if _, ok := u.Query()["sslrootcert"]; ok {
		t.Errorf("sslrootcert present with empty value: %q", u.Query().Get("sslrootcert"))
	}
}

// newIAMPostgresStore must refuse an incomplete contract loudly rather than
// falling back to a password DSN that does not exist.
func TestNewIAMStore_MissingContract(t *testing.T) {
	logger := logrus.New()
	for _, tc := range []struct {
		name    string
		host    string
		port    string
		dbname  string
		user    string
		region  string
		wantErr string
	}{
		{"no host", "", "5432", "db", "u", "us-east-1", "ROSA_TA_DB_HOST"},
		{"no port", "h", "", "db", "u", "us-east-1", "ROSA_TA_DB_PORT"},
		{"no name", "h", "5432", "", "u", "us-east-1", "ROSA_TA_DB_NAME"},
		{"no user", "h", "5432", "db", "", "us-east-1", "ROSA_TA_DB_USER"},
		{"no region", "h", "5432", "db", "u", "", "AWS_REGION"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newIAMPostgresStore(context.Background(), IAMDBConfig{
				Host: tc.host, Port: tc.port, DBName: tc.dbname, User: tc.user,
				Region: tc.region, SSLMode: "disable",
			}, PostgresConfig{}, logger)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// A partial IAM contract (some fields set, host missing) must fail loudly
// in dispatch rather than silently falling back to DATABASE_URL/SQLite —
// a truncated or mistyped ROSA_TA_DB_* environment would otherwise run the
// server against the wrong database.
func TestNewWithIAM_PartialContractFailsLoudly(t *testing.T) {
	_, err := NewWithIAM(context.Background(), "trusted_actions.db", IAMDBConfig{
		Port:   "5432",
		DBName: "trusted_actions",
		User:   "trusted_actions_app",
		Region: "us-east-1",
	}, PostgresConfig{}, logrus.New())
	if err == nil || !strings.Contains(err.Error(), "ROSA_TA_DB_HOST") {
		t.Fatalf("error = %v, want a loud ROSA_TA_DB_HOST failure", err)
	}
}
