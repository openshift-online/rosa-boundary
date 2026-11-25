package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	pgxstdlib "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
)

// IAMDBConfig is the IAM-database-authentication contract: connection
// coordinates and the region to sign tokens for. No password field exists —
// the database user authenticates with a short-lived RDS IAM token minted
// per physical connection from ambient credentials.
type IAMDBConfig struct {
	Host    string
	Port    string
	DBName  string
	User    string
	Region  string
	SSLMode string
}

// iamAuth mints RDS IAM authentication tokens.
type iamAuth struct {
	region      string
	credentials aws.CredentialsProvider
}

// mintAuthToken produces one presigned IAM database-authentication token.
// It is called per physical connection, never cached: each token is valid
// for a short window (15 minutes) and a fresh connection gets a fresh one,
// which is what keeps ConnMaxLifetime below token validity safe.
func (a *iamAuth) mintAuthToken(ctx context.Context, host, port, user string) (string, error) {
	return auth.BuildAuthToken(ctx, net.JoinHostPort(host, port), a.region, user, a.credentials)
}

// buildIAMTokenDSN composes the pgx connection URL for one connection: the
// minted token occupies the password slot of the URL only at connect time.
func buildIAMTokenDSN(host, port, dbname, user, token, sslmode string) string {
	u := url.URL{
		Scheme: "postgres",
		Host:   net.JoinHostPort(host, port),
		Path:   dbname,
		User:   url.UserPassword(user, token),
	}
	q := u.Query()
	q.Set("sslmode", sslmode)
	u.RawQuery = q.Encode()
	return u.String()
}

// tokenConnector mints a fresh IAM token for every physical connection a
// database/sql pool opens. The pool's DSN is rebuilt with a fresh token
// before the driver dials, so no token is ever reused across connections.
type tokenConnector struct {
	driver driver.Driver
	auth   *iamAuth
	cfg    IAMDBConfig
}

var _ driver.Connector = (*tokenConnector)(nil)

func (c *tokenConnector) Connect(ctx context.Context) (driver.Conn, error) {
	token, err := c.auth.mintAuthToken(ctx, c.cfg.Host, c.cfg.Port, c.cfg.User)
	if err != nil {
		return nil, fmt.Errorf("minting IAM database token: %w", err)
	}
	dsn := buildIAMTokenDSN(c.cfg.Host, c.cfg.Port, c.cfg.DBName, c.cfg.User, token, c.cfg.SSLMode)
	return c.driver.Open(dsn)
}

func (c *tokenConnector) Driver() driver.Driver { return c.driver }

// maxConnLifetime caps the pool's connection lifetime so a connection never
// outlives its 15-minute IAM token. Defaults and configured values above
// the cap are lowered to it.
const maxConnLifetime = 10 * time.Minute

// newIAMPostgresStore opens a Postgres-backed Store that authenticates with
// per-connection IAM tokens resolved from ambient AWS credentials. The full
// contract (host, port, name, user, region) must be present — a partial one
// fails loudly rather than silently falling back to any password path.
func newIAMPostgresStore(ctx context.Context, dbCfg IAMDBConfig, poolCfg PostgresConfig, logger *logrus.Logger) (*PostgresStore, error) {
	for _, absent := range []struct{ env, value string }{
		{"ROSA_TA_DB_HOST", dbCfg.Host},
		{"ROSA_TA_DB_PORT", dbCfg.Port},
		{"ROSA_TA_DB_NAME", dbCfg.DBName},
		{"ROSA_TA_DB_USER", dbCfg.User},
		{"AWS_REGION", dbCfg.Region},
	} {
		if absent.value == "" {
			return nil, fmt.Errorf("IAM database authentication requires %s to be set", absent.env)
		}
	}
	if dbCfg.SSLMode == "" {
		dbCfg.SSLMode = "verify-full"
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(dbCfg.Region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS configuration for IAM database tokens: %w", err)
	}

	db := sqlx.NewDb(sql.OpenDB(&tokenConnector{
		driver: pgxstdlib.GetDefaultDriver(),
		auth:   &iamAuth{region: dbCfg.Region, credentials: awsCfg.Credentials},
		cfg:    dbCfg,
	}), "pgx")

	if poolCfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(poolCfg.MaxOpenConns)
	}
	if poolCfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(poolCfg.MaxIdleConns)
	}
	if poolCfg.ConnMaxLifetime > 0 {
		if poolCfg.ConnMaxLifetime > maxConnLifetime {
			poolCfg.ConnMaxLifetime = maxConnLifetime
		}
		db.SetConnMaxLifetime(poolCfg.ConnMaxLifetime)
	}

	if err := db.PingContext(ctx); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			logger.WithError(closeErr).Warn("Failed to close database after ping failure")
		}
		return nil, fmt.Errorf("pinging postgres database: %w", err)
	}

	if err := runMigrations(ctx, db, "postgres"); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			logger.WithError(closeErr).Warn("Failed to close database after migration failure")
		}
		return nil, fmt.Errorf("running postgres migrations: %w", err)
	}

	logger.Info("PostgreSQL database initialized (IAM token authentication)")
	return &PostgresStore{db: db, logger: logger}, nil
}
