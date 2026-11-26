package store

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
)

//go:embed migrations/postgres/bootstrap.sql
var bootstrapSQL string

//go:embed migrations/postgres/bootstrap2.sql
var bootstrapSQL2 string

// appRoleName is the single database role the application authenticates as.
// It matches the role the SQL file creates.
const appRoleName = "trusted_actions_app"

// bootstrapConnectTimeout bounds the initial connection check so a stalled
// PostgreSQL cannot hold the CLI indefinitely; the caller's context still
// governs cancellation.
const bootstrapConnectTimeout = 30 * time.Second

// errMasterDSNInvalid wraps connection setup failures without the
// underlying driver text: pgx parse errors echo the raw keyword DSN
// best-effort-redacted at most, and the DSN carries master credentials
// that must not reach stderr.
var errMasterDSNInvalid = errors.New("connecting with master credentials: invalid or unreachable DSN (details suppressed — the DSN carries master credentials)")

// BootstrapDatabase applies the idempotent bootstrap SQL to the database the
// DSN points at, using master credentials. It creates the trusted_actions_app
// role (LOGIN, IAM-token authentication, CREATEDB), grants it rds_iam, and
// transfers database and schema ownership to it. Re-running is a no-op.
//
// The DSN is used for this one connection only and never logged; connection
// setup errors are reported without driver text for the same reason.
func BootstrapDatabase(ctx context.Context, dsn string, logger *logrus.Logger) error {
	if dsn == "" {
		return fmt.Errorf("bootstrap requires a master-credentials DSN")
	}

	// Single connection, no pool tuning: a one-shot administrative command.
	// Open (not Connect) plus PingContext so the bootstrap context governs
	// the connection attempt rather than a driver-internal background one.
	db, err := sqlx.Open("pgx", dsn)
	if err != nil {
		return errMasterDSNInvalid
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			logger.WithError(closeErr).Warn("Failed to close bootstrap connection")
		}
	}()

	pingCtx, cancel := context.WithTimeout(ctx, bootstrapConnectTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return errMasterDSNInvalid
	}

	// Phase order (all idempotent, safe to re-run in this sequence):
	//   1. bootstrapSQL — create the application role, grant rds_iam,
	//      CREATEDB, and master membership (the later transfers need both).
	//   2. database-level ownership transfer — must come before the schema
	//      transfer: ALTER SCHEMA ... OWNER requires the new owner to hold
	//      CREATE on the database, which database ownership confers and a
	//      fresh role lacks. ALTER DATABASE cannot take CURRENT_DATABASE()
	//      and a bind parameter cannot stand in for an identifier, so this
	//      runs a DO block with format()'s %I — server-side identifier
	//      quoting, exactly what PostgreSQL itself uses.
	//   3. bootstrapSQL2 — schema and legacy-object ownership transfers,
	//      which also cover a database initialized through the legacy
	//      DATABASE_URL path (schema_migrations et al.).
	if _, err := db.ExecContext(ctx, bootstrapSQL); err != nil {
		return fmt.Errorf("applying bootstrap SQL (roles and grants): %w", err)
	}

	if _, err := db.ExecContext(ctx, `DO $$BEGIN
		EXECUTE format('ALTER DATABASE %I OWNER TO `+appRoleName+`', current_database());
	END$$;`); err != nil {
		return fmt.Errorf("transferring database ownership: %w", err)
	}

	if _, err := db.ExecContext(ctx, bootstrapSQL2); err != nil {
		return fmt.Errorf("applying bootstrap SQL (ownership transfers): %w", err)
	}

	// Post-conditions: the role exists, can log in, holds rds_iam and
	// CREATEDB, and owns the current database. Asserted rather than assumed
	// so a partial bootstrap (e.g. an interrupted run) fails loudly instead
	// of leaving a half-prepared database behind.
	var ok bool
	for _, check := range []struct {
		name  string
		query string
	}{
		{"role exists", `SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = '` + appRoleName + `')`},
		{"role can log in", `SELECT rolcanlogin FROM pg_roles WHERE rolname = '` + appRoleName + `'`},
		{"rds_iam membership", `SELECT pg_has_role('` + appRoleName + `', 'rds_iam', 'MEMBER')`},
		{"CREATEDB attribute", `SELECT rolcreatedb FROM pg_roles WHERE rolname = '` + appRoleName + `'`},
		{"database ownership", `SELECT pg_catalog.pg_get_userbyid(datdba) = '` + appRoleName + `' FROM pg_database WHERE datname = current_database()`},
	} {
		if err := db.GetContext(ctx, &ok, check.query); err != nil {
			return fmt.Errorf("checking %s: %w", check.name, err)
		}
		if !ok {
			return fmt.Errorf("bootstrap post-condition failed: %s", check.name)
		}
	}

	return nil
}
