package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/openshift-online/rosa-trusted-actions/internal/store"
)

// newBootstrapCmd builds the `bootstrap` subcommand: connect to the
// application database with master credentials and apply the idempotent
// bootstrap SQL (create the IAM-auth application user, grant rds_iam and
// CREATEDB, transfer database/schema ownership). Master credentials arrive
// in one of three forms, in precedence order: the --dsn flag, the
// ROSA_TA_DB_MASTER_DSN environment variable, or connection coordinates plus
// ROSA_TA_DB_MASTER_SECRET (the raw JSON of an RDS-managed master secret:
// {"username":...,"password":...}). In every form the credentials are used
// for this one connection and never logged or persisted.
func newBootstrapCmd() *cobra.Command {
	var dsnFlag string

	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Prepare the application database for IAM token authentication",
		Long: "Apply the idempotent bootstrap SQL against the application database using " +
			"master credentials: create the trusted_actions_app role, grant it rds_iam and " +
			"CREATEDB, and transfer database and schema ownership to it. Safe to re-run — " +
			"every statement is idempotent.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBootstrap(cmd.Context(), dsnFlag)
		},
		// No positional arguments: a pasted DSN as an argument would be
		// silently ignored while the env DSN bootstrapped a different
		// database. Reject without echoing the argument (it may be a DSN).
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("bootstrap takes no positional arguments — pass the DSN via --dsn or ROSA_TA_DB_MASTER_DSN")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&dsnFlag, "dsn", "",
		"master-credentials DSN (postgres://master-user:password@host:port/dbname). "+
			"Defaults to the ROSA_TA_DB_MASTER_DSN environment variable.")

	return cmd
}

// dsnCoordinates are the non-secret connection coordinates of the master
// DSN, supplied by the caller (the ECS task definition carries them as
// plain environment values; only the secret is secret).
type dsnCoordinates struct {
	host    string
	port    string
	dbname  string
	sslmode string
	sslroot string
}

// buildDSNFromMasterSecret parses an RDS-managed master secret's JSON
// ({"username":...,"password":...}) and composes a keyword/value DSN. Done
// here in Go rather than in the task-definition shell: single quotes,
// backslashes, or spaces in the RDS-generated password break any
// shell-quoted DSN, and only pgx's single-quoted keyword arguments with
// backslash escaping can carry such values safely.
func buildDSNFromMasterSecret(secretJSON string, coords dsnCoordinates) (string, error) {
	var secret struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(secretJSON), &secret); err != nil {
		return "", fmt.Errorf("parsing ROSA_TA_DB_MASTER_SECRET as JSON (is it the raw RDS master secret?): %w", err)
	}
	if secret.Username == "" || secret.Password == "" {
		return "", fmt.Errorf("ROSA_TA_DB_MASTER_SECRET is missing username or password")
	}

	q := func(v string) string {
		return "'" + strings.ReplaceAll(v, "\\", "\\\\") + "'"
	}

	dsn := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s",
		q(coords.host), q(coords.port), q(coords.dbname), q(secret.Username), q(secret.Password))
	if coords.sslmode != "" {
		dsn += " sslmode=" + q(coords.sslmode)
	}
	if coords.sslroot != "" {
		dsn += " sslrootcert=" + q(coords.sslroot)
	}
	return dsn, nil
}

// resolveBootstrapDSN picks the master-credentials DSN, in precedence order:
// the --dsn flag, the ROSA_TA_DB_MASTER_DSN environment variable, or
// connection coordinates plus the raw JSON of an RDS-managed master secret
// in ROSA_TA_DB_MASTER_SECRET. None set is an error.
func resolveBootstrapDSN(dsnFlag, dsnEnv, secretEnv string, coords dsnCoordinates) (string, error) {
	if dsnFlag != "" {
		return dsnFlag, nil
	}
	if dsnEnv != "" {
		return dsnEnv, nil
	}
	if secretEnv != "" {
		return buildDSNFromMasterSecret(secretEnv, coords)
	}
	return "", fmt.Errorf("bootstrap needs master credentials: pass --dsn, set ROSA_TA_DB_MASTER_DSN, or set ROSA_TA_DB_MASTER_SECRET with the master-secret JSON")
}

func runBootstrap(ctx context.Context, dsnFlag string) error {
	dsn, err := resolveBootstrapDSN(dsnFlag, os.Getenv("ROSA_TA_DB_MASTER_DSN"), os.Getenv("ROSA_TA_DB_MASTER_SECRET"), dsnCoordinates{
		host:    os.Getenv("ROSA_TA_DB_HOST"),
		port:    os.Getenv("ROSA_TA_DB_PORT"),
		dbname:  os.Getenv("ROSA_TA_DB_NAME"),
		sslmode: os.Getenv("ROSA_TA_DB_SSLMODE"),
		sslroot: os.Getenv("ROSA_TA_DB_SSLROOTCERT"),
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02T15:04:05Z07:00"})

	if err := store.BootstrapDatabase(ctx, dsn, logger); err != nil {
		return err
	}
	logger.Info("database bootstrap complete (idempotent — safe to re-run)")
	return nil
}
