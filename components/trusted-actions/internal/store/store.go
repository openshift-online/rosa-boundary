package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/openshift-online/rosa-trusted-actions/internal/models"
)

var ErrNotFound = errors.New("not found")

type ExecutionFilter struct {
	Status        *string
	Action        *string
	Target        *string
	Operator      *string
	Scope         *string
	Type          *string
	ApprovalState *string
	DryRun        *bool
	Force         *bool
	Since         *time.Time
	Limit         int
	Offset        int
}

type ExecutionListResult struct {
	Items  []models.Execution
	Total  int
	Limit  int
	Offset int
}

type AuditFilter struct {
	Action        *string
	Target        *string
	Operator      *string
	Method        *string
	ApprovalState *string
	Since         *time.Time
	Limit         int
	Offset        int
}

type AuditListResult struct {
	Items  []models.AuditEntry
	Total  int
	Limit  int
	Offset int
}

// NewWithIAM selects the store, taking the IAM database contract as an
// explicit argument. A partial IAM contract (some of host/port/name/user
// set, host missing) fails loudly rather than silently falling back to
// DATABASE_URL/SQLite: a truncated or mistyped ROSA_TA_DB_* environment
// would otherwise quietly run the server against the wrong database.
func NewWithIAM(ctx context.Context, databaseURL string, iamDB IAMDBConfig, cfg PostgresConfig, logger *logrus.Logger) (Store, error) {
	if iamDB.Host != "" || iamDB.Port != "" || iamDB.DBName != "" || iamDB.User != "" {
		return newIAMPostgresStore(ctx, iamDB, cfg, logger)
	}
	if strings.HasPrefix(databaseURL, "postgres://") || strings.HasPrefix(databaseURL, "postgresql://") {
		return NewPostgresStore(ctx, databaseURL, cfg, logger)
	}
	return NewSQLiteStore(ctx, databaseURL, logger)
}

type Store interface {
	CreateExecution(ctx context.Context, exec *models.Execution) error
	GetExecution(ctx context.Context, id uuid.UUID) (*models.Execution, error)
	GetExecutionOutput(ctx context.Context, execId uuid.UUID) (*models.ExecutionOutput, error)
	ListExecutions(ctx context.Context, filter ExecutionFilter) (*ExecutionListResult, error)
	UpdateExecutionWithResult(ctx context.Context, id uuid.UUID, status, reason string, completedAt *time.Time, output *models.ExecutionOutput) error
	// ClaimNextExecution atomically claims the oldest pending execution,
	// transitioning it to running, for a worker to process. Returns
	// ErrNotFound if no execution is pending.
	ClaimNextExecution(ctx context.Context) (*models.Execution, error)

	CreateAuditEntry(ctx context.Context, entry *models.AuditEntry) error
	ListAuditEntries(ctx context.Context, filter AuditFilter) (*AuditListResult, error)

	Close() error
}
