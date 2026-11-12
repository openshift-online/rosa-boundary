# Files

- [ROSA Boundary auditing and logging flows](audit-and-logging.md) - Inventories the evidence produced by ROSA Boundary, explains its contents, access paths, retention and protection controls — including the Git-managed log_retention_days workspace variable — and identifies audit-coverage boundaries.
- [Trusted Actions audit and logging](trusted-actions-audit.md) - Explains Trusted Actions' two audit mechanisms — the per-request AuditEntry row written by middleware.NewAuditLogger into its SQLite-backed store, and the per-execution audit.Record the executor logs through the regional CloudWatch-to-Firehose-to-S3 pipeline — and how each is actually persisted, distinct from ROSA Boundary's own audit flows.
