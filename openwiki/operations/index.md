# Files

- [ROSA Boundary auditing and logging flows](audit-and-logging.md) - Inventories the evidence produced by ROSA Boundary, explains its contents, access paths, retention and protection controls — including the Git-managed log_retention_days workspace variable — and identifies audit-coverage boundaries.
- [Trusted Actions audit and logging](trusted-actions-audit.md) - Explains Trusted Actions' structured per-call audit.Record model, how middleware and the executor inject and emit it, and the regional CloudWatch-to-Firehose-to-S3 pipeline that ships those records — distinct from ROSA Boundary's own audit flows.
