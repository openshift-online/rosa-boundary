# Database Security Reference

Security checks for SQL/NoSQL databases, ORMs, migrations, connection management, and data protection.

## SQL Injection Prevention

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| String concatenation in queries | Building SQL with `+`, `f""`, `format()`, `fmt.Sprintf` | CRITICAL | Use parameterized queries / prepared statements in all cases |
| Template literals in SQL | `` `SELECT * FROM users WHERE id = ${id}` `` | CRITICAL | Use parameterized queries: `db.query('SELECT * FROM users WHERE id = $1', [id])` |
| Dynamic table/column names from user input | `SELECT * FROM ${tableName}` | CRITICAL | Use allowlists for table/column names. Never interpolate user input as identifiers |
| ORM raw queries with interpolation | `Model.raw(f"SELECT * FROM foo WHERE bar = '{val}'")` | CRITICAL | Use ORM parameterization: `Model.raw('SELECT * FROM foo WHERE bar = ?', [val])` |
| Stored procedure injection | Dynamic SQL in stored procedures | HIGH | Use parameterized dynamic SQL: `EXECUTE ... USING` in PostgreSQL, `sp_executesql` in SQL Server |
| LIKE injection | User input in LIKE clauses without escaping `%` and `_` | MEDIUM | Escape LIKE wildcards: `value.replace('%', '\\%').replace('_', '\\_')` |

**Remediation — Parameterized queries by language:**

```javascript
// Node.js (pg)
const { rows } = await pool.query(
  'SELECT * FROM users WHERE email = $1 AND status = $2',
  [email, 'active']
);

// Node.js (mysql2)
const [rows] = await connection.execute(
  'SELECT * FROM users WHERE email = ? AND status = ?',
  [email, 'active']
);
```

```python
# Python (psycopg2)
cursor.execute(
    "SELECT * FROM users WHERE email = %s AND status = %s",
    (email, 'active')
)

# Python (SQLAlchemy)
result = session.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": email}
)

# Python (Django ORM) — safe by default
User.objects.filter(email=email, status='active')
```

```go
// Go (database/sql)
row := db.QueryRow(
    "SELECT * FROM users WHERE email = $1 AND status = $2",
    email, "active",
)
```

```java
// Java (JDBC PreparedStatement)
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM users WHERE email = ? AND status = ?"
);
stmt.setString(1, email);
stmt.setString(2, "active");
```

## NoSQL Injection

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| MongoDB operator injection | User input directly in query object: `{ email: req.body.email }` | CRITICAL | Validate input types. Reject objects/arrays where strings expected: `if (typeof email !== 'string') throw` |
| MongoDB `$where` with user input | `$where: 'this.name == "' + name + '"'` | CRITICAL | Never use `$where` with user input. Use standard query operators |
| Redis command injection | Building Redis commands from user input | HIGH | Use parameterized Redis client methods. Never concatenate user input into command strings |
| LDAP injection | User input in LDAP filter strings | HIGH | Escape LDAP special characters: `*`, `(`, `)`, `\`, NUL. Use framework's escape functions |

**Remediation — MongoDB injection prevention:**
```javascript
// Before (vulnerable — user could send { "$gt": "" } as email)
const user = await db.collection('users').findOne({ email: req.body.email });

// After (fixed)
const email = req.body.email;
if (typeof email !== 'string') {
  return res.status(400).json({ error: 'Invalid email' });
}
const user = await db.collection('users').findOne({ email });
```

## Access Control

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Database user with superuser privileges | Application connecting as postgres/root/sa | CRITICAL | Create a dedicated application user with minimum required privileges |
| Missing row-level security | Multi-tenant data without row-level access control | HIGH | Implement row-level security (RLS) in PostgreSQL, or enforce tenant filtering in application layer |
| Excessive GRANT privileges | `GRANT ALL ON ALL TABLES` to application user | HIGH | Grant only needed privileges: `GRANT SELECT, INSERT, UPDATE ON specific_tables TO app_user` |
| Missing schema separation | All tables in `public` schema | MEDIUM | Use separate schemas for different concerns. Restrict application user to application schema |
| Shared database credentials | Multiple services using the same database user | HIGH | Create separate database users per service with appropriate permissions |

**Remediation — Least-privilege database user (PostgreSQL):**
```sql
-- Create application role
CREATE ROLE app_user LOGIN PASSWORD 'use_env_var_not_this';

-- Grant specific privileges
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app TO app_user;

-- Prevent schema modifications
REVOKE CREATE ON SCHEMA app FROM app_user;

-- Row-Level Security for multi-tenancy
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON orders
    USING (tenant_id = current_setting('app.tenant_id')::uuid);
```

## Data Protection

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| PII stored unencrypted | Names, emails, SSNs, credit cards in plaintext | HIGH | Encrypt PII at rest using application-level encryption (AES-256-GCM). Use database-level TDE as additional layer |
| Missing data masking | Full PII returned in non-essential queries | MEDIUM | Return masked data where full values aren't needed: `***-**-1234` for SSN, `j***@example.com` for email |
| No data retention policy | Sensitive data stored indefinitely | MEDIUM | Implement data retention policies. Auto-delete or anonymize data after retention period |
| Missing audit logging | No logging of data access/modifications | MEDIUM | Log all data access to sensitive tables: who, what, when. Use database triggers or application middleware |
| Backup without encryption | Database backups stored unencrypted | HIGH | Encrypt all backups. Use managed backup encryption (AWS RDS encryption, GCP Cloud SQL). Test restoration |
| Missing data classification | No classification of sensitive vs non-sensitive columns | LOW | Classify columns: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED. Apply controls based on classification |

**Remediation — Application-level encryption:**
```python
from cryptography.fernet import Fernet

class EncryptedField:
    def __init__(self):
        self.cipher = Fernet(os.environ['ENCRYPTION_KEY'])

    def encrypt(self, plaintext: str) -> str:
        return self.cipher.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        return self.cipher.decrypt(ciphertext.encode()).decode()

# Usage in model
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String)  # searchable, not encrypted
    ssn_encrypted = Column(String)  # encrypted at rest

    _enc = EncryptedField()

    @property
    def ssn(self):
        return self._enc.decrypt(self.ssn_encrypted)

    @ssn.setter
    def ssn(self, value):
        self.ssn_encrypted = self._enc.encrypt(value)
```

## Migration Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Destructive migrations without safeguards | `DROP TABLE`, `DROP COLUMN` without backup/confirmation | HIGH | Add data backup step before destructive migrations. Use soft-delete patterns. Make migrations reversible |
| GRANT/REVOKE in migrations | Privilege changes mixed with schema changes | MEDIUM | Separate privilege changes into their own migrations. Review privilege changes independently |
| Default values revealing secrets | `ALTER TABLE ADD COLUMN ... DEFAULT 'secret'` | HIGH | Never use secret values as column defaults. Use NULL or empty string defaults |
| Unreviewed auto-generated migrations | ORM auto-generated migrations committed without review | MEDIUM | Always review generated migrations before committing. Check for unintended data loss or privilege changes |
| Missing migration rollback | Migrations without down/rollback method | MEDIUM | Always implement rollback for every migration. Test rollback in staging before applying to production |
| Data migration with SQL injection | Dynamic SQL in data migration scripts | HIGH | Use parameterized queries even in migration scripts |

**Remediation — Safe migration pattern:**
```python
# Alembic migration (Python/SQLAlchemy)
def upgrade():
    # Add new column as nullable first
    op.add_column('users', sa.Column('phone_encrypted', sa.String()))

    # Backfill data
    connection = op.get_bind()
    connection.execute(
        text("UPDATE users SET phone_encrypted = :default WHERE phone_encrypted IS NULL"),
        {"default": ""}
    )

    # Then make non-nullable
    op.alter_column('users', 'phone_encrypted', nullable=False)

def downgrade():
    op.drop_column('users', 'phone_encrypted')
```

## Connection Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unencrypted database connections | Connecting without TLS/SSL | HIGH | Enable TLS: `sslmode=require` (PostgreSQL), `ssl: true` (MySQL). Verify server certificate in production |
| Connection string in source code | Hardcoded `postgresql://user:pass@host/db` | CRITICAL | Use environment variables or secret managers (AWS Secrets Manager, HashiCorp Vault) |
| Connection string in version control | Database URL in committed config files | CRITICAL | Add connection config files to `.gitignore`. Use `.env.example` with placeholder values |
| Missing connection pool limits | Unbounded database connections | HIGH | Set pool limits: `max: 20` for most apps. Monitor active connections vs pool size |
| Missing query timeouts | No statement timeout configured | HIGH | Set statement_timeout: `SET statement_timeout = '30s'` or in connection config |
| Missing idle connection timeout | Idle connections held indefinitely | MEDIUM | Set idle timeout: `idleTimeoutMillis: 30000`. Prevents connection exhaustion |

**Remediation — Secure database connection (Node.js/PostgreSQL):**
```javascript
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync('/path/to/ca-cert.pem'),
  },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  statement_timeout: 30000,
});
```

## Query Safety

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| SELECT * in production | Using `SELECT *` instead of explicit columns | LOW | List explicit columns. Prevents accidental data exposure when new sensitive columns are added |
| Missing LIMIT on queries | Queries that could return unbounded results | HIGH | Always add LIMIT. Set maximum allowed: `LIMIT LEAST($1, 100)` |
| N+1 query patterns | ORM lazy loading causing excessive queries | MEDIUM | Use eager loading / `JOIN` / `prefetch_related`. Monitor query count per request |
| Missing index on filtered columns | WHERE clauses on unindexed columns in large tables | LOW | Add indexes for frequently filtered/sorted columns. Use EXPLAIN to verify query plans |
| Unsafe DELETE/UPDATE without WHERE | `DELETE FROM table` or `UPDATE table SET ...` without WHERE clause | CRITICAL | Always include WHERE clause. Use transactions. Add application-level safeguards against mass operations |
