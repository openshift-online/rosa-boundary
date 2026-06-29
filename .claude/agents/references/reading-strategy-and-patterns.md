# File Reading Strategy & Tech Stack Patterns

Combined reference for file reading prioritization and framework-specific patterns used in Groundwork Phase 0.

---

# File Reading Strategy


Governs which files groundwork reads, in what order, and what to skip. Designed to maximize analysis quality within practical context limits.

## Always Skip

These paths are never read during groundwork analysis — they are generated, vendored, or binary content with no analytical value.

| Pattern | Reason |
|---------|--------|
| `node_modules/` | Vendored dependencies |
| `vendor/` | Vendored dependencies (Go, PHP, Ruby) |
| `.git/` | Git internals |
| `dist/`, `build/`, `out/` | Build output |
| `target/` | Rust/Java build output |
| `__pycache__/`, `*.pyc` | Python bytecode |
| `.venv/`, `.tox/`, `env/`, `venv/` | Virtual environments |
| `.next/`, `.nuxt/`, `.svelte-kit/` | Framework build cache |
| `coverage/`, `.nyc_output/` | Test coverage output |
| `*.min.js`, `*.min.css` | Minified files |
| `*.map` (source maps) | Generated mappings |
| `*.generated.*`, `*.pb.go`, `*_pb2.py` | Generated code |
| `swagger-ui/`, `redoc/` | Generated API docs |
| `*.wasm`, `*.class`, `*.o`, `*.so`, `*.dylib` | Compiled binaries |
| `*.png`, `*.jpg`, `*.gif`, `*.ico`, `*.woff*` | Binary assets (use find-images.sh instead) |
| `*.sqlite`, `*.db` | Database files |

### Lock Files — Read Manifests Instead

| Skip (lock) | Read Instead (manifest) |
|-------------|------------------------|
| `package-lock.json` | `package.json` |
| `yarn.lock` | `package.json` |
| `pnpm-lock.yaml` | `package.json` |
| `Cargo.lock` | `Cargo.toml` |
| `go.sum` | `go.mod` |
| `Gemfile.lock` | `Gemfile` |
| `uv.lock`, `Pipfile.lock` | `requirements.txt`, `pyproject.toml`, `Pipfile` |
| `pubspec.lock` | `pubspec.yaml` |
| `Podfile.lock` | `Podfile` |
| `composer.lock` | `composer.json` |
| `.terraform.lock.hcl` | `*.tf` files |
| `Chart.lock` | `Chart.yaml` |

## Priority Read Order

Read files in this order to build understanding from entry points outward.

### Priority 1: Entry Points & Configuration

| Pattern | What It Reveals |
|---------|----------------|
| `main.*`, `app.*`, `index.*`, `server.*` | Application entry point and initialization |
| `cmd/` directory | Go CLI/service entry points |
| `manage.py` | Django management entry |
| `settings.*`, `config.*`, `*.config.*` | Application configuration shape |
| `.env.example`, `.env.sample` | Environment variable requirements |
| Root `*.yaml`, `*.toml`, `*.json` | Project-level configuration |

### Priority 2: Routing & API Definitions

| Pattern | What It Reveals |
|---------|----------------|
| `routes/`, `router/`, `urls.py` | Request routing and endpoint definitions |
| `api/`, `handlers/`, `controllers/` | API implementation |
| `openapi.*`, `swagger.*`, `*.api.yaml` | API specifications |
| `middleware/` | Request/response pipeline |
| `graphql/`, `schema.graphql`, `*.gql` | GraphQL schema and resolvers |

### Priority 3: Models, Schema & Auth

| Pattern | What It Reveals |
|---------|----------------|
| `models/`, `entities/`, `schema/` | Data model definitions |
| `migrations/`, `migrate/` | Schema evolution history |
| `*.sql` (non-migration) | Raw queries, stored procedures |
| `auth/`, `security/`, `middleware/auth*` | Authentication and authorization logic |
| `permissions/`, `policies/`, `rbac/` | Access control definitions |

### Priority 4: Core Business Logic

| Pattern | What It Reveals |
|---------|----------------|
| `services/`, `domain/`, `core/`, `lib/` | Business logic implementation |
| `internal/`, `pkg/` | Go internal/shared packages |
| `utils/`, `helpers/`, `common/` | Shared utilities |
| `workers/`, `jobs/`, `tasks/`, `queues/` | Background processing |

### Priority 5: Infrastructure & DevOps

| Pattern | What It Reveals |
|---------|----------------|
| `Dockerfile`, `Containerfile` | Container build and runtime config |
| `docker-compose*` | Multi-container orchestration |
| `*.tf`, `*.tfvars` | Infrastructure as code |
| `Chart.yaml`, `templates/` (Helm) | Kubernetes deployment templates |
| `k8s/`, `kubernetes/`, `deploy/` | Kubernetes manifests |
| `.github/workflows/`, `Jenkinsfile` | CI/CD pipeline definitions |

### Priority 6: Tests

| Pattern | What It Reveals |
|---------|----------------|
| `*_test.*`, `*.test.*`, `*.spec.*` | Test patterns and coverage approach |
| `test/`, `tests/`, `__tests__/`, `spec/` | Test organization |
| `fixtures/`, `testdata/`, `mocks/` | Test infrastructure |
| `conftest.py`, `jest.config.*` | Test framework configuration |

### Priority 7: Documentation

| Pattern | What It Reveals |
|---------|----------------|
| `README*`, `CONTRIBUTING*`, `CHANGELOG*` | Project documentation |
| `docs/`, `documentation/`, `wiki/` | Extended documentation |
| `ARCHITECTURE.md`, `DESIGN.md` | Design decisions |
| `adr/`, `ADR/`, `decisions/` | Architecture Decision Records |

## Size Limits

| Constraint | Limit | Rationale |
|------------|-------|-----------|
| Max files for deep reading | 200 per project | Context budget — prioritize by read order |
| Skip individual files over | 5,000 lines | Likely generated or data dumps |
| For files over 500 lines | Read first 200 + last 50 | Understand structure and exports |
| Total line budget per project | ~50,000 lines | Practical context limit |
| Max single-read batch | 20 files | Avoid context flooding per agent |

## Framework-Specific Read Patterns

When a framework is detected, reorder the read queue to prioritize framework-critical files.

### Django
`settings.py` → `urls.py` → `models.py` → `views.py` → `serializers.py` → `admin.py` → `forms.py` → `signals.py` → `middleware.py` → `management/commands/`

### FastAPI / Flask
`main.py` or `app.py` → `routers/` or `routes/` → `models/` → `schemas/` → `dependencies.py` → `middleware.py` → `config.py`

### React / Next.js
`App.*` or `_app.*` → `pages/` or `app/` → `routes.*` → `store/` or `context/` → `hooks/` → `components/` (top-level) → `api/` (Next.js API routes)

### Express.js / Nest.js
`app.*` or `server.*` → `routes/` → `controllers/` → `middleware/` → `models/` → `services/` → `config/`

### Go (standard layout)
`main.go` → `cmd/` → `internal/` → `pkg/` → `api/` → `models/` or `domain/` → `middleware/` → `config/`

### Spring Boot
`*Application.java` → `*Controller.java` → `*Service.java` → `*Repository.java` → `*Entity.java` → `*Config.java` → `*Filter.java`

### Rails
`config/routes.rb` → `app/models/` → `app/controllers/` → `app/services/` → `config/initializers/` → `db/migrate/` → `config/application.rb`

### Rust (Actix/Axum)
`main.rs` → `lib.rs` → `routes/` or `handlers/` → `models/` → `middleware/` → `config/` → `schema.rs`

---

# Tech Stack Patterns


Comprehensive mapping of file patterns to technology stacks. Supplements `scripts/detect-stack.sh` with interpretation guidance and security implications.

## Language Detection

| File Extension | Language | Confidence | Notes |
|---------------|----------|-----------|-------|
| `.go` | Go | High | Check `go.mod` for module path |
| `.py` | Python | High | Check version in `pyproject.toml` or `setup.py` |
| `.js` | JavaScript | High | May be Node.js backend or browser frontend |
| `.ts`, `.tsx` | TypeScript | High | `.tsx` indicates React/JSX usage |
| `.jsx` | JavaScript (React) | High | React component files |
| `.java` | Java | High | Check `pom.xml`/`build.gradle` for framework |
| `.cs` | C# | High | Check `*.csproj` for .NET version |
| `.rb` | Ruby | High | Check `Gemfile` for framework |
| `.rs` | Rust | High | Check `Cargo.toml` for crate type |
| `.swift` | Swift | High | iOS/macOS application |
| `.kt`, `.kts` | Kotlin | High | Android or server-side (Spring) |
| `.dart` | Dart | High | Almost always Flutter |
| `.php` | PHP | High | Check `composer.json` for framework |
| `.ex`, `.exs` | Elixir | High | Check `mix.exs` for Phoenix |
| `.sh`, `.bash` | Shell | Medium | Scripts, not application code |

## Framework Detection from Manifests

### Python Ecosystem

| Manifest Pattern | Framework | Detection Method |
|-----------------|-----------|-----------------|
| `fastapi` in requirements/pyproject | FastAPI | Grep dependencies |
| `django` in requirements/pyproject | Django | Grep dependencies |
| `flask` in requirements/pyproject | Flask | Grep dependencies |
| `sqlalchemy` in requirements/pyproject | SQLAlchemy (ORM) | Grep dependencies |
| `celery` in requirements/pyproject | Celery (task queue) | Grep dependencies |
| `alembic` in requirements/pyproject | Alembic (migrations) | Grep dependencies |
| `pydantic` in requirements/pyproject | Pydantic (validation) | Grep dependencies |

### Node.js Ecosystem

| Manifest Pattern | Framework | Detection Method |
|-----------------|-----------|-----------------|
| `"react"` in package.json deps | React | JSON key match |
| `"next"` in package.json deps | Next.js | JSON key match |
| `"vue"` in package.json deps | Vue.js | JSON key match |
| `"nuxt"` in package.json deps | Nuxt.js | JSON key match |
| `"@angular/core"` in package.json | Angular | JSON key match |
| `"express"` in package.json deps | Express.js | JSON key match |
| `"@nestjs/core"` in package.json | Nest.js | JSON key match |
| `"svelte"` in package.json deps | Svelte | JSON key match |
| `"hono"` in package.json deps | Hono | JSON key match |
| `"prisma"` in package.json deps | Prisma (ORM) | JSON key match |

### Go Ecosystem

| Manifest Pattern | Framework | Detection Method |
|-----------------|-----------|-----------------|
| `gin-gonic/gin` in go.mod | Gin | Module require |
| `labstack/echo` in go.mod | Echo | Module require |
| `gofiber/fiber` in go.mod | Fiber | Module require |
| `go-chi/chi` in go.mod | Chi | Module require |
| `gorilla/mux` in go.mod | Gorilla Mux | Module require |
| `gorm.io/gorm` in go.mod | GORM (ORM) | Module require |
| `jmoiron/sqlx` in go.mod | sqlx | Module require |

### Java/Kotlin Ecosystem

| Manifest Pattern | Framework | Detection Method |
|-----------------|-----------|-----------------|
| `spring-boot` in pom.xml/build.gradle | Spring Boot | Dependency match |
| `quarkus` in pom.xml/build.gradle | Quarkus | Dependency match |
| `micronaut` in pom.xml/build.gradle | Micronaut | Dependency match |
| `hibernate` in pom.xml/build.gradle | Hibernate (ORM) | Dependency match |

### Ruby Ecosystem

| Manifest Pattern | Framework | Detection Method |
|-----------------|-----------|-----------------|
| `'rails'` in Gemfile | Ruby on Rails | Gem match |
| `'sinatra'` in Gemfile | Sinatra | Gem match |
| `'grape'` in Gemfile | Grape (API) | Gem match |

### Rust Ecosystem

| Manifest Pattern | Framework | Detection Method |
|-----------------|-----------|-----------------|
| `actix-web` in Cargo.toml | Actix Web | Crate dependency |
| `axum` in Cargo.toml | Axum | Crate dependency |
| `rocket` in Cargo.toml | Rocket | Crate dependency |
| `diesel` in Cargo.toml | Diesel (ORM) | Crate dependency |
| `sqlx` in Cargo.toml | SQLx | Crate dependency |

## Database Detection

| Detection Source | Database | Signal Type |
|-----------------|----------|-------------|
| `postgres` in docker-compose | PostgreSQL | Container service |
| `DATABASE_URL.*postgres` in .env | PostgreSQL | Connection string |
| `pg` or `asyncpg` in deps | PostgreSQL | Client library |
| `mysql` in docker-compose | MySQL | Container service |
| `mysql2` or `pymysql` in deps | MySQL | Client library |
| `mongo` in docker-compose | MongoDB | Container service |
| `pymongo` or `mongoose` in deps | MongoDB | Client library |
| `redis` in docker-compose | Redis | Container service |
| `redis` or `ioredis` in deps | Redis | Client library |
| `elasticsearch` in docker-compose | Elasticsearch | Container service |
| `sqlite3` in deps or imports | SQLite | Embedded DB |
| `cassandra` in docker-compose | Cassandra | Container service |

## Infrastructure Detection

| File/Pattern | Technology | Category |
|-------------|-----------|----------|
| `Dockerfile`, `Containerfile` | Docker | Container |
| `docker-compose*.yml` | Docker Compose | Orchestration |
| `*.tf`, `*.tfvars` | Terraform | IaC |
| `Chart.yaml` | Helm | K8s packaging |
| `kustomization.yaml` | Kustomize | K8s customization |
| `k8s/`, `kubernetes/`, `deploy/*.yaml` | Kubernetes | Orchestration |
| `argocd/`, `applicationset*` | ArgoCD | GitOps |
| `pulumi.*`, `Pulumi.yaml` | Pulumi | IaC |
| `serverless.yml` | Serverless Framework | FaaS |
| `sam.yaml`, `template.yaml` (AWS) | AWS SAM | FaaS |

## CI/CD Detection

| File/Pattern | System | Category |
|-------------|--------|----------|
| `.github/workflows/*.yml` | GitHub Actions | CI/CD |
| `Jenkinsfile` | Jenkins | CI/CD |
| `.gitlab-ci.yml` | GitLab CI | CI/CD |
| `.circleci/config.yml` | CircleCI | CI/CD |
| `.tekton/` | Tekton | CI/CD |
| `buildspec.yml` | AWS CodeBuild | CI/CD |
| `.travis.yml` | Travis CI | CI/CD |
| `azure-pipelines.yml` | Azure DevOps | CI/CD |
| `Makefile` | Make | Build automation |

## Security Implications by Stack

Maps detected stack components to security domains that should be activated, with key risks to watch for.

| Stack Component | Security Domains | Key Risks |
|----------------|------------------|-----------|
| **Django** | Web, Auth, Database, CSRF | Default admin exposure, ORM injection via `extra()`, `DEBUG=True` in production, `SECRET_KEY` exposure |
| **FastAPI** | API, Auth, Database | Missing auth on auto-generated docs, Pydantic bypass, CORS misconfiguration |
| **Flask** | Web, API, Auth | `app.secret_key` hardcoded, `debug=True`, no CSRF by default, Jinja2 SSTI |
| **Express.js** | Web, API, Auth | Missing `helmet`, `bodyParser` limits, `eval()`, prototype pollution |
| **Nest.js** | Web, API, Auth | Guard bypass, DTO validation gaps, CORS misconfiguration |
| **React** | Web | `dangerouslySetInnerHTML`, XSS in SSR, exposed env vars (`REACT_APP_*`) |
| **Next.js** | Web, API | API route auth gaps, SSR data leakage, `getServerSideProps` injection, middleware bypass |
| **Spring Boot** | Web, API, Auth, Database | Actuator exposure, SpEL injection, CSRF config, mass assignment |
| **Gin/Echo/Fiber** | API, Auth | Missing CORS middleware, no rate limiting default, context injection |
| **Rails** | Web, API, Auth, Database | Mass assignment, SQL injection via `where` strings, `permit` gaps, session fixation |
| **React Native** | Mobile, Web | AsyncStorage secrets, deep link hijacking, JavaScript bridge injection |
| **Flutter** | Mobile | Platform channel security, insecure storage, certificate pinning bypass |
| **Terraform** | Infrastructure, Cloud | IAM wildcard, public S3/GCS, missing encryption, state file exposure |
| **Kubernetes** | Container, Infrastructure | Privileged pods, RBAC over-permission, missing network policies, secret in env |
| **Docker** | Container | Running as root, unpinned base images, secrets in build args, exposed ports |
| **GitHub Actions** | CI/CD, Supply Chain | `pull_request_target` exploit, unpinned actions, secret exposure in logs |

## Monorepo Detection

| Tool | Detection File | Workspace Discovery |
|------|---------------|-------------------|
| Lerna | `lerna.json` | `packages` field in lerna.json |
| Nx | `nx.json` | `projects` in nx.json or workspace.json |
| Turborepo | `turbo.json` | `workspaces` in package.json |
| pnpm Workspaces | `pnpm-workspace.yaml` | `packages` field |
| npm/Yarn Workspaces | `package.json` with `workspaces` | `workspaces` array |
| Bazel | `WORKSPACE` or `WORKSPACE.bazel` | `BUILD` files |
| Cargo Workspaces | `Cargo.toml` with `[workspace]` | `members` field |
| Go Workspaces | `go.work` | `use` directives |

When a monorepo is detected, each workspace/package should be treated as a potential sub-project for cross-project overlap analysis.
