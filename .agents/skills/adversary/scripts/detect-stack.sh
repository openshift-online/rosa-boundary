#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${1:-.}"

if [ ! -d "$PROJECT_ROOT" ]; then
    echo "ERROR: Directory not found: $PROJECT_ROOT" >&2
    exit 1
fi

cd "$PROJECT_ROOT"

echo "=== LANGUAGE DETECTION ==="

declare -A lang_counts=()
while IFS= read -r ext; do
    case "$ext" in
        go)   lang_counts[go]=$(( ${lang_counts[go]:-0} + 1 )) ;;
        py)   lang_counts[python]=$(( ${lang_counts[python]:-0} + 1 )) ;;
        js)   lang_counts[javascript]=$(( ${lang_counts[javascript]:-0} + 1 )) ;;
        ts)   lang_counts[typescript]=$(( ${lang_counts[typescript]:-0} + 1 )) ;;
        tsx)  lang_counts[typescript]=$(( ${lang_counts[typescript]:-0} + 1 )) ;;
        jsx)  lang_counts[javascript]=$(( ${lang_counts[javascript]:-0} + 1 )) ;;
        java) lang_counts[java]=$(( ${lang_counts[java]:-0} + 1 )) ;;
        cs)   lang_counts[csharp]=$(( ${lang_counts[csharp]:-0} + 1 )) ;;
        rb)   lang_counts[ruby]=$(( ${lang_counts[ruby]:-0} + 1 )) ;;
        rs)   lang_counts[rust]=$(( ${lang_counts[rust]:-0} + 1 )) ;;
        swift) lang_counts[swift]=$(( ${lang_counts[swift]:-0} + 1 )) ;;
        kt)   lang_counts[kotlin]=$(( ${lang_counts[kotlin]:-0} + 1 )) ;;
        dart) lang_counts[dart]=$(( ${lang_counts[dart]:-0} + 1 )) ;;
        php)  lang_counts[php]=$(( ${lang_counts[php]:-0} + 1 )) ;;
        sh|bash) lang_counts[shell]=$(( ${lang_counts[shell]:-0} + 1 )) ;;
    esac
done < <(find . -type f \
    -not -path '*/node_modules/*' \
    -not -path '*/.git/*' \
    -not -path '*/vendor/*' \
    -not -path '*/dist/*' \
    -not -path '*/build/*' \
    -not -path '*/target/*' \
    -not -path '*/__pycache__/*' \
    -not -path '*/.venv/*' \
    -not -path '*/.tox/*' \
    2>/dev/null | sed -n 's/.*\.\([^./]*\)$/\1/p')

langs=""
for lang in "${!lang_counts[@]}"; do
    [ -n "$langs" ] && langs="${langs},"
    langs="${langs}${lang}:${lang_counts[$lang]}"
done
echo "LANGUAGES=${langs:-none}"

echo ""
echo "=== FRAMEWORK DETECTION ==="

frameworks=""

add_framework() {
    [ -n "$frameworks" ] && frameworks="${frameworks},"
    frameworks="${frameworks}$1"
}

# Python frameworks
if [ -f "requirements.txt" ] || [ -f "pyproject.toml" ] || [ -f "setup.py" ] || [ -f "Pipfile" ]; then
    for manifest in requirements.txt pyproject.toml setup.py Pipfile; do
        [ -f "$manifest" ] || continue
        grep -qi "fastapi" "$manifest" 2>/dev/null && add_framework "fastapi"
        grep -qi "django" "$manifest" 2>/dev/null && add_framework "django"
        grep -qi "flask" "$manifest" 2>/dev/null && add_framework "flask"
        grep -qi "sqlalchemy" "$manifest" 2>/dev/null && add_framework "sqlalchemy"
        grep -qi "celery" "$manifest" 2>/dev/null && add_framework "celery"
        grep -qi "pytest" "$manifest" 2>/dev/null && add_framework "pytest"
    done
fi

# Node.js frameworks
if [ -f "package.json" ]; then
    grep -q '"react"' package.json 2>/dev/null && add_framework "react"
    grep -q '"next"' package.json 2>/dev/null && add_framework "nextjs"
    grep -q '"vue"' package.json 2>/dev/null && add_framework "vue"
    grep -q '"nuxt"' package.json 2>/dev/null && add_framework "nuxt"
    grep -q '"angular' package.json 2>/dev/null && add_framework "angular"
    grep -q '"express"' package.json 2>/dev/null && add_framework "express"
    grep -q '"@nestjs' package.json 2>/dev/null && add_framework "nestjs"
    grep -q '"svelte"' package.json 2>/dev/null && add_framework "svelte"
    grep -q '"hono"' package.json 2>/dev/null && add_framework "hono"
fi

# Go frameworks
if [ -f "go.mod" ]; then
    grep -q "gin-gonic" go.mod 2>/dev/null && add_framework "gin"
    grep -q "labstack/echo" go.mod 2>/dev/null && add_framework "echo"
    grep -q "gofiber" go.mod 2>/dev/null && add_framework "fiber"
    grep -q "gorilla/mux" go.mod 2>/dev/null && add_framework "gorilla"
    grep -q "go-chi" go.mod 2>/dev/null && add_framework "chi"
fi

# Java frameworks
for jmanifest in pom.xml build.gradle build.gradle.kts; do
    [ -f "$jmanifest" ] || continue
    grep -qi "spring-boot" "$jmanifest" 2>/dev/null && add_framework "spring-boot"
    grep -qi "quarkus" "$jmanifest" 2>/dev/null && add_framework "quarkus"
    grep -qi "micronaut" "$jmanifest" 2>/dev/null && add_framework "micronaut"
done

# Ruby frameworks
if [ -f "Gemfile" ]; then
    grep -q "'rails'" Gemfile 2>/dev/null && add_framework "rails"
    grep -q "'sinatra'" Gemfile 2>/dev/null && add_framework "sinatra"
fi

# Rust frameworks
if [ -f "Cargo.toml" ]; then
    grep -q "actix-web" Cargo.toml 2>/dev/null && add_framework "actix"
    grep -q "axum" Cargo.toml 2>/dev/null && add_framework "axum"
    grep -q "rocket" Cargo.toml 2>/dev/null && add_framework "rocket"
fi

# Mobile frameworks
[ -f "pubspec.yaml" ] && add_framework "flutter"
[ -f "Podfile" ] && add_framework "cocoapods"
if [ -f "package.json" ]; then
    grep -q '"react-native"' package.json 2>/dev/null && add_framework "react-native"
fi

echo "FRAMEWORKS=${frameworks:-none}"

echo ""
echo "=== DATABASE DETECTION ==="

databases=""

add_db() {
    case ",$databases," in
        *",$1,"*) ;; # already added
        *) [ -n "$databases" ] && databases="${databases},$1"; databases="${databases:-$1}" ;;
    esac
}

# From docker-compose
for compose in docker-compose.yml docker-compose.yaml compose.yml compose.yaml; do
    [ -f "$compose" ] || continue
    grep -qi "postgres" "$compose" 2>/dev/null && add_db "postgresql"
    grep -qi "mysql" "$compose" 2>/dev/null && add_db "mysql"
    grep -qi "mariadb" "$compose" 2>/dev/null && add_db "mariadb"
    grep -qi "mongo" "$compose" 2>/dev/null && add_db "mongodb"
    grep -qi "redis" "$compose" 2>/dev/null && add_db "redis"
    grep -qi "elasticsearch" "$compose" 2>/dev/null && add_db "elasticsearch"
    grep -qi "cassandra" "$compose" 2>/dev/null && add_db "cassandra"
done

# From config/source files
grep -rql "sqlite" --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.rb" . 2>/dev/null | head -1 > /dev/null && add_db "sqlite"
grep -rql "DATABASE_URL.*postgres" --include="*.env*" --include="*.yml" --include="*.yaml" --include="*.toml" . 2>/dev/null | head -1 > /dev/null && add_db "postgresql"
grep -rql "DATABASE_URL.*mysql" --include="*.env*" --include="*.yml" --include="*.yaml" . 2>/dev/null | head -1 > /dev/null && add_db "mysql"
grep -rql "REDIS_URL\|redis://" --include="*.env*" --include="*.yml" --include="*.yaml" --include="*.toml" . 2>/dev/null | head -1 > /dev/null && add_db "redis"
grep -rql "MONGO.*URI\|mongodb://" --include="*.env*" --include="*.yml" --include="*.yaml" . 2>/dev/null | head -1 > /dev/null && add_db "mongodb"

echo "DATABASES=${databases:-none}"

echo ""
echo "=== INFRASTRUCTURE DETECTION ==="

infra=""

add_infra() {
    [ -n "$infra" ] && infra="${infra},$1"
    infra="${infra:-$1}"
}

find . -name "Dockerfile" -o -name "Containerfile" -not -path '*/.git/*' 2>/dev/null | head -1 | grep -q . && add_infra "docker"
find . -name "docker-compose*.yml" -o -name "docker-compose*.yaml" -o -name "compose.yml" -o -name "compose.yaml" -not -path '*/.git/*' 2>/dev/null | head -1 | grep -q . && add_infra "docker-compose"
find . -name "*.tf" -not -path '*/.git/*' 2>/dev/null | head -1 | grep -q . && add_infra "terraform"
find . -name "Chart.yaml" -not -path '*/.git/*' 2>/dev/null | head -1 | grep -q . && add_infra "helm"
find . -path "*/k8s/*" -o -path "*/kubernetes/*" -o -path "*/deploy/*.yaml" -not -path '*/.git/*' 2>/dev/null | head -1 | grep -q . && add_infra "kubernetes"
[ -d "argocd" ] || [ -d ".argocd" ] && add_infra "argocd"

echo "INFRASTRUCTURE=${infra:-none}"

echo ""
echo "=== CI/CD DETECTION ==="

cicd=""

add_cicd() {
    [ -n "$cicd" ] && cicd="${cicd},$1"
    cicd="${cicd:-$1}"
}

[ -d ".github/workflows" ] && add_cicd "github-actions"
[ -f "Jenkinsfile" ] && add_cicd "jenkins"
[ -f ".gitlab-ci.yml" ] && add_cicd "gitlab-ci"
[ -d ".circleci" ] && add_cicd "circleci"
[ -d ".tekton" ] && add_cicd "tekton"
[ -f "buildspec.yml" ] || [ -f "buildspec.yaml" ] && add_cicd "aws-codebuild"
[ -f "Makefile" ] && add_cicd "make"

echo "CICD=${cicd:-none}"

echo ""
echo "=== BUILD TOOLS ==="

build_tools=""

add_build() {
    [ -n "$build_tools" ] && build_tools="${build_tools},$1"
    build_tools="${build_tools:-$1}"
}

if [ -f "package.json" ]; then
    grep -q '"webpack"' package.json 2>/dev/null && add_build "webpack"
    grep -q '"vite"' package.json 2>/dev/null && add_build "vite"
    grep -q '"esbuild"' package.json 2>/dev/null && add_build "esbuild"
    grep -q '"rollup"' package.json 2>/dev/null && add_build "rollup"
    grep -q '"turbo"' package.json 2>/dev/null && add_build "turborepo"
fi
[ -f "Cargo.toml" ] && add_build "cargo"
[ -f "go.mod" ] && add_build "go"
[ -f "mix.exs" ] && add_build "mix"

echo "BUILD_TOOLS=${build_tools:-none}"

echo ""
echo "=== PACKAGE MANAGERS ==="

pkg_mgrs=""

add_pkg() {
    [ -n "$pkg_mgrs" ] && pkg_mgrs="${pkg_mgrs},$1"
    pkg_mgrs="${pkg_mgrs:-$1}"
}

[ -f "package-lock.json" ] && add_pkg "npm"
[ -f "yarn.lock" ] && add_pkg "yarn"
[ -f "pnpm-lock.yaml" ] && add_pkg "pnpm"
[ -f "go.mod" ] && add_pkg "go-mod"
[ -f "requirements.txt" ] || [ -f "Pipfile" ] && add_pkg "pip"
[ -f "uv.lock" ] && add_pkg "uv"
[ -f "Gemfile.lock" ] && add_pkg "bundler"
[ -f "Cargo.lock" ] && add_pkg "cargo"
[ -f "pubspec.lock" ] && add_pkg "pub"
[ -f "Podfile.lock" ] && add_pkg "cocoapods"

echo "PACKAGE_MANAGERS=${pkg_mgrs:-none}"

echo ""
echo "=== MONOREPO DETECTION ==="

monorepo="false"
monorepo_tool="none"

[ -f "lerna.json" ] && monorepo="true" && monorepo_tool="lerna"
[ -f "nx.json" ] && monorepo="true" && monorepo_tool="nx"
[ -f "pnpm-workspace.yaml" ] && monorepo="true" && monorepo_tool="pnpm-workspaces"
if [ -f "package.json" ]; then
    grep -q '"workspaces"' package.json 2>/dev/null && monorepo="true" && monorepo_tool="${monorepo_tool:-npm-workspaces}"
fi
[ -f "WORKSPACE" ] || [ -f "WORKSPACE.bazel" ] && monorepo="true" && monorepo_tool="bazel"

echo "MONOREPO=${monorepo}"
echo "MONOREPO_TOOL=${monorepo_tool}"

echo ""
echo "=== FILE COUNTS ==="
total_files=$(find . -type f \
    -not -path '*/node_modules/*' \
    -not -path '*/.git/*' \
    -not -path '*/vendor/*' \
    -not -path '*/dist/*' \
    -not -path '*/build/*' \
    -not -path '*/target/*' \
    -not -path '*/__pycache__/*' \
    -not -path '*/.venv/*' \
    2>/dev/null | wc -l)

source_files=$(find . -type f \
    \( -name "*.go" -o -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.tsx" -o -name "*.jsx" \
    -o -name "*.java" -o -name "*.cs" -o -name "*.rb" -o -name "*.rs" -o -name "*.swift" \
    -o -name "*.kt" -o -name "*.dart" -o -name "*.php" -o -name "*.sh" \) \
    -not -path '*/node_modules/*' \
    -not -path '*/.git/*' \
    -not -path '*/vendor/*' \
    -not -path '*/dist/*' \
    2>/dev/null | wc -l)

test_files=$(find . -type f \
    \( -name "*_test.*" -o -name "*.test.*" -o -name "*.spec.*" -o -name "*_spec.*" \) \
    -not -path '*/node_modules/*' \
    -not -path '*/.git/*' \
    2>/dev/null | wc -l)

config_files=$(find . -type f \
    \( -name "*.yml" -o -name "*.yaml" -o -name "*.toml" -o -name "*.json" -o -name "*.ini" -o -name "*.cfg" \) \
    -not -path '*/node_modules/*' \
    -not -path '*/.git/*' \
    -not -path '*/vendor/*' \
    2>/dev/null | wc -l)

echo "TOTAL_FILES=${total_files}"
echo "SOURCE_FILES=${source_files}"
echo "TEST_FILES=${test_files}"
echo "CONFIG_FILES=${config_files}"
