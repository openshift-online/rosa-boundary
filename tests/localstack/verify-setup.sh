#!/bin/bash
# Verification script for LocalStack testing infrastructure

set -euo pipefail

echo "========================================="
echo "LocalStack Testing Setup Verification"
echo "========================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}✓${NC} $1"
}

fail() {
    echo -e "${RED}✗${NC} $1"
}

warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

ERRORS=0

# Check 1: Directory structure
echo "Checking directory structure..."
REQUIRED_DIRS=(
    "tests/localstack/oidc"
    "tests/localstack/oidc/test_keys"
    "tests/localstack/terraform"
    "tests/localstack/integration"
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        pass "Directory exists: $dir"
    else
        fail "Missing directory: $dir"
        ((ERRORS++))
    fi
done
echo ""

# Check 2: Required files
echo "Checking required files..."
REQUIRED_FILES=(
    "tests/localstack/compose.yml"
    "tests/localstack/.env.example"
    "tests/localstack/init-aws.sh"
    "tests/localstack/conftest.py"
    "tests/localstack/pytest.ini"
    "tests/localstack/README.md"
    "tests/localstack/oidc/Containerfile"
    "tests/localstack/oidc/mock_jwks.py"
    "tests/localstack/oidc/requirements.txt"
    "tests/localstack/oidc/test_keys/private.pem"
    "tests/localstack/oidc/test_keys/public.pem"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        pass "File exists: $file"
    else
        fail "Missing file: $file"
        ((ERRORS++))
    fi
done
echo ""

# Check 3: Test files
echo "Checking integration test files..."
TEST_FILES=(
    "tests/localstack/integration/test_s3_audit.py"
    "tests/localstack/integration/test_iam_roles.py"
    "tests/localstack/integration/test_kms_keys.py"
    "tests/localstack/integration/test_efs_access_points.py"
    "tests/localstack/integration/test_ecs_tasks.py"
    "tests/localstack/integration/test_tag_isolation.py"
    "tests/localstack/integration/test_lambda_handler.py"
    "tests/localstack/integration/test_full_workflow.py"
)

for file in "${TEST_FILES[@]}"; do
    if [ -f "$file" ]; then
        pass "Test file exists: $file"
    else
        fail "Missing test file: $file"
        ((ERRORS++))
    fi
done
echo ""

# Check 4: Environment configuration
echo "Checking environment configuration..."
if [ -f "tests/localstack/.env" ]; then
    pass ".env file exists"
    if grep -q "LOCALSTACK_AUTH_TOKEN=" tests/localstack/.env; then
        pass "LOCALSTACK_AUTH_TOKEN present in .env"
    else
        warn "LOCALSTACK_AUTH_TOKEN not found in .env"
        echo "  Add your token from: https://app.localstack.cloud/workspace/auth-tokens"
    fi
else
    warn ".env file not found"
    echo "  Copy .env.example to .env and add LOCALSTACK_AUTH_TOKEN"
fi
echo ""

# Check 5: Podman setup
echo "Checking podman setup..."
if command -v podman &> /dev/null; then
    pass "podman installed"
    
    # Check podman socket
    if systemctl --user is-active podman.socket &> /dev/null; then
        pass "podman.socket is active"
    else
        warn "podman.socket is not running"
        echo "  Start with: systemctl --user start podman.socket"
    fi
else
    fail "podman not installed"
    ((ERRORS++))
fi

if command -v podman-compose &> /dev/null; then
    pass "podman-compose installed"
else
    warn "podman-compose not installed"
    echo "  Install with: uv pip install podman-compose"
fi
echo ""

# Check 6: uv package manager
echo "Checking uv package manager..."
if command -v uv &> /dev/null; then
    pass "uv is installed"
else
    warn "uv not installed (recommended for this project)"
    echo "  Install with: curl -LsSf https://astral.sh/uv/install.sh | sh"
fi
echo ""

# Check 7: Python dependencies
echo "Checking Python dependencies..."
PYTHON_DEPS=(pytest boto3 requests)

for dep in "${PYTHON_DEPS[@]}"; do
    if python3 -c "import $dep" 2>/dev/null; then
        pass "Python module: $dep"
    else
        warn "Missing Python module: $dep"
        echo "  Install with: uv pip install $dep"
    fi
done
echo ""

# Check 8: RSA keys
echo "Checking RSA keys..."
if [ -f "tests/localstack/oidc/test_keys/private.pem" ]; then
    if openssl rsa -in tests/localstack/oidc/test_keys/private.pem -check -noout &> /dev/null; then
        pass "Valid RSA private key"
    else
        fail "Invalid RSA private key"
        ((ERRORS++))
    fi
fi

if [ -f "tests/localstack/oidc/test_keys/public.pem" ]; then
    if openssl rsa -pubin -in tests/localstack/oidc/test_keys/public.pem -noout &> /dev/null; then
        pass "Valid RSA public key"
    else
        fail "Invalid RSA public key"
        ((ERRORS++))
    fi
fi
echo ""

# Check 9: Makefile targets
echo "Checking Makefile targets..."
MAKEFILE_TARGETS=(localstack-up localstack-down localstack-logs test-localstack test-localstack-fast)

for target in "${MAKEFILE_TARGETS[@]}"; do
    if grep -q "^$target:" Makefile; then
        pass "Makefile target: $target"
    else
        fail "Missing Makefile target: $target"
        ((ERRORS++))
    fi
done
echo ""

# Check 10: GitIgnore entries
echo "Checking .gitignore entries..."
if grep -q "tests/localstack/.env" .gitignore; then
    pass ".gitignore excludes tests/localstack/.env"
else
    warn ".gitignore missing: tests/localstack/.env"
fi

if grep -q "tests/localstack/volume/" .gitignore; then
    pass ".gitignore excludes tests/localstack/volume/"
else
    warn ".gitignore missing: tests/localstack/volume/"
fi
echo ""

# Summary
echo "========================================="
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ Setup verification PASSED${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Ensure .env file has LOCALSTACK_AUTH_TOKEN"
    echo "2. Run: make localstack-up"
    echo "3. Run: make test-localstack-fast"
else
    echo -e "${RED}✗ Setup verification FAILED${NC}"
    echo ""
    echo "Found $ERRORS critical errors"
    echo "Fix the errors above and run this script again"
    exit 1
fi
