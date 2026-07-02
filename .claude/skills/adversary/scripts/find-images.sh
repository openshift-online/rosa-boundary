#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${1:-.}"

if [ ! -d "$PROJECT_ROOT" ]; then
    echo "ERROR: Directory not found: $PROJECT_ROOT" >&2
    exit 1
fi

cd "$PROJECT_ROOT"

echo "=== IMAGE INVENTORY ==="

total=0
doc_images=0
diagram_images=0
asset_images=0
other_images=0

find . -type f \
    \( -iname "*.png" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.gif" \
    -o -iname "*.svg" -o -iname "*.webp" -o -iname "*.drawio" -o -iname "*.mermaid" \) \
    -not -path '*/node_modules/*' \
    -not -path '*/.git/*' \
    -not -path '*/vendor/*' \
    -not -path '*/dist/*' \
    -not -path '*/build/*' \
    -not -path '*/__pycache__/*' \
    2>/dev/null | sort | while read -r filepath; do

    size=$(stat --format="%s" "$filepath" 2>/dev/null || stat -f "%z" "$filepath" 2>/dev/null || echo "0")
    size_kb=$(awk "BEGIN {printf \"%.1f\", $size/1024}")

    category="other"
    case "$filepath" in
        */docs/*|*/documentation/*|*/wiki/*|*/doc/*)
            category="documentation"
            ;;
        */diagrams/*|*/architecture/*|*/design/*|*/adr/*)
            category="diagram"
            ;;
        */assets/*|*/static/*|*/public/*|*/images/*|*/img/*)
            category="asset"
            ;;
        */.github/*)
            category="documentation"
            ;;
    esac

    ext="${filepath##*.}"
    ext_lower=$(echo "$ext" | tr '[:upper:]' '[:lower:]')

    echo "${category}|${size_kb}KB|${ext_lower}|${filepath}"
done

echo ""
echo "=== SUMMARY ==="

doc_count=$(find . -type f \
    \( -iname "*.png" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.gif" -o -iname "*.svg" -o -iname "*.webp" -o -iname "*.drawio" -o -iname "*.mermaid" \) \
    \( -path "*/docs/*" -o -path "*/documentation/*" -o -path "*/wiki/*" -o -path "*/doc/*" -o -path "*/.github/*" \) \
    -not -path '*/node_modules/*' -not -path '*/.git/*' \
    2>/dev/null | wc -l)

diagram_count=$(find . -type f \
    \( -iname "*.png" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.gif" -o -iname "*.svg" -o -iname "*.webp" -o -iname "*.drawio" -o -iname "*.mermaid" \) \
    \( -path "*/diagrams/*" -o -path "*/architecture/*" -o -path "*/design/*" -o -path "*/adr/*" \) \
    -not -path '*/node_modules/*' -not -path '*/.git/*' \
    2>/dev/null | wc -l)

asset_count=$(find . -type f \
    \( -iname "*.png" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.gif" -o -iname "*.svg" -o -iname "*.webp" \) \
    \( -path "*/assets/*" -o -path "*/static/*" -o -path "*/public/*" -o -path "*/images/*" -o -path "*/img/*" \) \
    -not -path '*/node_modules/*' -not -path '*/.git/*' \
    2>/dev/null | wc -l)

total_count=$(find . -type f \
    \( -iname "*.png" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.gif" -o -iname "*.svg" -o -iname "*.webp" -o -iname "*.drawio" -o -iname "*.mermaid" \) \
    -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/vendor/*' -not -path '*/dist/*' \
    2>/dev/null | wc -l)

echo "TOTAL_IMAGES=${total_count}"
echo "DOCUMENTATION=${doc_count}"
echo "DIAGRAMS=${diagram_count}"
echo "ASSETS=${asset_count}"
echo "OTHER=$((total_count - doc_count - diagram_count - asset_count))"

echo ""
echo "=== DIAGRAM FILES (architecture-relevant) ==="

find . -type f \
    \( -iname "*.drawio" -o -iname "*.mermaid" -o -iname "*.puml" -o -iname "*.plantuml" \) \
    -not -path '*/node_modules/*' -not -path '*/.git/*' \
    2>/dev/null | sort | while read -r filepath; do
    echo "  ${filepath}"
done

find . -type f -iname "*.svg" \
    -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/vendor/*' \
    2>/dev/null | sort | while read -r filepath; do
    if grep -qi "diagram\|architecture\|flow\|sequence\|component" "$filepath" 2>/dev/null; then
        echo "  ${filepath} (likely diagram)"
    fi
done
