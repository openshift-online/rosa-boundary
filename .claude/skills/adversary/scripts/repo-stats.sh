#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${1:-.}"
DAYS="${2:-90}"

if [ ! -d "$PROJECT_ROOT" ]; then
    echo "ERROR: Directory not found: $PROJECT_ROOT" >&2
    exit 1
fi

cd "$PROJECT_ROOT"

if ! git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    echo "ERROR: Not a git repository: $PROJECT_ROOT" >&2
    exit 1
fi

echo "=== REPO OVERVIEW ==="

total_commits=$(git rev-list --count HEAD 2>/dev/null || echo "0")
branch_count=$(git branch --list 2>/dev/null | wc -l)
tag_count=$(git tag --list 2>/dev/null | wc -l)
first_commit=$(git log --reverse --format="%ai" 2>/dev/null | head -1 | cut -d' ' -f1)
last_commit=$(git log -1 --format="%ai" 2>/dev/null | cut -d' ' -f1)
default_branch=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || git branch --show-current 2>/dev/null || echo "unknown")

echo "TOTAL_COMMITS=${total_commits}"
echo "BRANCHES=${branch_count}"
echo "TAGS=${tag_count}"
echo "FIRST_COMMIT=${first_commit:-unknown}"
echo "LAST_COMMIT=${last_commit:-unknown}"
echo "DEFAULT_BRANCH=${default_branch}"

echo ""
echo "=== CONTRIBUTOR STATS ==="

contributor_count=$(git shortlog -sn --no-merges HEAD 2>/dev/null | wc -l)
echo "TOTAL_CONTRIBUTORS=${contributor_count}"

echo ""
echo "TOP_CONTRIBUTORS:"
git shortlog -sn --no-merges HEAD 2>/dev/null | head -10 | while read -r count name; do
    echo "  ${count} ${name}"
done

# Bus factor: contributors needed to cover 80% of commits
echo ""
total_for_bus=$(git shortlog -sn --no-merges HEAD 2>/dev/null | awk '{print $1}')
total_sum=0
for c in $total_for_bus; do
    total_sum=$((total_sum + c))
done

if [ "$total_sum" -gt 0 ]; then
    threshold=$((total_sum * 80 / 100))
    running=0
    bus_factor=0
    for c in $total_for_bus; do
        running=$((running + c))
        bus_factor=$((bus_factor + 1))
        if [ "$running" -ge "$threshold" ]; then
            break
        fi
    done
    echo "BUS_FACTOR=${bus_factor}"
else
    echo "BUS_FACTOR=0"
fi

echo ""
echo "=== HOTSPOTS (most modified files, all time) ==="

git log --format=format: --name-only HEAD 2>/dev/null \
    | grep -v '^$' \
    | sort \
    | uniq -c \
    | sort -rn \
    | head -20 \
    | while read -r count file; do
        echo "  ${count}  ${file}"
    done

echo ""
echo "=== RECENT HOTSPOTS (last ${DAYS} days) ==="

since_date=$(date -d "${DAYS} days ago" +%Y-%m-%d 2>/dev/null || date -v-${DAYS}d +%Y-%m-%d 2>/dev/null || echo "")

if [ -n "$since_date" ]; then
    git log --since="$since_date" --format=format: --name-only HEAD 2>/dev/null \
        | grep -v '^$' \
        | sort \
        | uniq -c \
        | sort -rn \
        | head -20 \
        | while read -r count file; do
            echo "  ${count}  ${file}"
        done
else
    echo "  (date calculation unavailable on this platform)"
fi

echo ""
echo "=== CODE CHURN (last ${DAYS} days) ==="

if [ -n "${since_date:-}" ]; then
    git log --since="$since_date" --numstat --format="" HEAD 2>/dev/null \
        | awk '{ added[$3]+=$1; removed[$3]+=$2 } END { for(f in added) if(f != "") printf "  +%-6d -%-6d %s\n", added[f], removed[f], f }' \
        | sort -t'+' -k2 -rn \
        | head -15
else
    echo "  (date calculation unavailable on this platform)"
fi

echo ""
echo "=== LARGE FILES (>1MB tracked) ==="

git ls-files 2>/dev/null | while read -r file; do
    if [ -f "$file" ]; then
        size=$(stat --format="%s" "$file" 2>/dev/null || stat -f "%z" "$file" 2>/dev/null || echo "0")
        if [ "$size" -gt 1048576 ]; then
            size_mb=$(awk "BEGIN {printf \"%.1f\", $size/1048576}")
            echo "  ${size_mb}MB  ${file}"
        fi
    fi
done

echo ""
echo "=== STALE BRANCHES (no commits in 90+ days) ==="

stale_date=$(date -d "90 days ago" +%s 2>/dev/null || date -v-90d +%s 2>/dev/null || echo "")

if [ -n "$stale_date" ]; then
    git for-each-ref --sort=-committerdate --format='%(refname:short) %(committerdate:unix) %(committerdate:short)' refs/heads/ 2>/dev/null | while read -r branch epoch datestr; do
        if [ -n "$epoch" ] && [ "$epoch" -lt "$stale_date" ]; then
            echo "  ${datestr}  ${branch}"
        fi
    done
else
    echo "  (date calculation unavailable on this platform)"
fi

echo ""
echo "=== COMMIT VELOCITY ==="

if [ -n "${since_date:-}" ]; then
    recent_commits=$(git rev-list --count --since="$since_date" HEAD 2>/dev/null || echo "0")
    weekly_avg=$(awk "BEGIN {printf \"%.1f\", $recent_commits / ($DAYS / 7)}")
    echo "COMMITS_LAST_${DAYS}_DAYS=${recent_commits}"
    echo "WEEKLY_AVERAGE=${weekly_avg}"
else
    echo "COMMITS_LAST_${DAYS}_DAYS=unavailable"
    echo "WEEKLY_AVERAGE=unavailable"
fi

echo ""
echo "=== MERGE PATTERNS ==="

merge_commits=$(git rev-list --merges --count HEAD 2>/dev/null || echo "0")
total_for_pct=${total_commits:-1}
if [ "$total_for_pct" -gt 0 ]; then
    merge_pct=$(awk "BEGIN {printf \"%.1f\", $merge_commits * 100 / $total_for_pct}")
else
    merge_pct="0.0"
fi
echo "MERGE_COMMITS=${merge_commits}"
echo "MERGE_PERCENTAGE=${merge_pct}%"
