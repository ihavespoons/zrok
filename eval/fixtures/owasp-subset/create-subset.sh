#!/usr/bin/env bash
# Creates a curated subset of OWASP Benchmark Python for evaluation.
# Selects 3 true vulns + 2 false positives per category for a balanced test set.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_DIR="${SCRIPT_DIR}/../owasp-benchmark-python"
SUBSET_DIR="${SCRIPT_DIR}"

if [[ ! -d "$BENCHMARK_DIR" ]]; then
    echo "Error: OWASP Benchmark not found. Run: git submodule update --init"
    exit 1
fi

CSV="$BENCHMARK_DIR/expectedresults-0.1.csv"

# Categories to sample from
CATEGORIES=(pathtraver sqli xss cmdi codeinj deserialization xpathi xxe redirect hash weakrand securecookie trustbound ldapi)

# Number of true/false per category
TRUE_PER_CAT=3
FALSE_PER_CAT=2

# Copy supporting files
mkdir -p "$SUBSET_DIR/testcode" "$SUBSET_DIR/helpers" "$SUBSET_DIR/testfiles" "$SUBSET_DIR/templates"
cp "$BENCHMARK_DIR/app.py" "$SUBSET_DIR/" 2>/dev/null || true
cp "$BENCHMARK_DIR/requirements.txt" "$SUBSET_DIR/" 2>/dev/null || true
cp -r "$BENCHMARK_DIR/helpers/"* "$SUBSET_DIR/helpers/" 2>/dev/null || true
cp -r "$BENCHMARK_DIR/testfiles/"* "$SUBSET_DIR/testfiles/" 2>/dev/null || true

# Build subset
# Oracle is written OUTSIDE the fixture root so agents reviewing the fixture
# cannot reach it. The fixture path is what recon-agent sees; the oracle path
# is for the scorer only.
ORACLE="$(cd "$SUBSET_DIR/../.." && pwd)/ground-truth-owasp.csv"
> "$ORACLE"
echo "# test name, category, real vulnerability, cwe" >> "$ORACLE"

TOTAL=0
for cat in "${CATEGORIES[@]}"; do
    # True vulnerabilities
    count=0
    while IFS=',' read -r test_name category is_vuln cwe; do
        [[ "$test_name" == "#"* ]] && continue
        [[ "$category" != "$cat" ]] && continue
        [[ "$is_vuln" != "true" ]] && continue
        [[ $count -ge $TRUE_PER_CAT ]] && break

        test_file="$BENCHMARK_DIR/testcode/${test_name}.py"
        if [[ -f "$test_file" ]]; then
            cp "$test_file" "$SUBSET_DIR/testcode/"
            echo "${test_name},${category},${is_vuln},${cwe}" >> "$ORACLE"
            count=$((count + 1))
            TOTAL=$((TOTAL + 1))
        fi
    done < "$CSV"

    # False positives
    count=0
    while IFS=',' read -r test_name category is_vuln cwe; do
        [[ "$test_name" == "#"* ]] && continue
        [[ "$category" != "$cat" ]] && continue
        [[ "$is_vuln" != "false" ]] && continue
        [[ $count -ge $FALSE_PER_CAT ]] && break

        test_file="$BENCHMARK_DIR/testcode/${test_name}.py"
        if [[ -f "$test_file" ]]; then
            cp "$test_file" "$SUBSET_DIR/testcode/"
            echo "${test_name},${category},${is_vuln},${cwe}" >> "$ORACLE"
            count=$((count + 1))
            TOTAL=$((TOTAL + 1))
        fi
    done < "$CSV"
done

# Copy relevant templates
for f in "$SUBSET_DIR"/testcode/*.py; do
    test_name=$(basename "$f" .py)
    # Extract the template path from the test file
    template_subdir=$(grep -oP "render_template\('web/\K[^/]+" "$f" 2>/dev/null | head -1) || true
    if [[ -n "$template_subdir" ]]; then
        src_template="$BENCHMARK_DIR/templates/web/$template_subdir"
        if [[ -d "$src_template" ]]; then
            mkdir -p "$SUBSET_DIR/templates/web/$template_subdir"
            cp "$src_template"/*.html "$SUBSET_DIR/templates/web/$template_subdir/" 2>/dev/null || true
        fi
    fi
done

# Also copy base templates
if [[ -d "$BENCHMARK_DIR/templates" ]]; then
    for f in "$BENCHMARK_DIR/templates/"*.html; do
        [[ -f "$f" ]] && cp "$f" "$SUBSET_DIR/templates/"
    done
fi

echo "Created subset with $TOTAL test cases in $SUBSET_DIR"
echo "Expected results: $ORACLE"
