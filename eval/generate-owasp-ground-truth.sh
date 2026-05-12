#!/usr/bin/env bash
# Generates ground-truth-owasp.yaml from the OWASP Benchmark subset's expected results CSV.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Oracle CSV lives at the eval/ root, not inside the fixture, so review agents
# operating inside the fixture cannot reach it.
CSV="${SCRIPT_DIR}/ground-truth-owasp.csv"
OUTPUT="${SCRIPT_DIR}/ground-truth-owasp.yaml"

if [[ ! -f "$CSV" ]]; then
    echo "Error: expected results CSV not found. Run create-subset.sh first."
    exit 1
fi

# CWE to category name mapping
declare -A CWE_NAMES=(
    [22]="Path Traversal"
    [78]="OS Command Injection"
    [79]="Cross-site Scripting"
    [89]="SQL Injection"
    [90]="LDAP Injection"
    [200]="Information Exposure"
    [327]="Broken Crypto"
    [328]="Weak Hash"
    [330]="Weak Random"
    [352]="CSRF"
    [501]="Trust Boundary Violation"
    [502]="Deserialization"
    [611]="XXE"
    [614]="Insecure Cookie"
    [643]="XPath Injection"
    [601]="Open Redirect"
    [94]="Code Injection"
)

# Category to tag mapping
declare -A CAT_TAGS=(
    [pathtraver]="path-traversal"
    [sqli]="injection, sql"
    [xss]="xss"
    [cmdi]="injection, command"
    [codeinj]="injection, code"
    [deserialization]="deserialization"
    [xpathi]="injection, xpath"
    [xxe]="xxe"
    [redirect]="redirect"
    [hash]="crypto, hash"
    [weakrand]="crypto, random"
    [securecookie]="session, cookie"
    [trustbound]="trust-boundary"
    [ldapi]="injection, ldap"
)

cat > "$OUTPUT" << 'HEADER'
# Ground truth for OWASP Benchmark Python subset.
# Auto-generated from expectedresults CSV - do not edit manually.
# Source: https://github.com/OWASP-Benchmark/BenchmarkPython
#
# This uses a real-world, non-LLM-generated test suite with documented
# true vulnerabilities and false positives across 14 CWE categories.

vulnerabilities:
HEADER

# Only emit true vulnerabilities as ground truth
count=0
while IFS=',' read -r test_name category is_vuln cwe; do
    [[ "$test_name" == "#"* ]] && continue
    [[ "$is_vuln" != "true" ]] && continue

    count=$((count + 1))
    cwe_name="${CWE_NAMES[$cwe]:-Unknown}"
    tags="${CAT_TAGS[$category]:-$category}"

    # Determine severity based on CWE
    case "$cwe" in
        89|78|502|94) severity="critical" ;;
        22|79|643|90|611) severity="high" ;;
        601|501|352) severity="medium" ;;
        327|328|330|614) severity="medium" ;;
        *) severity="medium" ;;
    esac

    cat >> "$OUTPUT" << EOF
  - id: "OWASP-$(printf '%03d' $count)"
    title: "${cwe_name} in ${test_name}"
    severity: ${severity}
    cwe: "CWE-${cwe}"
    file: "testcode/${test_name}.py"
    line_start: 0
    tags: [${tags}]
    description: "OWASP Benchmark test case: true ${category} vulnerability"

EOF
done < "$CSV"

# Add false positive tracking section
cat >> "$OUTPUT" << 'FOOTER'
# False positives in this test set (findings against these should NOT match):
# These are test cases with the same CWE category but where the vulnerability
# is NOT actually exploitable. Tools that flag these are producing false positives.
false_positives:
FOOTER

while IFS=',' read -r test_name category is_vuln cwe; do
    [[ "$test_name" == "#"* ]] && continue
    [[ "$is_vuln" != "false" ]] && continue

    cat >> "$OUTPUT" << EOF
  - test_name: "${test_name}"
    category: "${category}"
    cwe: "CWE-${cwe}"
    file: "testcode/${test_name}.py"
EOF
done < "$CSV"

# Add scoring config
cat >> "$OUTPUT" << 'CONFIG'

severity_weights:
  critical: 5
  high: 3
  medium: 2
  low: 1
  info: 0

matching:
  line_tolerance: 30
  cwe_exact_match: true
  title_similarity_threshold: 0.2
CONFIG

echo "Generated $OUTPUT with $count true vulnerabilities"
