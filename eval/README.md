# zrok Evaluation Framework

Measures the consistency and accuracy of zrok code reviews by running evaluations against test applications with known vulnerabilities, then comparing findings to ground truth.

## Test Fixtures

### OWASP Benchmark Python (recommended)

A curated 70-test subset of the [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython) -- a non-LLM-generated, community-maintained test suite. Contains 42 true vulnerabilities and 28 false positives across 14 CWE categories (SQL injection, XSS, command injection, path traversal, deserialization, etc.).

This is the primary fixture because:
- Written by humans, not an LLM (avoids detection bias)
- Each test case has a documented expected result (true vuln or false positive)
- Covers OWASP Top 10 categories
- False positive cases test whether the tool correctly ignores non-exploitable patterns

### Vulnerable Flask App (supplementary)

A smaller app (`fixtures/vulnerable-app/`) with 18 intentional vulnerabilities for quick smoke tests.

## Quick Start

```bash
# Prerequisites
go build -o zrok .
git submodule update --init  # Pulls OWASP Benchmark

# Prepare OWASP subset (extracts 70 test cases from full benchmark)
eval/fixtures/owasp-subset/create-subset.sh
eval/generate-owasp-ground-truth.sh

# Dry run (shows config without executing)
./eval/run.sh --fixture owasp --dry-run

# Run 10 evaluations and generate baseline
./eval/run.sh --fixture owasp -n 10 --baseline

# Compare a new run against baseline
./eval/run.sh --fixture owasp --compare
```

## Metrics

| Metric | Description |
|--------|-------------|
| **Recall** | % of known vulnerabilities detected |
| **Precision** | % of reported findings that match real vulnerabilities |
| **F1 Score** | Harmonic mean of precision and recall |
| **Weighted Recall** | Recall weighted by severity (critical=5, high=3, medium=2, low=1) |
| **Severity Accuracy** | % of detected findings with correct severity rating |
| **Confirmed FP** | Findings that match known false-positive test cases (OWASP only) |
| **Per-vuln detection rate** | How often each vulnerability is found across runs |

## Scorer CLI

```bash
# Score a single run
eval/eval-scorer score --run eval/results/owasp/run-01.json \
    --ground-truth eval/ground-truth-owasp.yaml

# Generate baseline from multiple runs
eval/eval-scorer baseline --runs eval/results/owasp/ \
    --ground-truth eval/ground-truth-owasp.yaml \
    -o eval/baseline-owasp.json

# Compare run to baseline (exits non-zero on failure)
eval/eval-scorer compare --run eval/results/owasp/run-new.json \
    --baseline eval/baseline-owasp.json \
    --ground-truth eval/ground-truth-owasp.yaml
```

## CI/CD Integration

The `eval.yaml` workflow supports two authentication methods:

### Claude Max subscription (recommended for personal use)

Uses your Max subscription instead of API billing:

1. Run `claude setup-token` locally to generate an OAuth token
2. Add it as a GitHub secret: `CLAUDE_CODE_OAUTH_TOKEN`
3. The workflow uses this automatically

### API key

1. Add `ANTHROPIC_API_KEY` as a GitHub secret
2. Billed per token through the Anthropic API

### Workflow modes

**On pull requests** (automatic): Runs a single evaluation against the OWASP fixture and compares to baseline. Fails if metrics drop below thresholds.

**Manual dispatch**: Go to Actions > Evaluation > Run workflow:
- `compare` mode: Single run against baseline
- `baseline` mode: N runs to generate/update baseline (commits `baseline-{fixture}.json`)

## Baseline Thresholds

Computed as `mean - 2*stddev` from baseline runs, accounting for LLM variance:

- Minimum recall
- Minimum F1 score
- Minimum weighted recall
- Maximum false positive rate (50% default)

## Project Structure

```
eval/
├── fixtures/
│   ├── owasp-benchmark-python/    # Git submodule (full OWASP benchmark)
│   ├── owasp-subset/              # Curated 70-test subset (generated)
│   │   └── create-subset.sh       # Generates subset from full benchmark
│   └── vulnerable-app/            # Small Flask app with 18 vulns
├── scorer/                        # Go scoring package
│   ├── scorer.go                  # Matching, metrics, baseline, comparison
│   └── scorer_test.go             # Tests
├── cmd/                           # CLI: score, baseline, compare
├── run.sh                         # Evaluation runner
├── generate-owasp-ground-truth.sh # Generates YAML from OWASP CSV
├── ground-truth.yaml              # Ground truth for vulnerable-app
├── ground-truth-owasp.yaml        # Ground truth for OWASP (generated)
├── baseline-owasp.json            # Baseline for OWASP (generated after runs)
├── baseline-vulnerable-app.json   # Baseline for vulnerable-app (generated)
└── results/                       # Run output (gitignored)
```
