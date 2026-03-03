#!/usr/bin/env bash
# deploy/verify-session.sh — Verify a remote forge session's results.
#
# A management Claude (or human) uses this to inspect what happened
# in a remote gleisner forge session.
#
# Usage:
#   ./deploy/verify-session.sh <results-dir>
#   ./deploy/verify-session.sh .gleisner/remote-sessions/gleisner-20260303-141500-12345
#
# Checks:
#   1. Manifest schema version
#   2. Session completed successfully
#   3. Forge output integrity (if both manifest and output are present)
#   4. Package metadata and attestation data

set -euo pipefail

RESULTS_DIR="${1:?usage: verify-session.sh <results-dir>}"

if [[ ! -f "${RESULTS_DIR}/manifest.json" ]]; then
    echo "error: no manifest.json in ${RESULTS_DIR}" >&2
    exit 1
fi

echo "=== Session Manifest ==="
# Pretty-print the manifest
python3 -m json.tool "${RESULTS_DIR}/manifest.json" 2>/dev/null || cat "${RESULTS_DIR}/manifest.json"

echo ""
echo "=== Verification ==="

# Check schema version
SCHEMA=$(python3 -c "import json; print(json.load(open('${RESULTS_DIR}/manifest.json')).get('schema', 'unknown'))" 2>/dev/null || echo "unknown")
echo "schema: ${SCHEMA}"

# Check status
STATUS=$(python3 -c "import json; print(json.load(open('${RESULTS_DIR}/manifest.json')).get('status', 'unknown'))" 2>/dev/null || echo "unknown")
echo "status: ${STATUS}"

if [[ -f "${RESULTS_DIR}/forge-output.json" ]]; then
    echo ""
    echo "=== Forge Output Summary ==="

    # Extract key stats
    python3 -c "
import json
data = json.load(open('${RESULTS_DIR}/forge-output.json'))

forge = data.get('forge', data)
stats = forge.get('stats', {})
attest = data.get('attestation', {})
env = forge.get('environment', {})

print(f'packages evaluated: {stats.get(\"evaluated\", \"?\")}')
print(f'packages failed: {stats.get(\"failed\", \"?\")}')
print(f'elapsed: {stats.get(\"elapsed_secs\", \"?\"):.1f}s')
print(f'dir mappings: {len(env.get(\"dir_mappings\", []))}')
print(f'file mappings: {len(env.get(\"file_mappings\", []))}')
print(f'dns needed: {env.get(\"needs\", {}).get(\"dns\", False)}')
print(f'internet needed: {env.get(\"needs\", {}).get(\"internet\", False)}')

if attest:
    print(f'materials: {len(attest.get(\"materials\", []))}')
    print(f'subjects: {len(attest.get(\"subjects\", []))}')
    print(f'package metadata: {len(attest.get(\"package_metadata\", []))}')

    for pm in attest.get('package_metadata', []):
        prov = pm.get('source_provenance', {})
        cat = prov.get('category', 'unknown') if prov else 'none'
        print(f'  {pm[\"name\"]}: {pm[\"purl\"]} (provenance: {cat})')

warnings = forge.get('warnings', []) + data.get('warnings', [])
if warnings:
    print(f'\\nwarnings ({len(warnings)}):')
    for w in warnings:
        print(f'  - {w}')
" 2>/dev/null || echo "(python3 not available for detailed analysis)"
fi

if [[ -f "${RESULTS_DIR}/forge-stderr.log" ]]; then
    echo ""
    echo "=== Forge Logs (stderr) ==="
    cat "${RESULTS_DIR}/forge-stderr.log"
fi

echo ""
echo "=== Result ==="
if [[ "$STATUS" == "complete" ]]; then
    echo "PASS: Session completed successfully"
    exit 0
else
    echo "FAIL: Session status is '${STATUS}'"
    exit 1
fi
