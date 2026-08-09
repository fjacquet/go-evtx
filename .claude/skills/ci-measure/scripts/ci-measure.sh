#!/usr/bin/env bash
# ci-measure — resolve the Format Verify run for a commit, wait with a hard
# ceiling, and print the measurement lines.
#
# Exists because two failure modes dominated the v0.7.0 investigation:
#   * six agents burned their entire budget in unbounded CI polling loops
#   * one cited a run whose head_sha was two commits stale, so its "identical"
#     result was mechanically guaranteed and proved nothing
#
# This script cannot do either: it matches by head_sha and it always exits.
set -uo pipefail

REPO="fjacquet/go-evtx"
SHA="${1:-$(git rev-parse HEAD)}"
MAX_WAIT="${2:-600}"   # seconds; hard ceiling, never exceeded
INTERVAL=20

FULL_SHA="$(git rev-parse "$SHA" 2>/dev/null)" || { echo "not a commit: $SHA" >&2; exit 1; }
echo "commit: ${FULL_SHA:0:7}"

# Resolve by head_sha, never by recency.
run_id=""
for id in $(gh run list --repo "$REPO" --limit 25 \
              --json databaseId,name --jq '.[] | select(.name=="Format Verify") | .databaseId'); do
  head="$(gh api "repos/$REPO/actions/runs/$id" --jq '.head_sha' 2>/dev/null)" || continue
  if [ "$head" = "$FULL_SHA" ]; then run_id="$id"; break; fi
done

if [ -z "$run_id" ]; then
  echo "no Format Verify run found with head_sha $FULL_SHA" >&2
  echo "(it may not have been created yet — push, then retry)" >&2
  exit 3
fi
echo "run: $run_id  https://github.com/$REPO/actions/runs/$run_id"

waited=0
while :; do
  status="$(gh api "repos/$REPO/actions/runs/$run_id" --jq '.status' 2>/dev/null || echo unknown)"
  [ "$status" = "completed" ] && break
  if [ "$waited" -ge "$MAX_WAIT" ]; then
    echo "PENDING after ${MAX_WAIT}s — status=$status. Not waiting further." >&2
    echo "Report the run ID as pending; do not loop." >&2
    exit 4
  fi
  sleep "$INTERVAL"; waited=$((waited + INTERVAL))
done

echo "--- measurements ---"
gh run view "$run_id" --repo "$REPO" --log 2>/dev/null \
  | grep -E 'STAGE1 OPEN:|STAGE2 READ:|PROP |GETWINEVENT|EXTSTATUS|WIN32ERROR|OK: [0-9]+ records|ObjectName count|wrote artifacts/|FAIL' \
  | grep -v 'Write-Host' \
  | sed 's/.*[0-9]Z //'

echo "--- job conclusions ---"
gh run view "$run_id" --repo "$REPO" --json jobs --jq '.jobs[] | "\(.name): \(.conclusion)"'
