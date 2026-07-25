#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
today="${FOCTET_REVIEW_DATE:-$(date -u +%F)}"

while IFS= read -r review_by; do
  if [[ "$review_by" < "$today" ]]; then
    echo "deny.toml contains an expired advisory exception (review-by $review_by)." >&2
    exit 1
  fi
done < <(sed -n 's/.*Review-by: \([0-9][0-9-]*\).*/\1/p' "$repository_root/deny.toml")

ignored_count="$(sed -n '/^ignore = \[/,/^\]/p' "$repository_root/deny.toml" | grep -c 'RUSTSEC-' || true)"
review_count="$(sed -n '/^ignore = \[/,/^\]/p' "$repository_root/deny.toml" | grep -c 'Review-by:' || true)"
if [[ "$ignored_count" != "$review_count" ]]; then
  echo "Every RustSec exception must have an owner, rationale, and Review-by date." >&2
  exit 1
fi
