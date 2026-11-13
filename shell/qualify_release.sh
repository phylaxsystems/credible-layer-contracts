#!/usr/bin/env bash
set -euo pipefail

# Publishing and CI can start on the same push. The caller bounds the entire
# wait with a job timeout; API denial and malformed responses fail immediately.
: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_SHA:?}"
if [[ ! "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo '::error::Publication requires a full source commit SHA.' >&2
  exit 1
fi

latest_run() {
  gh api --method GET \
    "repos/$GITHUB_REPOSITORY/actions/workflows/solidity-test.yml/runs" \
    -f event=push -f "head_sha=$GITHUB_SHA" -F per_page=100 | jq -er '
    if .total_count == (.workflow_runs | length) then
      [.workflow_runs[] | select(.head_branch == "main" or .head_branch == "linea")]
      | if length == 0 then "waiting" else max_by(.run_number).id end
    else error("Incomplete CI run list") end
  '
}

for attempt in {1..40}; do
  run_id=$(latest_run)
  [[ "$run_id" == waiting ]] || break
  echo "Waiting for branch CI on $GITHUB_SHA ($attempt/40)..."
  sleep 15
done
if [[ ! "$run_id" =~ ^[0-9]+$ ]]; then
  echo "::error::No branch CI run qualified $GITHUB_SHA." >&2
  exit 1
fi

# Do not select only successful runs: a newer failure or rerun must supersede
# an older success, and PR merge-commit checks are not publication evidence.
gh run watch "$run_id" --repo "$GITHUB_REPOSITORY" --exit-status --interval 15
run=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id")
ci_url=$(jq -er --arg sha "$GITHUB_SHA" --arg repo "$GITHUB_REPOSITORY" '
  select(.head_sha == $sha and .head_repository.full_name == $repo
    and (.head_branch == "main" or .head_branch == "linea")
    and .event == "push" and .path == ".github/workflows/solidity-test.yml"
    and .status == "completed" and .conclusion == "success")
  | .html_url + "/attempts/" + (.run_attempt | tostring)
' <<< "$run")
run_attempt=$(jq -er '.run_attempt | select(type == "number" and . > 0)' <<< "$run")
jobs=$(gh api --paginate --slurp \
  "repos/$GITHUB_REPOSITORY/actions/runs/$run_id/attempts/$run_attempt/jobs?per_page=100")
jq -e --arg sha "$GITHUB_SHA" '
  [.[].jobs[]] as $jobs
  | ["release-config", "contract-compatibility", "rust-bindings", "rust-bindings-msrv"]
  | all(.[]; . as $name
      | [$jobs[] | select(.name == $name)]
      | length == 1 and all(.[]; .head_sha == $sha
          and .status == "completed" and .conclusion == "success"))
' <<< "$jobs" >/dev/null

# Refuse a result superseded while we waited or read its jobs. This cannot
# prevent a new run after qualification; that needs protected immutable refs.
[[ "$(latest_run)" == "$run_id" ]]
gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id" | jq -e \
  --argjson attempt "$run_attempt" '
    .run_attempt == $attempt and .status == "completed" and .conclusion == "success"
  ' >/dev/null

printf 'Qualified source %s with %s\n' "$GITHUB_SHA" "$ci_url"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  printf '### Contract publication qualification\n\nSource: %s\n\n[Successful CI attempt](%s)\n' \
    "$GITHUB_SHA" "$ci_url" >> "$GITHUB_STEP_SUMMARY"
fi
