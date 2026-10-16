#!/bin/bash
# Container entrypoint for the research worker.
# Runs as container root only long enough to set up the firewall, then runs
# Claude Code as the unprivileged "worker" user with every capability dropped.
# Everything the host reads back is written by this script into /job.
set -euo pipefail

JOB=/job
fail() { printf '%s\n' "$1" > "$JOB/error.txt"; exit 3; }

[ -r "$JOB/brief.txt" ] || fail "missing brief"
[[ "${QR_CANARY:-}" =~ ^QR-[A-Za-z0-9]{16,64}$ ]] || fail "missing or malformed canary"
[ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] || fail "missing subscription token"

/opt/qr/init-firewall.sh || fail "firewall setup failed"

run_as_worker() {
  setpriv --reuid=worker --regid=worker --init-groups \
    --inh-caps=-all --bounding-set=-all --no-new-privs \
    env -i HOME=/home/worker PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8 \
      CLAUDE_CODE_OAUTH_TOKEN="$CLAUDE_CODE_OAUTH_TOKEN" \
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_AUTOUPDATER=1 \
      QR_CANARY="$QR_CANARY" QR_LOG=/home/worker/qr/fetch.log \
      QR_MAX_FETCHES="${QR_MAX_FETCHES:-40}" QR_MAX_SEARCHES="${QR_MAX_SEARCHES:-20}" \
      "$@"
}

cd /
run_as_worker sh -c 'mkdir -p "$HOME/qr" "$HOME/empty" && sed "s/{{CANARY}}/$QR_CANARY/" /opt/qr/worker-prompt.md > "$HOME/qr/prompt.md"' \
  || fail "worker setup failed"

# Refuse to run on a Claude Code build that lacks the flags this design relies on.
# (Some flags, such as --append-system-prompt-file and --max-turns, are hidden from
# --help, so only the visible ones are checked here; the image pins a known version.)
HELP=$(run_as_worker claude --help 2>/dev/null || true)
for flag in --restricted --tools --strict-mcp-config --settings --permission-mode; do
  printf '%s' "$HELP" | grep -q -- "$flag" || fail "Claude Code in the image lacks $flag; rebuild the image"
done

BRIEF=$(cat "$JOB/brief.txt")
cd /home/worker/empty
set +e
run_as_worker claude -p --restricted --strict-mcp-config \
  --tools "WebSearch,WebFetch" \
  --permission-mode dontAsk \
  --settings /opt/qr/settings.json \
  --append-system-prompt-file /home/worker/qr/prompt.md \
  --output-format json \
  --max-turns "${QR_MAX_TURNS:-60}" \
  "$BRIEF" > "$JOB/stdout.json" 2> "$JOB/stderr.log"
rc=$?
set -e

run_as_worker cat /home/worker/qr/fetch.log > "$JOB/fetch.log" 2>/dev/null || : > "$JOB/fetch.log"
printf '%s\n' "$rc" > "$JOB/exit_code"
exit 0
