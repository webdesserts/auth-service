#!/bin/sh
# run-bounded-restart-test.sh -- exercises auth-watchdog.sh's bounded
# restart logic against stub-docker-unhealthy, entirely offline (DRY_RUN=1,
# nothing installed, nothing on the live umbra stack touched).
#
# Demonstrates:
#   1. The first MAX_ACTIONS_PER_WINDOW runs each "restart" (DRY-RUN log).
#   2. The (N+1)th run within the same window notifies instead of
#      restarting.
#   3. Backdating the state file past WINDOW_SECONDS (simulating elapsed
#      time without a real sleep) resets the window -- the next run
#      restarts again.
#
# Usage: sh deploy/t227/test/run-bounded-restart-test.sh

set -eu

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
WATCHDOG="${SELF_DIR}/../auth-watchdog.sh"
STUB_DOCKER="${SELF_DIR}/stub-docker-unhealthy"

SCRATCH_DIR="$(mktemp -d)"
trap 'rm -rf "$SCRATCH_DIR"' EXIT

export DOCKER="$STUB_DOCKER"
export COLIMA="/bin/true"   # unused in this scenario, never reached
export CURL="/usr/bin/curl"
export CONTAINER_NAME="stub-container"
export LOG_DIR="$SCRATCH_DIR"
export LOG_FILE="${SCRATCH_DIR}/watchdog.log"
export STATE_FILE="${SCRATCH_DIR}/restart-state"
export NOTIFIED_FILE="${SCRATCH_DIR}/last-notified"
export MAX_ACTIONS_PER_WINDOW=2
export WINDOW_SECONDS=5
export NOTIFY_COOLDOWN_SECONDS=0
export DRY_RUN=1

echo "=== Run 1 (expect: restart 1/2) ==="
sh "$WATCHDOG"
echo ""
echo "=== Run 2 (expect: restart 2/2) ==="
sh "$WATCHDOG"
echo ""
echo "=== Run 3, still inside the ${WINDOW_SECONDS}s window (expect: budget exhausted -> NOTIFY, no restart) ==="
sh "$WATCHDOG"
echo ""
echo "--- state file before backdating ---"
cat "$STATE_FILE"
echo ""

echo "=== Backdating state-file timestamps by $((WINDOW_SECONDS + 100))s to simulate the window elapsing (no real sleep) ==="
awk -v shift="$((WINDOW_SECONDS + 100))" '{ $1 = $1 - shift; print }' "$STATE_FILE" > "${STATE_FILE}.backdated"
mv "${STATE_FILE}.backdated" "$STATE_FILE"
echo "--- state file after backdating ---"
cat "$STATE_FILE"
echo ""

echo "=== Run 4, new window (expect: restart 1/2 again -- the old entries are now outside the window) ==="
sh "$WATCHDOG"

echo ""
echo "=== Full watchdog.log ==="
cat "$LOG_FILE"

echo ""
echo "=== Assertions ==="
FAIL=0
# Restart is only logged as "restarted" when DRY_RUN != 1; this test
# runs with DRY_RUN=1 throughout, so it checks for the DRY-RUN phrasing.
restart_dryrun_count=$(grep -c "DRY-RUN would run: .*restart auth-service" "$LOG_FILE" || true)
notify_count=$(grep -c "NOTIFY:\|DRY-RUN would POST.*observations" "$LOG_FILE" || true)
budget_exhausted_count=$(grep -c "restart budget for this window is exhausted" "$LOG_FILE" || true)

echo "restart (DRY-RUN) log lines: $restart_dryrun_count (expect 3: run1, run2, run4)"
echo "notify (DRY-RUN POST) log lines: $notify_count (expect 1: run3 only)"
echo "'budget exhausted' log lines: $budget_exhausted_count (expect 1: run3 only)"

if [ "$restart_dryrun_count" -eq 3 ]; then
  echo "PASS: 3 restart attempts logged (run1, run2, run4 after window reset)"
else
  echo "FAIL: expected 3 restart attempts, got $restart_dryrun_count"
  FAIL=1
fi

if [ "$notify_count" -eq 1 ]; then
  echo "PASS: exactly 1 notify fired (run3, when the budget was exhausted)"
else
  echo "FAIL: expected exactly 1 notify, got $notify_count"
  FAIL=1
fi

if [ "$budget_exhausted_count" -eq 1 ]; then
  echo "PASS: exactly 1 'budget exhausted' standing-down log line (run3)"
else
  echo "FAIL: expected exactly 1 'budget exhausted' line, got $budget_exhausted_count"
  FAIL=1
fi

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "=== ALL ASSERTIONS PASSED ==="
else
  echo "=== ASSERTIONS FAILED ==="
fi
exit "$FAIL"
