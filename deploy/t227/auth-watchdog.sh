#!/bin/sh
# auth-watchdog.sh -- autonomy/t:227 Dispatch C, criterion 5
# (break-glass-independent).
#
# Polls the obsidian-memory auth-service container's health and restarts
# it (and colima, if the docker daemon itself is unreachable) when it's
# down -- BOUNDED, so a wedged/crash-looping container gets a bounded
# number of restart attempts and then a notification, never an infinite
# flap loop. Installed as a launchd agent
# (com.webdesserts.auth-watchdog.plist, StartInterval polling) running as
# user nir -- see BREAK-GLASS.md for install/uninstall/verify.
#
# Design note (Auth Service -- Design Exploration (2026-08-27) SS4): this
# watchdog is the WHOLE break-glass mechanism alongside the manual
# ssh/`Reset` path in BREAK-GLASS.md. There is deliberately NO no-auth
# HTTP admin endpoint -- recovery is either this local, unauthenticated
# (by virtue of running ON umbra, not through the edge) shell-level
# process, or an ssh session onto umbra itself.
#
# Health check order (see health_status() below):
#   1. `docker info` preflight -- if the DAEMON itself is unreachable,
#      that's a colima problem, not an auth-service problem; go straight
#      to the colima branch.
#   2. `docker inspect -f '{{.State.Health.Status}}' <container>` -- the
#      container's own HEALTHCHECK (docker/Dockerfile.auth[.local]: GET
#      /setup, curl -sf, every 30s). Authoritative when it says
#      "healthy" or "unhealthy".
#   3. Anything else (container missing, "starting", "none", inspect
#      itself erroring even though the daemon answered) falls back to an
#      IN-NETWORK probe: `docker exec <container> curl .../validate`,
#      run from INSIDE the auth-service container's own network
#      namespace (sidesteps the host<->VM port-forwarder entirely --
#      auth-service is `expose:`-only, never published to the host; see
#      deploy/t228/verify/verify.sh's header for the same "in-network,
#      not through host ports" reasoning on this machine). A bare
#      unauthenticated GET /validate returning 401 means the process is
#      up and routing requests -- see crates/auth-service/src/
#      validation.rs: `handler` always answers with 401 (never crashes)
#      when no credential is presented.
#
# Bounded restarts: every corrective action this script takes (an
# auth-service restart OR a colima start) is logged as a timestamp in
# STATE_FILE. Before acting, timestamps older than WINDOW_SECONDS are
# purged; if MAX_ACTIONS_PER_WINDOW have already landed inside the
# window, this run does NOT act -- it notifies instead (rate-limited by
# NOTIFY_COOLDOWN_SECONDS via NOTIFIED_FILE, so a still-down service
# doesn't get an observation on every single poll).
#
# Every variable below can be overridden from the environment -- this is
# what lets deploy/t227/test/ exercise the bounded-restart logic against
# a STUB docker/colima without installing anything or touching the real
# stack (see that directory's README).

set -u

DOCKER="${DOCKER:-/opt/homebrew/bin/docker}"
COLIMA="${COLIMA:-/opt/homebrew/bin/colima}"
CURL="${CURL:-/usr/bin/curl}"

COMPOSE_DIR="${COMPOSE_DIR:-/opt/docker/obsidian-memory}"
COMPOSE_FILE_ARGS="-f ${COMPOSE_DIR}/docker-compose.yml -f ${COMPOSE_DIR}/docker-compose.override.yml"
COMPOSE_PROJECT_DIR="${COMPOSE_DIR}"
SERVICE_NAME="${SERVICE_NAME:-auth-service}"
CONTAINER_NAME="${CONTAINER_NAME:-obsidian-memory-auth-service-1}"

LOG_DIR="${LOG_DIR:-/Users/nir/Library/Logs/webdesserts-auth-watchdog}"
LOG_FILE="${LOG_FILE:-${LOG_DIR}/watchdog.log}"
STATE_FILE="${STATE_FILE:-${LOG_DIR}/restart-state}"
NOTIFIED_FILE="${NOTIFIED_FILE:-${LOG_DIR}/last-notified}"

MAX_ACTIONS_PER_WINDOW="${MAX_ACTIONS_PER_WINDOW:-3}"
WINDOW_SECONDS="${WINDOW_SECONDS:-1800}"
NOTIFY_COOLDOWN_SECONDS="${NOTIFY_COOLDOWN_SECONDS:-1800}"

# Board notification target -- primed binds loopback-only and this
# script runs ON umbra (where primed lives), so no auth headers are
# needed for a loopback POST. `POST /observations` (not `POST /feed`) is
# the deliberate choice: an observation's `source` is stored as a plain
# string with NO registry interaction (`resolve_identity` in
# crates/prime/src/routes/observations.rs picks the body `source` field
# or `X-Auth-User`, never calls `data_layer::actors::resolve_or_mint`),
# unlike `POST /feed`'s author (`write_feed_post`'s chokepoint 3, which
# DOES call `resolve_or_mint` and would permanently mint a new registry
# actor for a string like "auth-watchdog@umbra" the very first time this
# watchdog ever notified). A recurring automated notifier must never grow
# the actor registry as a side effect of its own health-checking.
BOARD_URL="${BOARD_URL:-http://127.0.0.1:4600}"
BOARD_PROJECT="${BOARD_PROJECT:-memory}"
NOTIFY_SOURCE="${NOTIFY_SOURCE:-auth-watchdog@$(hostname -s 2>/dev/null || echo umbra)}"

DRY_RUN="${DRY_RUN:-0}"

mkdir -p "$LOG_DIR"

log() {
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "[$ts] $1" | tee -a "$LOG_FILE"
}

now_epoch() {
  date -u +%s
}

# --- Bounded-action state -----------------------------------------------

# Print the number of action timestamps still inside the window, having
# first rewritten STATE_FILE to drop anything older than WINDOW_SECONDS.
actions_in_window() {
  cutoff=$(( $(now_epoch) - WINDOW_SECONDS ))
  if [ -f "$STATE_FILE" ]; then
    tmp="${STATE_FILE}.tmp.$$"
    awk -v cutoff="$cutoff" '$1 >= cutoff' "$STATE_FILE" > "$tmp" 2>/dev/null || : > "$tmp"
    mv "$tmp" "$STATE_FILE"
  else
    : > "$STATE_FILE"
  fi
  wc -l < "$STATE_FILE" | tr -d ' '
}

record_action() {
  echo "$(now_epoch) $1" >> "$STATE_FILE"
}

should_notify_now() {
  if [ ! -f "$NOTIFIED_FILE" ]; then
    return 0
  fi
  last=$(cat "$NOTIFIED_FILE" 2>/dev/null || echo 0)
  case "$last" in
    ''|*[!0-9]*) last=0 ;;
  esac
  elapsed=$(( $(now_epoch) - last ))
  [ "$elapsed" -ge "$NOTIFY_COOLDOWN_SECONDS" ]
}

notify_board() {
  reason="$1"
  if ! should_notify_now; then
    log "NOTIFY suppressed (within ${NOTIFY_COOLDOWN_SECONDS}s cooldown of the last notification): ${reason}"
    return
  fi
  text="auth-watchdog on umbra: ${reason} -- ${MAX_ACTIONS_PER_WINDOW} corrective action(s) already used in the last ${WINDOW_SECONDS}s window; standing down rather than flapping. Manual recovery: deploy/t227/BREAK-GLASS.md."
  body=$(printf '{"text": %s, "context": "", "refs": [], "solution_shaped": false, "source": %s, "project": %s}' \
    "$(json_escape "$text")" "$(json_escape "$NOTIFY_SOURCE")" "$(json_escape "$BOARD_PROJECT")")
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN would POST ${BOARD_URL}/observations: ${body}"
  else
    resp=$("$CURL" -sS -o /dev/null -w '%{http_code}' -X POST "${BOARD_URL}/observations" \
      -H 'Content-Type: application/json' -d "$body" 2>>"$LOG_FILE")
    log "NOTIFY POST ${BOARD_URL}/observations -> ${resp}"
  fi
  date -u +%s > "$NOTIFIED_FILE"
}

# Minimal JSON string escaper -- backslash and double-quote only, which
# is all `reason`/NOTIFY_SOURCE/BOARD_PROJECT ever need (no newlines are
# ever built into `reason` above).
json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | awk '{printf "\"%s\"", $0}'
}

# --- Health check ---------------------------------------------------------

# Prints one of: healthy | unhealthy | unknown-docker-unreachable
health_status() {
  if ! "$DOCKER" info >/dev/null 2>>"$LOG_FILE"; then
    echo "unknown-docker-unreachable"
    return
  fi

  status=$("$DOCKER" inspect -f '{{.State.Health.Status}}' "$CONTAINER_NAME" 2>>"$LOG_FILE")
  case "$status" in
    healthy)
      echo "healthy"
      return
      ;;
    unhealthy)
      echo "unhealthy"
      return
      ;;
  esac

  # Ambiguous (missing container, "starting", "none", inspect error) --
  # fall back to the in-network /validate probe.
  log "docker inspect health status ambiguous ('${status}'); falling back to in-network /validate probe"
  code=$("$DOCKER" exec "$CONTAINER_NAME" "$CURL" -s -o /dev/null -w '%{http_code}' http://localhost:3001/validate 2>>"$LOG_FILE")
  if [ "$code" = "401" ]; then
    echo "healthy"
  else
    log "in-network /validate probe returned '${code:-<none>}' (expected 401)"
    echo "unhealthy"
  fi
}

# --- Corrective actions ----------------------------------------------------

restart_auth_service() {
  count=$(actions_in_window)
  if [ "$count" -ge "$MAX_ACTIONS_PER_WINDOW" ]; then
    log "WOULD restart ${SERVICE_NAME} but ${count}/${MAX_ACTIONS_PER_WINDOW} corrective actions already used in the last ${WINDOW_SECONDS}s -- standing down"
    notify_board "auth-service unhealthy and the restart budget for this window is exhausted"
    return
  fi
  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN would run: ${DOCKER} compose ${COMPOSE_FILE_ARGS} restart ${SERVICE_NAME}"
  else
    if (cd "$COMPOSE_PROJECT_DIR" && "$DOCKER" compose $COMPOSE_FILE_ARGS restart "$SERVICE_NAME" >>"$LOG_FILE" 2>&1); then
      log "restarted ${SERVICE_NAME} (action $((count + 1))/${MAX_ACTIONS_PER_WINDOW} this window)"
    else
      log "restart of ${SERVICE_NAME} FAILED -- see ${LOG_FILE}"
    fi
  fi
  record_action "restart"
}

start_colima_if_stopped() {
  count=$(actions_in_window)
  if [ "$count" -ge "$MAX_ACTIONS_PER_WINDOW" ]; then
    log "docker daemon unreachable but ${count}/${MAX_ACTIONS_PER_WINDOW} corrective actions already used in the last ${WINDOW_SECONDS}s -- standing down"
    notify_board "docker daemon unreachable and the restart budget for this window is exhausted"
    return
  fi

  colima_status=$("$COLIMA" status 2>&1)
  case "$colima_status" in
    *"Running"*|*"running"*)
      log "colima reports running but docker is still unreachable -- not colima's problem, standing down (needs a human)"
      notify_board "docker daemon unreachable even though colima reports running -- needs manual investigation"
      return
      ;;
  esac

  if [ "$DRY_RUN" = "1" ]; then
    log "DRY-RUN would run: ${COLIMA} start"
  else
    if "$COLIMA" start >>"$LOG_FILE" 2>&1; then
      log "started colima (action $((count + 1))/${MAX_ACTIONS_PER_WINDOW} this window)"
    else
      log "colima start FAILED -- see ${LOG_FILE}"
    fi
  fi
  record_action "colima-start"
}

# --- Main -------------------------------------------------------------------

status=$(health_status)
case "$status" in
  healthy)
    log "OK: ${CONTAINER_NAME} healthy"
    ;;
  unhealthy)
    log "UNHEALTHY: ${CONTAINER_NAME}"
    restart_auth_service
    ;;
  unknown-docker-unreachable)
    log "docker daemon unreachable"
    start_colima_if_stopped
    ;;
  *)
    log "unexpected health_status() output: '${status}'"
    ;;
esac
