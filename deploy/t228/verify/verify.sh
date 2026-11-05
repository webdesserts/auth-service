#!/usr/bin/env bash
# Isolated live-wire verification for autonomy/t:228's additive-uuid-header
# criterion. See README.md for the seeding rationale and what each probe
# would show under the OLD (pre-t228) or UNPATCHED-Caddy behavior -- this
# script only says what it proves, not just what it ran.
#
# Usage: cd deploy/t228/verify && ./verify.sh
# Exits non-zero if any assertion fails. Transcript written to last-run.log
# (committed) as well as stdout.
#
# Reviewers: re-run this yourself in your own isolated workspace rather
# than trusting the committed last-run.log as attestation -- per the
# standing "reviewers re-sever independently, never the shared tree"
# convention, a log file only proves a run happened once, not that it
# reproduces.
set -uo pipefail

cd "$(dirname "$0")"

PROJECT="t228-verify"
LOG_FILE="last-run.log"

SESSION_TOKEN="t228-verify-fixed-session-token-do-not-reuse"
SEEDED_UUID="deffe93e-62db-4479-a837-deaf4d3ab697"
API_KEY="t228-verify-api-key-do-not-reuse"
FORGED_UUID="00000000-0000-0000-0000-000000000000"

FAILURES=0

log() {
  echo "$@" | tee -a "$LOG_FILE"
}

pass() {
  log "PASS: $1"
}

fail() {
  log "FAIL: $1"
  FAILURES=$((FAILURES + 1))
}

cleanup() {
  log "--- Tearing down (docker compose -p $PROJECT down -v) ---"
  docker compose -p "$PROJECT" down -v --remove-orphans >>"$LOG_FILE" 2>&1

  local leftover_containers leftover_networks
  leftover_containers=$(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" -q)
  leftover_networks=$(docker network ls --filter "name=$PROJECT" -q)

  if [ -n "$leftover_containers" ]; then
    fail "leftover containers after teardown: $leftover_containers"
  else
    pass "no leftover $PROJECT containers after teardown"
  fi
  if [ -n "$leftover_networks" ]; then
    fail "leftover networks after teardown: $leftover_networks"
  else
    pass "no leftover $PROJECT networks after teardown"
  fi

  log "=== t228 verify.sh finished: $FAILURES failure(s) ==="
  exit "$FAILURES"
}
trap cleanup EXIT

: > "$LOG_FILE"
log "=== t228 verify.sh run: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

log "--- Creating stack without starting it (docker compose -p $PROJECT create --build) ---"
# Created-but-not-started, so the Caddyfile and seed-config can be
# injected via `docker cp` before each container's FIRST start -- no
# restart needed. (An earlier version of this script used up + cp +
# restart; on this machine that made caddy's container lose its
# reachability, diagnosed as a Colima host<->VM port-forwarder gap, see
# docker-compose.yml's header. `probe`-based reach-in sidesteps host
# port-forwarding entirely, but create-then-start is also simply
# fewer moving parts, so it's kept regardless.)
if ! docker compose -p "$PROJECT" create --build >>"$LOG_FILE" 2>&1; then
  fail "docker compose create failed -- see $LOG_FILE"
  exit 1
fi

log "--- Injecting Caddyfile + seed-config via docker cp (see docker-compose.yml's"
log "    header: this Docker host's VM doesn't mount this worktree, so a host bind"
log "    mount would fail here even though it works for /opt/docker) ---"
AUTH_CID=$(docker compose -p "$PROJECT" ps -aq auth-service)
CADDY_CID=$(docker compose -p "$PROJECT" ps -aq caddy)
if [ -z "$AUTH_CID" ] || [ -z "$CADDY_CID" ]; then
  fail "could not resolve auth-service/caddy container ids after create"
  exit 1
fi
docker cp seed-config/config.json "${AUTH_CID}:/config/config.json" >>"$LOG_FILE" 2>&1
docker cp seed-config/users.json "${AUTH_CID}:/config/users.json" >>"$LOG_FILE" 2>&1
docker cp seed-config/sessions.json "${AUTH_CID}:/config/sessions.json" >>"$LOG_FILE" 2>&1
docker cp Caddyfile "${CADDY_CID}:/etc/caddy/Caddyfile" >>"$LOG_FILE" 2>&1

log "--- Starting stack (docker compose -p $PROJECT start) ---"
if ! docker compose -p "$PROJECT" start >>"$LOG_FILE" 2>&1; then
  fail "docker compose start failed -- see $LOG_FILE"
  exit 1
fi

log "--- Waiting for auth-service healthcheck ---"
status="starting"
for _ in $(seq 1 60); do
  status=$(docker inspect -f '{{.State.Health.Status}}' "$AUTH_CID" 2>/dev/null || echo "starting")
  [ "$status" = "healthy" ] && break
  sleep 1
done
if [ "$status" = "healthy" ]; then
  pass "auth-service became healthy"
else
  fail "auth-service never became healthy (last status: $status)"
fi

# Every HTTP probe below runs FROM the `probe` sibling container, on the
# scratch network, never through the host's TCP stack (see
# docker-compose.yml's header for why: an ephemeral host-port publish
# was tried first and found unreliable on this machine).
probe_curl() {
  docker compose -p "$PROJECT" exec -T probe curl -s "$@"
}

log "--- Waiting for caddy to accept connections (from the probe container) ---"
ready=""
for _ in $(seq 1 30); do
  if probe_curl -o /dev/null -w '%{http_code}' http://caddy/headers 2>/dev/null | grep -qE '^[0-9]{3}$'; then
    ready=1
    break
  fi
  sleep 1
done
if [ -n "$ready" ]; then
  pass "caddy is accepting connections from the probe container"
else
  fail "caddy never accepted a connection from the probe container"
fi

log ""
log "--- Assert 0: scratch Caddy version >= 2.11.2 ---"
log "(GHSA-7r4p-vjf4-gxv4's unconditional-delete-before-conditional-set fix, without"
log " which the forged-header assertions below would NOT discriminate anything --"
log " a forged header would pass through unstripped.)"
CADDY_VERSION_LINE=$(docker compose -p "$PROJECT" exec -T caddy caddy version 2>&1)
log "caddy version output: $CADDY_VERSION_LINE"
CADDY_VERSION=$(printf '%s\n' "$CADDY_VERSION_LINE" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed 's/^v//')

version_ge() {
  # $1 >= $2, both "major.minor.patch"
  local a_major a_minor a_patch b_major b_minor b_patch
  IFS='.' read -r a_major a_minor a_patch <<<"$1"
  IFS='.' read -r b_major b_minor b_patch <<<"$2"
  [ "$a_major" -gt "$b_major" ] && return 0
  [ "$a_major" -lt "$b_major" ] && return 1
  [ "$a_minor" -gt "$b_minor" ] && return 0
  [ "$a_minor" -lt "$b_minor" ] && return 1
  [ "$a_patch" -ge "$b_patch" ]
}

if [ -n "$CADDY_VERSION" ] && version_ge "$CADDY_VERSION" "2.11.2"; then
  pass "scratch Caddy version $CADDY_VERSION >= 2.11.2 -- forged-header probe below is meaningful"
else
  fail "scratch Caddy version '$CADDY_VERSION' < 2.11.2 -- forged-header probe below would NOT be a valid discriminator, its results are meaningless on this run"
fi

# Extract a header's first value from a go-httpbin /headers JSON response.
# Prints the value, or nothing (empty string) if the header is absent.
header_value() {
  local json="$1" name="$2"
  printf '%s' "$json" | jq -r --arg h "$name" '.headers[$h][0] // empty'
}

log ""
log "--- Assert 1: session-cookie request through the catch-all route (copies X-Auth-User + X-Auth-Actor) shows BOTH headers, actor = seeded uuid ---"
RESP1=$(probe_curl -H "Cookie: auth_session=${SESSION_TOKEN}" http://caddy/headers)
USER1=$(header_value "$RESP1" "X-Auth-User")
ACTOR1=$(header_value "$RESP1" "X-Auth-Actor")
log "X-Auth-User=$USER1 X-Auth-Actor=$ACTOR1"
if [ "$USER1" = "t228-verify-user" ]; then
  pass "session-cookie request shows X-Auth-User=t228-verify-user"
else
  fail "session-cookie request X-Auth-User expected 't228-verify-user', got '$USER1'"
fi
if [ "$ACTOR1" = "$SEEDED_UUID" ]; then
  pass "session-cookie request shows X-Auth-Actor=$SEEDED_UUID"
else
  fail "session-cookie request X-Auth-Actor expected '$SEEDED_UUID', got '$ACTOR1'"
fi

log ""
log "--- Assert 2: API-key request shows X-Auth-User present, X-Auth-Actor ABSENT ---"
RESP2=$(probe_curl -H "Authorization: Bearer ${API_KEY}" http://caddy/headers)
USER2=$(header_value "$RESP2" "X-Auth-User")
ACTOR2=$(header_value "$RESP2" "X-Auth-Actor")
log "X-Auth-User=$USER2 X-Auth-Actor=${ACTOR2:-<absent>}"
if [ "$USER2" = "t228-verify-bot" ]; then
  pass "API-key request shows X-Auth-User=t228-verify-bot"
else
  fail "API-key request X-Auth-User expected 't228-verify-bot', got '$USER2'"
fi
if [ -z "$ACTOR2" ]; then
  pass "API-key request omits X-Auth-Actor"
else
  fail "API-key request X-Auth-Actor expected absent, got '$ACTOR2'"
fi

log ""
log "--- Assert 3: forged-header probe (the Caddy-level defeat-check) ---"
log "Client sends its own X-Auth-Actor: $FORGED_UUID on the inbound request."
log "Under UNPATCHED Caddy (<2.11.2), case 3a would show the FORGED uuid"
log "(not the real seeded one), and case 3b would show the forged uuid"
log "instead of absent -- that's what 'not a discriminator' would look like."
RESP3A=$(probe_curl -H "Cookie: auth_session=${SESSION_TOKEN}" -H "X-Auth-Actor: ${FORGED_UUID}" http://caddy/headers)
ACTOR3A=$(header_value "$RESP3A" "X-Auth-Actor")
log "3a (session, forged actor) X-Auth-Actor=$ACTOR3A"
if [ "$ACTOR3A" = "$SEEDED_UUID" ]; then
  pass "3a: real seeded uuid wins over the client's forged X-Auth-Actor"
else
  fail "3a: expected the real seeded uuid '$SEEDED_UUID', got '$ACTOR3A' (forged value may have leaked through)"
fi

RESP3B=$(probe_curl -H "Authorization: Bearer ${API_KEY}" -H "X-Auth-Actor: ${FORGED_UUID}" http://caddy/headers)
ACTOR3B=$(header_value "$RESP3B" "X-Auth-Actor")
log "3b (api-key, forged actor) X-Auth-Actor=${ACTOR3B:-<absent>}"
if [ -z "$ACTOR3B" ]; then
  pass "3b: client's forged X-Auth-Actor is stripped, not passed through"
else
  fail "3b: expected X-Auth-Actor absent, but the forged value '$ACTOR3B' was passed through"
fi

log ""
log "--- Assert 4: unauthenticated request -> 401, no auth headers copied ---"
RESP4_CODE=$(probe_curl -o /dev/null -w '%{http_code}' http://caddy/headers)
log "status=$RESP4_CODE"
if [ "$RESP4_CODE" = "401" ]; then
  pass "unauthenticated request returns 401"
else
  fail "unauthenticated request expected 401, got $RESP4_CODE"
fi
# A 401 body isn't the echo upstream's JSON at all (forward_auth
# short-circuits before reverse_proxy on a non-2xx /validate response),
# so there's nothing to parse for header presence -- the 401 status
# itself is the regression check.

log ""
log "=== Assertions complete: $FAILURES failure(s) before teardown ==="
# cleanup() (the EXIT trap) runs next, tears the stack down unconditionally,
# and exits with the final failure count including its own teardown checks.
