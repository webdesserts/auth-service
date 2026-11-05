# autonomy/t:227 Dispatch C -- orchestrator notes

Worker (Dispatch C) builds and stages only. Everything below is
orchestrator-executed, mirroring `deploy/t228/DEPLOY.md`'s own opening
line. This file is the install/before-state/rollback checklist; see
`BREAK-GLASS.md` for the standing operational runbook (the artifact this
card leaves behind for future incidents, not just for this cutover).

Two independent pieces, neither depends on the other:

- **C1** `../../scripts/guest-session-e2e.sh` -- a script, not a live
  service. Nothing to "install"; it needs Dispatch A's `/login/key` route
  live and a seeded guest (rhea) to run against (plan's Orchestrator-only
  live step 1).
- **C2** the watchdog (`auth-watchdog.sh` + the plist) -- a LaunchAgent,
  genuinely installed.

## C1: running the guest E2E script

**Prerequisite: Dispatch A (`crates/auth-service`) deployed** with
`/login/key` live, AND a seeded guest (plan step 1: `create-guest --handle
rhea` -> uuid, `issue-key` -> key, `data_layer::actors::adopt(...)` on the
agent-task side). The three constants at the top of
`guest-session-e2e.sh` (`LOGIN_KEY_FIELD`, `LOGIN_TOKEN_FIELD`,
`SESSION_COOKIE_NAME`) were written from the plan's PROSE description of
Dispatch A2, since Dispatch A hadn't landed when this script was written
-- **reconcile them against Dispatch A's actual landed request/response
structs before the first real run** (see the script's own header comment
for exactly what to check).

```sh
# Before-state: none to record -- this step only reads/writes a feed
# entry attributed to the guest, it doesn't mutate any config.
GUEST_API_KEY=<rhea's issued key> ./scripts/guest-session-e2e.sh
```

Exit code 0 with every step printing `PASS` is the criterion-2 evidence.
Run `--dry-run` first (no key needed) to sanity-check the request shapes
without touching the live edge at all.

**Rollback:** N/A -- this script only ever performs one `POST /feed` per
run (a real, visible feed entry attributed to the guest; harmless, and
arguably a useful visible proof left on the board) plus reads. If a clean
board is wanted, delete the posted entry the normal way (there's no
special guest-specific cleanup).

## C2: installing the watchdog

### Before-state (record before touching anything)

```sh
ssh umbra
launchctl list | grep com.webdesserts.auth-watchdog   # expect: no output (not yet installed)
ls /Users/nir/Library/LaunchAgents/ | grep auth-watchdog   # expect: no output
docker ps --filter name=obsidian-memory-auth-service-1   # record current Up/health state
```

### Install

See `BREAK-GLASS.md` SS1 "Install" for the exact copy/chmod/bootstrap
commands -- not duplicated here to avoid the two files drifting apart.

### Verify

See `BREAK-GLASS.md` SS1 "Verify" -- **the load-bearing check stops the
auth container for real** (`docker stop obsidian-memory-auth-service-1`)
and confirms the watchdog brings it back within one `StartInterval` tick.
This is the actual proof of criterion 5, not a simulation; the fully
offline proof of the BOUNDED-restart *logic specifically* (never touching
docker/colima at all) already lives at `test/README.md` and was run by
the worker before this file was written -- see the worker's report for
that transcript. The live verify step above is what proves the watchdog
is correctly wired to the REAL docker/compose commands, which the offline
stub test deliberately does not exercise.

### Rollback

```sh
launchctl bootout gui/$(id -u)/com.webdesserts.auth-watchdog
rm /Users/nir/Library/LaunchAgents/com.webdesserts.auth-watchdog.plist
rm /opt/docker/obsidian-memory/auth-watchdog.sh
# logs under /Users/nir/Library/Logs/webdesserts-auth-watchdog/ are
# harmless to leave in place; remove if a clean rollback is wanted.
```

Nothing about this rollback touches the auth-service container, its
volume, or any compose file -- the watchdog is purely additive
(monitoring + a bounded `restart`/`start`), so removing it just stops the
automatic recovery, it doesn't undo anything the watchdog itself already
did while installed (a `restart`/`start` it already ran isn't reversible,
nor does it need to be -- both are idempotent, non-destructive
operations).

## What could go wrong, and how you'd notice

- **`docker exec ... curl .../validate` fallback probe fails even though
  the container is actually fine**: would show up as a spurious restart
  in `watchdog.log` ("in-network /validate probe returned ..."). Check
  that `curl` is actually present in the running container (it is, per
  `docker/Dockerfile.auth[.local]`'s own `apt-get install ... curl`) and
  that `/validate` genuinely still 401s with no credential (see
  `crates/auth-service/src/validation.rs`'s `handler` -- this is a stable
  invariant, not something this card changes).
- **Bounded-restart budget exhausted during a real, prolonged outage**:
  the watchdog stands down and posts an observation (`project: memory`,
  `source: auth-watchdog@<host>`) rather than restart-looping forever --
  this is intentional (see `auth-watchdog.sh`'s header comment), not a
  bug; the manual ssh path (`BREAK-GLASS.md` SS2) is exactly what that
  notification is pointing at.
- **The plist's hardcoded install path
  (`/opt/docker/obsidian-memory/auth-watchdog.sh`) drifts from the
  script's actual location**: `launchctl list` would still show the
  agent loaded, but every tick would fail silently into
  `launchd-stderr.log` ("No such file or directory") with no
  `watchdog.log` entries at all -- a genuinely silent failure mode, worth
  checking `launchd-stderr.log` specifically (not just `watchdog.log`) if
  the agent looks installed but nothing is happening.
