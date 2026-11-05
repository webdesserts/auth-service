# Break-glass: recovering the auth service without auth

autonomy/t:227, criterion `break-glass-independent`: *"A documented
recovery path restarts the auth service without requiring auth."*

**There is deliberately NO no-auth HTTP endpoint.** Auth Service --
Design Exploration (2026-08-27) SS4 rules this out explicitly: an
unauthenticated admin route on the same service that's supposed to be
the trust boundary is exactly the failure mode this design avoids.
Recovery instead has two independent legs, neither of which goes through
`https://umbra.computer/*` or needs a valid session/key at all:

1. **The watchdog** (`auth-watchdog.plist` + `auth-watchdog.sh`,
   automatic, bounded) -- the first line of defense, catches most
   crashes/hangs without a human.
2. **The manual ssh path** (below) -- what a human does when the
   watchdog itself has exhausted its bounded restart budget, or when
   docker/colima itself needs attention the watchdog can't take (it only
   ever starts a stopped colima; it never runs `colima delete`/rebuilds
   it, and it never touches Docker volumes).

Both legs work by virtue of running directly ON umbra (as user `nir`, at
the shell or via `ssh umbra`) -- **not** by presenting any credential to
the auth service itself. That's the whole mechanism: recovery lives
below the layer auth protects, the same way recovering a locked house
means finding the physical spare key, not knocking louder on the
front door.

## 1. The watchdog

### Install

```sh
ssh umbra
sudo -u nir true   # (no-op; documents that every step below runs as nir, not root)

mkdir -p /opt/docker/obsidian-memory
cp <this worktree>/deploy/t227/auth-watchdog.sh /opt/docker/obsidian-memory/auth-watchdog.sh
chmod +x /opt/docker/obsidian-memory/auth-watchdog.sh

mkdir -p /Users/nir/Library/Logs/webdesserts-auth-watchdog
cp <this worktree>/deploy/t227/com.webdesserts.auth-watchdog.plist \
   /Users/nir/Library/LaunchAgents/com.webdesserts.auth-watchdog.plist

launchctl bootstrap gui/$(id -u) /Users/nir/Library/LaunchAgents/com.webdesserts.auth-watchdog.plist
launchctl list | grep com.webdesserts.auth-watchdog   # expect a PID (or "-" between ticks) and exit status 0
```

`/opt/docker/obsidian-memory/auth-watchdog.sh` is the chosen canonical
install path -- alongside `docker-compose.yml`/`docker-compose.override.yml`,
the same "ops scripts live next to the service they manage" convention
this directory already uses, not a new location. The plist's
`ProgramArguments` hardcodes this exact path (see the plist's own
comment) -- if the install path ever changes, the plist must change with
it.

### Verify (with the service actually stopped -- this is the load-bearing check)

```sh
# Before-state: confirm the watchdog is running and quiet with a healthy
# service.
tail -5 /Users/nir/Library/Logs/webdesserts-auth-watchdog/watchdog.log
# expect: "OK: obsidian-memory-auth-service-1 healthy" on the most recent line(s)

# Now actually stop the service (this IS the break-glass scenario, not a
# simulation -- the whole point of this verification step).
docker stop obsidian-memory-auth-service-1

# Wait for the watchdog's next StartInterval tick (up to 60s), then:
tail -5 /Users/nir/Library/Logs/webdesserts-auth-watchdog/watchdog.log
# expect: "UNHEALTHY: obsidian-memory-auth-service-1" followed by a
# restart line, and the container should be back:
docker ps --filter name=obsidian-memory-auth-service-1
# expect: Up, (healthy) once the container's own 5s-start-period +
# 30s-interval healthcheck has had a chance to run again.
```

If the container doesn't come back within ~2 minutes, check
`watchdog.log` for a "budget exhausted" / NOTIFY line (the bounded-restart
guard, see `auth-watchdog.sh`'s own header comment and
`deploy/t227/test/README.md` for a fully offline proof of that logic),
then fall back to the manual path below.

### Uninstall

```sh
launchctl bootout gui/$(id -u)/com.webdesserts.auth-watchdog
rm /Users/nir/Library/LaunchAgents/com.webdesserts.auth-watchdog.plist
```

(Leaves `/opt/docker/obsidian-memory/auth-watchdog.sh` and the log
directory in place -- they're inert without the LaunchAgent; delete by
hand if a full removal is wanted.)

## 2. The manual ssh path

For when the watchdog's own restart budget is exhausted, or the watchdog
itself isn't installed/running, or docker/colima needs more than a start:

```sh
ssh umbra

# a) Is the docker daemon (colima) even up?
colima status
# if not:
colima start

# b) Is the container up?
docker ps -a --filter name=obsidian-memory-auth-service-1

# c) Simple restart (no config change, matches deploy/t228/ROLLBACK.md's
#    own "prefer docker restart over reload" convention for this kind of
#    recovery):
docker restart obsidian-memory-auth-service-1

# d) If (c) doesn't help -- e.g. the compose-level environment/volumes
#    need re-evaluating, or the container was removed entirely -- recreate
#    it from compose:
cd /opt/docker/obsidian-memory
docker compose -f docker-compose.yml -f docker-compose.override.yml up -d auth-service

# e) Tail logs to see what's actually wrong:
docker logs --tail 100 obsidian-memory-auth-service-1
```

### The `Reset` subcommand -- what it destroys (read this before running it)

`auth-service` ships a `reset` CLI subcommand
(`crates/auth-service/src/main.rs`, `Command::Reset` ->
`Storage::reset_auth`), for when the auth state itself, not just the
process, is wedged (e.g. a corrupted `sessions.json`/`passkeys.json`
blocking every login including Michael's own). Run it against the live
container:

```sh
docker exec obsidian-memory-auth-service-1 auth-service reset
```

(No `--config-path` needed -- the container's own `AUTH_CONFIG_PATH=/config`
environment variable, set in `docker/docker-compose.yml`, is inherited by
`docker exec`.)

**Exactly what this clears** (verified against `Storage::reset_auth`,
`crates/auth-service/src/storage.rs`):

- Every registered user/passkey (`users.json`, `passkeys.json`) -- **this
  deletes Michael's own passkey registration.** He would need to visit
  `/auth/setup` again and re-register from scratch.
- Every active session (`sessions.json`) -- every browser currently
  logged in is signed out immediately.
- **Every guest principal** -- `users.json` holds guests too (as of
  Dispatch A, `create-guest`), so `rhea` is deleted along with Michael's
  own record.
- **Every runtime API key** (`api_keys.json`) -- `reset_auth` now clears
  the key store as well (re-verified 2026-09-03 against Dispatch A's
  landed `Storage::reset_auth`, obsidian-memory `dd6e86b`). That is
  rhea's key AND the migrated `OpenCode` entry.

**Exactly what this does NOT touch** (same function): `config.json`
(the legacy API-key file) is untouched, so the `OpenCode` bearer key is
re-seeded into `api_keys.json` on the next service startup
(`migrate_config_keys`) and keeps working after one restart.
`/config/clients.json` and `/config/tokens.json` (OAuth-era leftovers,
out of scope for this card) are also untouched.

**Blast radius, stated plainly:** a `reset` destroys the guest floor
(criterion 2). After one, re-run `create-guest --handle rhea` and
`issue-key --user rhea --name rhea`, hand the new key over
out-of-band, and note that the re-created guest gets a NEW uuid: the
prime registry's `agent:rhea` entry still points at the old one, and
`seed_actor` refuses to adopt a different uuid onto an existing handle,
so the registry side needs a deliberate re-link (`rename`/alias) rather
than a re-seed. Prefer restarting the service (section 1) over
resetting it; reset is for corrupted auth state, not for a stuck
container.

## 3. The colima path

Docker itself lives inside a Colima-managed Linux VM (`com.github.colima`
LaunchAgent, per `~/Device.md`) -- without it, every container (auth,
memory, caddy, sync) is down, not just auth. `colima status` /
`colima start` (step (a) above) covers the common case. If colima itself
won't start:

```sh
colima list          # sanity-check there's exactly one profile, "default"
colima start --verbose 2>&1 | tail -50   # look for the actual failure
```

A colima VM that won't come back at all (corrupted VM state, not just
"stopped") is out of scope for this runbook -- that's a Colima-level
incident, not an auth-service one, and Device.md doesn't document a
tested recovery path for it either. Flag it rather than improvising one
here.

## 4. Volumes and backups

`auth-service`'s persistent state (`/config` inside the container --
`users.json`, `passkeys.json`, `sessions.json`, `config.json`, the
OAuth-era leftovers, and once Dispatch A lands the new key/guest
storage) lives in the **named docker volume** `auth-config`
(`docker/docker-compose.yml`'s `volumes:` section -- no `driver_opts`, so
it's a plain docker-managed volume, unlike the `notes:` volume which is a
host bind mount). Docker's default naming prefixes it with the compose
project name (this compose file sets no explicit `name:`, so the project
name is the directory basename, `obsidian-memory`) -- expect
`obsidian-memory_auth-config`; **confirm the exact name with
`docker volume ls | grep auth-config` before backing it up or restoring
into it** rather than trusting this document's guess blindly.

```sh
# Backup (read-only, safe to run any time):
docker run --rm \
  -v obsidian-memory_auth-config:/config:ro \
  -v /Users/nir/backups:/backup \
  alpine tar czf /backup/auth-config-backup-$(date -u +%Y%m%dT%H%M%SZ).tar.gz -C /config .

# Restore (DESTRUCTIVE -- stop the container first, confirm before-state,
# never run against a volume you haven't already backed up):
docker stop obsidian-memory-auth-service-1
docker run --rm \
  -v obsidian-memory_auth-config:/config \
  -v /Users/nir/backups:/backup \
  alpine sh -c "cd /config && rm -rf ./* && tar xzf /backup/<chosen-backup>.tar.gz -C /config"
docker start obsidian-memory-auth-service-1
```

No backup schedule is set up as part of this card -- criterion 5 only
asks for a documented recovery path, not a backup cadence. Worth its own
follow-up if the auth volume's actual failure/corruption rate ever
warrants one (flagged, not undertaken here).

## What this deliberately does NOT do

- No no-auth HTTP route anywhere (design SS4). Every recovery mechanism
  above requires either an ssh session onto umbra (the same trust umbra
  itself already carries -- see `~/Device.md`) or the watchdog's own
  local, unauthenticated-by-virtue-of-being-local process.
- The watchdog never touches `/opt/docker/caddy` -- a Caddy-level outage
  is a separate incident with its own (pre-existing, undocumented-here)
  recovery path.
- The watchdog never runs `docker compose down`/`colima delete`/anything
  that destroys state -- only `restart` (auth-service) and `start`
  (colima), both idempotent and non-destructive.
