# t:228 isolated live-wire verification

Proves the Caddy-forwarding half of `additive-uuid-header` (autonomy/t:228)
against real, pinned binaries -- Caddy actually forwards `X-Auth-Actor`,
`X-Auth-User` behavior is untouched, and a client-forged `X-Auth-Actor` is
stripped -- without touching anything under `/opt/docker` or the live
proxy network.

Commit 1 (`crates/auth-service/src/validation.rs`) already fully confirms
the auth-service half at the unit level: 9 tests assert both headers'
presence/absence rules directly. This stack adds the one thing a unit test
can't reach -- Caddy's real `copy_headers` behavior, including the
forgery-safety property the fork resolution in the plan rests on.

## Run it

```sh
cd deploy/t228/verify
./verify.sh
```

Exits non-zero if any assertion fails. Writes a transcript to
`last-run.log` (committed) in addition to stdout.

**Reviewers: re-run this yourself in your own isolated workspace.**
`last-run.log` proves a run happened once; it isn't a substitute for
independently reproducing it, per the standing "reviewers re-sever
independently, never the shared tree" convention.

## Why session-cookie login is seeded from files instead of a real WebAuthn ceremony

Proving the session-cookie path end-to-end over real HTTP normally means a
real WebAuthn ceremony (register a passkey, then authenticate with it).
That needs a virtual authenticator, which isn't available headlessly in
this environment (the design note's own §9 flags this same gap; it also
bit an earlier staging pass). This stack works around it the same way the
crate's own unit tests already do (`storage.create_user(...)`,
`storage.create_session(...)`), but at the storage-file level, since these
probes run against a real container over real HTTP rather than in-process:

- `seed-config/*.json` and `Caddyfile` are injected into their containers
  via `docker cp`, not a bind-mount volume -- this Docker host's VM
  (Colima) only virtiofs-mounts `/opt/docker` and `/Users/nir/notes`;
  `$HOME` (and this worktree under it) isn't mounted, so a host bind
  mount of a file under here fails at container-create time with an OCI
  "not a directory" error even though the file exists and is the right
  type. `docker cp` is a host<->daemon data copy over the Docker API and
  doesn't depend on any VM filesystem mount, so it works regardless.
  `verify.sh` creates the stack without starting it
  (`docker compose create`), copies the files in, then starts it
  (`docker compose start`) -- so each container's first read of its
  config is already the seeded one, no restart needed. See
  `docker-compose.yml`'s header comment and `verify.sh`'s injection step
  for the mechanics.
- `seed-config/users.json` seeds one `StoredUser` directly.
- `seed-config/sessions.json` seeds one `StoredSession` whose
  `session_hash` is `hash_token(<plaintext>)` for a known plaintext
  token (`t228-verify-fixed-session-token-do-not-reuse`), computed by
  replicating `hash_token`'s algorithm (SHA-256 -> `base64::URL_SAFE_NO_PAD`)
  -- confirmed byte-identical against the real crate's exact dependency
  versions (`sha2 = "0.10"`, `base64 = "0.22"`) in a throwaway scratch
  binary before writing this file, not just eyeballed.
- `verify.sh` sends that plaintext token as the `auth_session` cookie.
  `Storage::validate_session` re-hashes it and looks up the seeded
  session, so this exercises the real lookup/hash-compare code path --
  it isn't a mock.
- A wrong seed can't pass vacuously: `validate_session` 401s on any hash
  mismatch and sets no headers, so a seeding bug shows up as assertion 1
  failing outright, not as a false pass.

This workaround only unblocks *this card's* live-wire proof. The real
WebAuthn ceremony itself remains untested anywhere in the crate (design
§9) -- not this card's job to close, flagged in the plan's Noticed section.

## What each assertion proves (and what a regression would look like)

1. **Session-cookie request through the catch-all route** (copies both
   `X-Auth-User` and `X-Auth-Actor`) shows both headers, actor equal to
   the seeded uuid. A regression here (e.g. `try_authorized`'s uuid arg
   silently dropped, or `copy_headers` missing `X-Auth-Actor`) would show
   the actor header absent or wrong.
2. **API-key request** shows `X-Auth-User` present, `X-Auth-Actor`
   absent. A regression here (e.g. `authenticate_bearer` accidentally
   gaining a uuid source) would show the actor header present when it
   must not be.
3. **Forged-header probe** -- the load-bearing proof the fork resolution's
   forgery-safety claim rests on. The client sets its own
   `X-Auth-Actor: 00000000-0000-0000-0000-000000000000` on the *inbound*
   request. 3a (session cookie + forged header) must still show the real
   seeded uuid, not the forged one. 3b (API key + forged header) must show
   `X-Auth-Actor` absent, not the forged value passed through.
   **What a failure here would mean**: under Caddy older than 2.11.2 (pre
   GHSA-7r4p-vjf4-gxv4 fix), `copy_headers` did not unconditionally delete
   a client-supplied copy of a named header before conditionally setting
   it from the auth response -- so 3b would show the forged uuid leaking
   through, and this is exactly the class of bug the probe exists to catch.
   Assert 0 (below) gates this probe's meaning on the real Caddy version.
   **Empirically confirmed, not just asserted in prose**: temporarily
   pointing this stack at `caddy:2.10.2-alpine` (pre-fix) and re-running
   reproduced exactly the predicted failure -- assertion 3b failed with
   the forged uuid `00000000-...-000000000000` showing up in place of
   `<absent>`, while 3a still passed (the real value still wins when
   `/validate` *does* set one; only the uuid-less API-key path leaks the
   forgery). Assert 0 independently caught the same run via the version
   check. Reverted to the pinned `caddy:2.11.4-alpine` before committing;
   this isn't part of the committed stack (it would make `edge-edit-verified`'s
   pin meaningless), just a one-off proof that the probe is a real
   discriminator, not a tautology.
4. **Unauthenticated request** returns 401 (regression sanity check, not
   itself part of the additive-uuid-header criterion).
0. **Scratch Caddy version >= 2.11.2**, checked via `caddy version` inside
   the running container -- not the image tag string -- so the forged-header
   probe's meaning isn't silently invalidated if the pin ever drifts.

## Isolation

- Compose project name `t228-verify` (`docker compose -p t228-verify ...`
  on every invocation, and set as the compose file's default `name:` too)
  so `down -v` can never reach another project's resources.
- Own bridge network (`verify`), never the live `proxy` network.
- **No host port published at all.** `caddy` is reached only from the
  `probe` sibling container (a `sleep infinity` `curlimages/curl`
  container on the same `verify` network) -- `verify.sh` drives every
  HTTP assertion via `docker compose exec probe curl ...`, never through
  the host's TCP stack. This isn't just belt-and-suspenders against the
  live Caddy's `0.0.0.0:80`/`0.0.0.0:443` collision risk: an ephemeral
  loopback publish (`127.0.0.1::80` + `docker compose port`) was tried
  first and found genuinely unreliable on this machine -- the Colima
  VM's host<->VM port-forwarder did not reliably surface newly-created
  containers' ephemeral ports on the macOS host side (confirmed via
  `lsof` on the host showing no listener while `colima ssh -- ss -tlnp`
  showed the port bound inside the VM), while container-to-container
  traffic on the custom bridge network was reliable throughout.
- Teardown (`docker compose -p t228-verify down -v`) runs unconditionally
  via an `EXIT` trap, and `verify.sh` then asserts no `t228-verify`-labeled
  containers or networks remain by name.

## Image pins

- `caddy:2.11.4-alpine` -- matches the live production pin exactly
  (verified present on Docker Hub 2026-09-02, no fallback tag chain).
- `mccutchen/go-httpbin:2.25.0` -- newest confirmed-present versioned tag
  on Docker Hub as of 2026-09-02, pinned by digest:
  `sha256:20739736d4eb8dc1b998dff701f437b8bd62dcc46492bd0d861e89890ca36500`.
  Its `/headers` endpoint reflects request headers as JSON
  (`{"headers": {"Header-Name": ["value"]}}`, Go-canonicalized casing) --
  confirmed empirically against the pinned image before writing
  `verify.sh`'s parsing logic, not assumed from the httpbin API docs.
- `auth-service` is built locally from this branch's working tree via
  `docker/Dockerfile.auth.local` (context = repo root), not pulled from
  ghcr -- this is the local-build staging path, independent of any real
  release tag.
