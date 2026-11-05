# autonomy/t:228 -- deploy notes for the orchestrator

Worker builds and stages only. Everything below is orchestrator-executed.

## 1. The Caddyfile edit alone does nothing without a new auth-service image

`Caddyfile.staged` (see `Caddyfile.diff`, `ROLLBACK.md`) only tells Caddy to
*forward* `X-Auth-Actor` if the auth-service response sets it. The
auth-service image running in production today (`ghcr.io/webdesserts/auth-service:0.5.3`,
pinned in `/opt/docker/obsidian-memory/docker-compose.override.yml`) predates
this card's code change and never sets the header. Both pieces need to land
together (or the Caddyfile first is harmless -- it's purely additive and
inert until the image change lands too):

```sh
cd <checkout of obsidian-memory, branch t228, tip b74b714 or later>
docker build -f docker/Dockerfile.auth.local -t auth-service:local-t228 .
```

Then MERGE a new pin into the existing multi-service
`docker-compose.override.yml` -- **never `cp`-clobber it**; the file already
carries `auth-service:` and `memory:` pins side by side with a running
dated-comment history (t:237, t:225, memory/t:3, the v0.5.3 bump), and its
own header already documents this exact discipline ("must MERGE into this
file, never cp-clobber it"). Add a new dated comment block above the
`auth-service:` service, in the same style as the existing entries, then
update the `image:` line:

```yaml
  # autonomy/t:228 (<date>, orchestrator cutover): X-Auth-Actor emission
  # added to /validate (conditional on the credential carrying a known
  # actor uuid; see crates/auth-service/src/validation.rs module docs).
  # X-Auth-User behavior unchanged. Image swapped 0.5.3 -> local-t228 (id
  # <fill in after build>, built from branch t228 @<tip sha>).
  # ROLLBACK: image back to ghcr.io/webdesserts/auth-service:0.5.3 + up -d
  # auth-service.
  auth-service:
    image: auth-service:local-t228
```

Then:

```sh
docker compose -f /opt/docker/obsidian-memory/docker-compose.yml \
                -f /opt/docker/obsidian-memory/docker-compose.override.yml \
                up -d auth-service
```

**Same ORCHESTRATOR RULING as the Caddyfile applies to whatever header
comment gets written for this new pin**: keep the existing file's structure
(dated entry, attribution, WHAT/ROLLBACK), but don't introduce a "STAGED --
NOT ACTIVE"-style opening line describing this file as inactive when the
merge makes it active immediately -- that's precisely the doc-truth defect
flagged below, and a third copy of the same mistake is exactly what this
ruling exists to prevent. (This override file's own original top-of-file
header already carries this defect twice over -- see Noticed below -- so it
would be worth cleaning up while already touching the file, though that's a
separate, larger edit than this card's own dated-comment addition and not
required to land t:228.)

## 2. Out of scope: a real ghcr tag+push

Nothing in this card publishes a new `auth-service` release image to ghcr.
The image swap above uses a locally-built image (`auth-service:local-t228`),
matching the `docker/Dockerfile.auth.local` local-build convention already
used for every prior staged cutover in this file (local-h2, local-t237). A
real semver tag + ghcr push is **Michael's call only** -- `.github/workflows/docker.yml`
triggers on a real git tag, and nothing here creates one.

## 3. Noticed, not fixed by this card

The live `/opt/docker/caddy/Caddyfile` currently carries a stale "STAGED
Caddyfile -- NOT ACTIVE" header (written by worker-t237) describing itself
as inactive while it has been the active file since the t:237 cutover --
none of the routes that header claims to remove are present. This card's
own `Caddyfile.staged` replaces that entire header block wholesale with a
new one for t:228 (see `Caddyfile.diff`), so **activating this card's
package incidentally fixes that specific defect** -- worth noting on the
card rather than treating as a separate cleanup.

The same failure pattern exists a layer up, and this card does NOT touch
it: `/opt/docker/obsidian-memory/docker-compose.override.yml`'s own
*original* top-of-file header (from the H2/`auth-session-validate` era,
lines 1-15) still opens "STAGED override -- NOT ACTIVE" while the file has
been active since that cutover -- a later comment block (the "memory/t:3"
entry) even calls this out explicitly ("NB: despite the header above, this
FILE IS ACTIVE"). This card's new dated-comment addition (point 1 above)
doesn't touch or replace that original header, so the defect survives this
cutover too. Both instances are the same doc-truth defect class the design
doc's own §9 already flagged; a proper fix means rewriting that file's
original header, which is a larger, separate edit than what point 1 above
needs -- flagged here, not undertaken as part of t:228.
