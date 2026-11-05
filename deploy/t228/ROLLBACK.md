# autonomy/t:228 -- Caddyfile activation and rollback

Orchestrator-executed only. The worker builds and stages; nothing here
touches the live file.

## Activate

Run from `/opt/docker/caddy` on umbra:

```sh
md5 -q Caddyfile   # record before-state; expect 60b00c0d38be5fafddac28a233f4ec11
                    # (matches the live file as of 2026-09-02, the pickup time
                    # for this card -- re-verify at activation time, it may have
                    # drifted if another card touched it first)
cp Caddyfile Caddyfile.bak-2026-09-02-t228-caddy
cp <worktree>/deploy/t228/Caddyfile.staged Caddyfile
docker restart caddy-caddy-1   # prefer over `caddy reload` -- Device.md's virtiofs bind-mount footgun
md5 -q Caddyfile
docker exec caddy-caddy-1 md5sum /etc/caddy/Caddyfile
# the two md5 outputs above MUST match -- if they don't, the container is
# still serving a stale/truncated view of the file (the documented
# virtiofs footgun); do not consider the edit deployed until they agree.
```

`edge-edit-verified`'s check (host md5 == container md5) is exactly the
last two commands above. Record both outputs on the card when closing
this criterion.

## Rollback

If anything looks wrong after activation:

```sh
cp /opt/docker/caddy/Caddyfile.bak-2026-09-02-t228-caddy /opt/docker/caddy/Caddyfile
docker restart caddy-caddy-1
md5 -q /opt/docker/caddy/Caddyfile
docker exec caddy-caddy-1 md5sum /etc/caddy/Caddyfile
# must match each other, and must match the before-state md5 recorded above.
```

No Docker volumes are touched by either path -- this is a single-file
bind-mounted config, restart-only.

## What could go wrong, and how you'd notice

- **Caddyfile syntax error**: `docker restart caddy-caddy-1` would leave
  the container failing to start (or crash-looping); `docker ps` would
  show it not `Up`. This shouldn't happen -- the staged file was
  validated with `caddy adapt --config - --adapter caddyfile` against
  the pinned `caddy:2.11.4-alpine` image before this card was committed
  (see Caddyfile.diff for the full change) -- but check `docker logs
  caddy-caddy-1` first if the restart looks wrong.
- **md5 mismatch between host and container after `docker restart`**:
  the documented virtiofs stale-view footgun (Device.md). Don't trust
  a reload; the restart step above already accounts for this, but if
  the mismatch persists after a restart, stop and diagnose rather than
  retrying blindly.
- **Nothing changes at all**: this Caddyfile edit alone has no visible
  effect until the auth-service image running in production actually
  emits `X-Auth-Actor` -- see `DEPLOY.md` for the accompanying step. Not
  a rollback trigger by itself.
