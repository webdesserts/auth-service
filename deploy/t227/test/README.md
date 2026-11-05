# auth-watchdog.sh bounded-restart test

Exercises `../auth-watchdog.sh`'s bounded-restart logic entirely offline:
no docker, no colima, no network call, nothing on the live umbra stack
touched. `DOCKER` is pointed at `stub-docker-unhealthy` (a fake `docker`
that always reports the container unhealthy) and `DRY_RUN=1` throughout,
so every "restart"/"notify" is a logged intention, never an executed
command.

## Run it

```sh
sh run-bounded-restart-test.sh
```

Exits non-zero if any assertion fails. `last-run.log` (committed) is a
captured transcript from a real run of this script — per the standing
"reviewers re-sever independently, never the shared tree" convention,
re-run it yourself rather than trusting the committed log as attestation.

## What it proves

With `MAX_ACTIONS_PER_WINDOW=2` and `WINDOW_SECONDS=5` (small values,
purely so the test runs in under a second instead of needing a real
30-minute wait):

1. **Run 1 and run 2** each log a restart attempt — the container is
   unhealthy (per the stub) and the action budget isn't exhausted yet.
2. **Run 3**, still inside the same 5s window, logs "budget exhausted"
   and a `POST /observations` notification instead of a third restart —
   this is the bounded part: a wedged container gets `N` restart
   attempts, then the watchdog stands down rather than flapping forever.
3. The state file's two recorded timestamps are then **backdated** by
   `WINDOW_SECONDS + 100` seconds (a plain rewrite of the state file, not
   a real 5-minute sleep) to simulate the window elapsing.
4. **Run 4** restarts again — proving the window genuinely resets once
   its own action timestamps age out, rather than the budget being a
   one-shot lifetime cap.

The driver script's own assertions count restart-vs-notify log lines
across all four runs and fail loudly (non-zero exit) if the counts don't
match runs 1/2/4 = restart, run 3 = notify.

## Why `POST /observations`, not `POST /feed`, for the notification

See `auth-watchdog.sh`'s own header comment on `notify_board()`/`BOARD_URL`
for the full reasoning: `POST /observations`'s `source` field is stored as
a plain string with no registry lookup (`crates/prime/src/routes/
observations.rs`'s `resolve_identity` never calls
`data_layer::actors::resolve_or_mint`), unlike `POST /feed`'s `author`,
which does mint a permanent new actor-registry entry for any
never-before-seen string. A recurring automated health-checker must never
grow the actor registry as a side effect of its own polling.

## Files

- `stub-docker-unhealthy` — the fake `docker` binary.
- `run-bounded-restart-test.sh` — the driver (setup, four runs, backdate,
  assertions).
- `last-run.log` — a captured transcript of a real run.
