# 01 Foundations

## What this section delivers

A solution that builds, tests and runs the same way on a laptop, in CI and in Docker, with nothing in it yet except the plumbing every later section depends on.

## Layout

- Noema.Api is the control plane host. It will own auth, inventory, history and the job queue.
- Noema.Infrastructure holds persistence and wiring. Domain and Application projects arrive in section 2 when there is real domain code to put in them. Empty projects now would only be noise.
- Noema.Agent is the scanner host. It is a separate deployable from day one and only ever talks outbound.

## Decisions

Central package management and shared build props keep versions in one place and turn warnings into errors.

Configuration is validated at startup. If the database connection string is missing the API refuses to start with a clear message. The agent does the same for its control plane URL, and it only allows plain http for loopback addresses.

Database options are read lazily when the DbContext is resolved. That keeps test and container overrides reliable.

Health is split in two. Live says the process is up. Ready also checks Postgres. Orchestrators should use ready for traffic and live for restarts.

Every request gets a correlation id. A caller supplied id is kept only if it is short and uses safe characters, which blocks log injection through the header.

The agent runs as a Windows Service or a systemd unit using the standard hosting extensions, and the same binary runs in a console during development.

## Testing

- Unit tests cover the correlation id rules and the agent option validation.
- In process tests use WebApplicationFactory against an unreachable database, so they need no Docker and prove the unhealthy paths.
- One Docker test uses Testcontainers to prove readiness against a real Postgres. It carries the trait Category=Docker and is skipped on the Windows CI runner.
- The worker test uses a fake clock so no test waits on real time.

## Known gaps, on purpose

No migrations yet, no auth, no logging sink beyond the console. Those belong to sections 2, 3 and 10.
