# 02 Domain and persistence

## What this section delivers

The core model of the system and the database that stores it. Assets, their interfaces and addresses, scan runs, and the raw observations that probes produce. Nothing here talks to the network yet.

## The model

An asset is a device. It owns one or more interfaces, and each interface owns the IP addresses seen on it. A laptop on wifi and ethernet is one asset with two interfaces.

An interface can exist without a MAC address, for example a device only seen through a routed subnet. An asset can have at most one of those, so repeated IP only sightings land on the same interface.

Addresses keep a first seen and last seen time per interface. When a device moves to a new IP the old address stays as history instead of being overwritten.

A scan run is one request to scan a range with a set of probes. It moves from queued to running to one final state and refuses any other move.

An observation is one fact a probe saw at one moment. They are append only and are the raw material that assets are built from later. They are not tied to an asset yet, because deciding which asset an observation belongs to is identity resolution, which is section 8.

## Decisions worth knowing about

The domain classes protect their own rules. You cannot build an invalid MAC address, a sloppy CIDR range, or a scan that jumps from queued to completed. Timestamps must be UTC and are checked at the edge, which also keeps Postgres happy.

CIDR parsing is strict on purpose. These values will decide what the scanner may touch, so shorthand like 10.1, leading zeros, scope ids and host bits set are all rejected instead of guessed at.

Results can arrive out of order once there are several agents. First seen moves back when an older sighting arrives, last seen never moves back, and an older hostname cannot overwrite a newer one.

A MAC address is indexed but not unique across assets. Shared virtual MACs from VRRP or HSRP and cloned network cards are real, and a unique constraint would turn them into insert failures. Within one asset a MAC is unique. Section 8 decides what to do when two assets claim the same one.

IDs are time ordered UUIDs generated in the domain, so inserts stay mostly sequential in the index.

Optimistic concurrency uses the Postgres xmin row version on assets, so two writers cannot silently overwrite each other.

Postgres native types are used where they fit: macaddr for MAC addresses, inet for IPs, jsonb for probe detail, timestamptz for time. CIDR ranges are stored as text so a stored value always reads back as exactly the same range.

The database backs up the domain rules with constraints. Last seen cannot be before first seen, and a scan row cannot be in a state its timestamps contradict. The tests prove the database refuses these even when SQL goes around the domain.

Columns are snake_case so hand written SQL and reports stay readable.

## Migrations

Migrations are generated with the dotnet ef tools from the Infrastructure project and committed. In development and in the compose file the API applies pending migrations at startup, which suits one instance. With several instances, run migrations as a separate step before deploying. EF Core takes a database lock while migrating, so two instances starting together will not collide.

A test fails if the model changes without a matching migration, so a forgotten migration is caught before it ships.

## Testing

Domain tests are pure and fast, with no database. Infrastructure tests run against a real Postgres through Testcontainers, using the real migrations, and prove round trips, queries, cascades, concurrency and the database level constraints. They carry the trait Category=Docker.

## Left for later

Retention rules for observations, partitioning if volume needs it, and linking observations to assets. Those arrive with sections 5, 8 and 10.
