# 05 Agents and the job queue

## What this section delivers

A real agent that enrolls with the control plane, asks for work over outbound requests only, runs scans with the engine from section 4, and reports what it finds. It runs as a Windows service or a systemd unit, and the control plane keeps scans from getting stuck when an agent dies.

## The shape of it

The control plane never reaches into a network. Agents ask for work, so an agent can sit behind NAT or a firewall with no inbound ports. Plural routes such as /api/v1/agents are for administrators. The singular /api/v1/agent routes are the agent protocol. Both sides share their request and response types through Noema.Contracts, so they cannot drift apart.

## Enrollment

An administrator creates a single use enrollment token through the API. It lasts 1 to 168 hours, is shown once, and only its hash is stored. On the machine that will run the agent:

    noema-agent enroll --server https://noema.example.com --token nmt_... --allow 192.168.1.0/24

The agent trades the token for its own credential, an id and a random secret. Unknown, used and expired tokens all get the same refusal, and a token that two agents present at the same moment can only be redeemed once, which the database enforces. A rejected request, for example a bad range, does not use the token up.

The credential is saved in one file. On Linux and macOS it is created readable by its owner only from the first byte. On Windows its access list is cut down to administrators, the system and the local service account. It is written in one step, so a crash never leaves half a credential. Enrollment also writes a small settings file next to it with the server address and allowed ranges, so the service needs no further setup.

## Authentication

Agents send Authorization: Agent id:secret. The control plane stores only a hash of the secret. A wrong secret, an unknown agent and a revoked agent all get the same answer, and an unknown agent still costs the same hashing work. Headers that use any other scheme are ignored, so agent credentials can never open user endpoints and user tokens can never open agent endpoints.

The agent also refuses to send its credential anywhere except the server it enrolled with. If the configured address differs from the one in the credential file, it stops and says why. That protects the secret from a mistyped or tampered setting.

## How work flows

An idle agent asks for work every 30 seconds. Each ask doubles as a heartbeat and refreshes the version, probes and ranges the agent reports. The control plane offers the oldest queued scan whose target sits inside a range the agent reports and whose probes the agent has. A scan can also be pinned to one agent when it is requested. Two agents asking at once can never get the same scan, which is enforced with the database row version rather than a lock.

Claiming a scan starts it and gives the agent a lease of two minutes. While it works, the agent reports every 5 seconds, sending its findings in batches of up to 100 and its progress. Every report renews the lease and carries back whether someone asked to cancel. When the engine finishes, the agent sends the final batch and then how the scan ended. Completion can safely be repeated.

Findings are numbered. The control plane accepts the next number, recognises a repeat of the last one without storing it twice, and refuses a skipped number. So a retry after a lost reply is harmless and data is never lost silently. A batch is accepted whole or not at all. Every address must be inside the scan's target, every time must be UTC and within five minutes of the scan window, which also exposes agents with a wrong clock.

## When things go wrong

If an agent stops reporting, a background pass fails its scan once the lease runs out. A scan nobody claims within a day is failed rather than left queued forever. An agent that restarts and asks for work again has its old running scan failed at once. Revoking an agent permanently locks it out, fails what it was running and cancels scans that were pinned to it.

On the agent, network trouble is retried with doubling, jittered waits up to five minutes. If uploads keep failing during a scan, the scan is reported as failed with the reason. If the control plane says the scan is gone, the agent stops working on it quietly. If the credential is refused, the agent was revoked, so it stops and exits instead of hammering the server. Stopping the service mid scan stops the engine and reports the scan as failed.

## Running it as a service

Linux: deploy/linux holds a systemd unit and an installer. The unit runs as a dedicated account with only the capability to send ping, a read only filesystem, and no privilege escalation. Windows: deploy/windows holds an installer that puts the program under Program Files, locks the data folder, enrolls, and runs the service as LocalService, which can ping and nothing more, with automatic restarts. CI publishes self contained single file builds for win-x64, linux-x64 and linux-arm64.

## Left for later

Turning observations into assets and history is section 8. ARP, DNS, TCP and SNMP probes are sections 6 and 7, and the agent already reports which probes it has so scans are routed correctly. Agents poll rather than hold a connection open, which is simple and firewall friendly, and long polling can be added if latency matters. The agent has no self update yet.
