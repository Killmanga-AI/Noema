# 04 Scan engine

## What this section delivers

A scan engine that lives in the agent, a real ICMP sweep, and a way to try it on your own network from a command line. The control plane still only authorizes and records scan requests. Everything that touches the network happens in the agent.

## Where it lives

Noema.Scanning is a library with no network or hosting dependencies beyond the framework. It holds the probe contract, the rate limiter, target expansion, the agent side scope check, the engine and the ICMP probe. The agent hosts it. Keeping it a library means the engine can be tested with fake probes and a fake clock, and later probes plug in without touching it.

## How a scan runs

The engine first checks the target against the agent's own scope. If it is not allowed nothing is sent, and the result says why. This repeats the control plane's check on purpose, so a bug or a stolen credential upstream still cannot make this agent probe arbitrary networks. Loopback, multicast and reserved space are refused even if the scope covers them, only private ranges can be listed by default, and a scan has a size cap.

Probes come in two phases. Discovery probes, such as ping and later ARP, decide whether a host is there. Enrichment probes, such as reverse DNS, ports and SNMP, only run against hosts that answered discovery. If a scan asks for enrichment probes alone, they run against every address. Adding the later probes means adding classes, not changing the engine.

Addresses are expanded lazily, so a large range costs nothing until it is walked. IPv4 ranges of /30 and larger skip the network and broadcast addresses.

## Limits

Concurrency is bounded. Every probe attempt takes a permit from one shared token bucket, 200 per second with a burst of 50 by default, so the agent's total network load stays bounded however many scans run. Each probe has its own timeout, and the engine adds a short grace period after which it stops a probe that is not honouring its timeout, so one hung call cannot stall a scan.

A silent address is the normal answer for an empty slot and is not an error. Real errors, such as a missing permission or a broken network, are counted. After 25 errors in a row the scan stops as failed with the cause, instead of grinding through thousands of addresses. A success resets the streak, so scattered errors do not abort a scan.

Results are written to the sink one at a time, so a sink does not need to be thread safe. If the sink fails the scan stops as failed instead of silently losing results. Cancelling returns what was found so far with a Cancelled outcome. A faulty progress listener can never break a scan.

## Trying it

From the agent project on a machine on your network:

    dotnet run --project src/Noema.Agent -- scan 192.168.1.0/24

Scans are only allowed inside Scanning:AllowedRanges in the agent's settings, which is empty by default. For a quick try use an environment variable, for example Scanning__AllowedRanges__0=192.168.1.0/24. Each host that answers is printed with its round trip time and TTL. The exit code is 0 for a finished scan, 1 for failed or refused, 2 for bad input or settings and 130 for cancelled.

## Operating system notes

ICMP goes through the operating system's own ping support, so there is no platform specific code. On Windows it just works. On Linux, as far as I know, the account needs permission to send ping. Either the group of the account has to fall inside net.ipv4.ping_group_range, for example sudo sysctl -w net.ipv4.ping_group_range="0 2147483647", or the binary needs the cap_net_raw capability. If it is missing the scan fails fast with a clear error rather than scanning in silence. Packaging the agent with the right permission is part of section 5.

## Left for later

ARP and neighbor tables, reverse DNS, TCP ports and SNMP are separate probes in sections 6 and 7. Turning scan requests from the control plane into jobs the agent pulls is section 5. Observations from the engine become stored observations through ProbeObservation.ToDomain once the agent can report results.
