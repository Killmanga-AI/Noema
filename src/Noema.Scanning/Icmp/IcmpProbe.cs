using System.Globalization;
using System.Net;
using System.Text.Json;
using Noema.Domain;

namespace Noema.Scanning.Icmp;

/// <summary>Finds hosts that answer a ping. A silent address is normal and is not an error.</summary>
public sealed class IcmpProbe(IIcmpPinger pinger, TimeProvider? timeProvider = null) : IProbe
{
    private readonly TimeProvider time = timeProvider ?? TimeProvider.System;

    public ScanProbes Kind => ScanProbes.Icmp;

    public ProbePhase Phase => ProbePhase.Discovery;

    public async ValueTask<ProbeResult> ProbeAsync(IPAddress target, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var reply = await pinger.PingAsync(target, timeout, cancellationToken).ConfigureAwait(false);

        switch (reply.Status)
        {
            case IcmpStatus.Success:
                var detail = new Dictionary<string, object>
                {
                    ["rttMs"] = Math.Round(reply.RoundTrip.TotalMilliseconds, 2)
                };

                if (reply.TimeToLive is { } ttl)
                {
                    detail["ttl"] = ttl;
                }

                return ProbeResult.Responded(new ProbeObservation(
                    ObservationKind.IcmpEchoReply,
                    target,
                    time.GetUtcNow(),
                    DetailJson: JsonSerializer.Serialize(detail)));

            case IcmpStatus.TimedOut:
            case IcmpStatus.Unreachable:
                return ProbeResult.NoResponse;

            default:
                return ProbeResult.Failure(
                    string.Format(CultureInfo.InvariantCulture, "ICMP to {0} failed: {1}", target, reply.Error ?? "unknown error"));
        }
    }
}
