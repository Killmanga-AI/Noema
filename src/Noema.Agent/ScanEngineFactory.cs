using Noema.Scanning;
using Noema.Scanning.Icmp;

namespace Noema.Agent;

public static class ScanEngineFactory
{
    /// <summary>The probes this build of the agent can run. Grows as probes are added.</summary>
    public static Noema.Domain.ScanProbes SupportedProbes => Noema.Domain.ScanProbes.Icmp;

    /// <summary>Builds the real engine with the probes this agent supports. The options must already be valid.</summary>
    public static ScanEngine Create(ScanningOptions options, TimeProvider time, IIcmpPinger? pinger = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);

        var probes = new IProbe[] { new IcmpProbe(pinger ?? new SystemIcmpPinger(), time) };
        var limiter = new TokenBucketRateLimiter(options.PacketsPerSecond, options.Burst, time);

        return new ScanEngine(probes, options.BuildScope(), options.BuildEngineOptions(), limiter, time);
    }
}
