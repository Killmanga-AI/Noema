using System.Net;
using Noema.Domain;

namespace Noema.Scanning;

public interface IProbe
{
    /// <summary>Which scan probe flag this implements. Exactly one flag.</summary>
    ScanProbes Kind { get; }

    ProbePhase Phase { get; }

    /// <summary>
    /// Probes one address. The engine has already checked the target is allowed and has waited for rate limit capacity.
    /// Return NoResponse for an empty address and Failure when the probe itself could not run.
    /// Honour the timeout and the cancellation token.
    /// </summary>
    ValueTask<ProbeResult> ProbeAsync(IPAddress target, TimeSpan timeout, CancellationToken cancellationToken);
}
