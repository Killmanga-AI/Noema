using Noema.Domain;

namespace Noema.Scanning;

/// <summary>
/// What this agent is willing to scan, set locally on the agent. It repeats the control plane's authorization
/// on purpose, so a bug or a stolen credential upstream still cannot make this agent probe arbitrary networks.
/// </summary>
public sealed class ScanScope
{
    private readonly CidrRange[] allowedRanges;

    public ScanScope(IEnumerable<CidrRange> allowedRanges, int maxAddresses)
    {
        ArgumentNullException.ThrowIfNull(allowedRanges);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxAddresses, 1);

        this.allowedRanges = allowedRanges.ToArray();
        MaxAddresses = maxAddresses;
    }

    public IReadOnlyList<CidrRange> AllowedRanges => allowedRanges;

    public int MaxAddresses { get; }

    public ScanAuthorizationResult Authorize(CidrRange target) =>
        ScanAuthorizationPolicy.Evaluate(target, allowedRanges, MaxAddresses);
}
