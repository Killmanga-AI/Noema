using System.Numerics;

namespace Noema.Domain;

public enum ScanAuthorizationOutcome
{
    Allowed,
    Forbidden,
    NotAuthorized,
    TooLarge
}

public sealed record ScanAuthorizationResult(ScanAuthorizationOutcome Outcome, string? Reason)
{
    public bool IsAllowed => Outcome == ScanAuthorizationOutcome.Allowed;
}

/// <summary>
/// Decides whether a scan target may be scanned. A target is allowed only when it is not reserved space,
/// sits completely inside an authorized range, and is not larger than the configured limit.
/// </summary>
public static class ScanAuthorizationPolicy
{
    public static ScanAuthorizationResult Evaluate(
        CidrRange target,
        IEnumerable<CidrRange> authorizedRanges,
        BigInteger maxAddresses)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(authorizedRanges);

        if (ScanTargetRules.IsNeverScannable(target))
        {
            return new(ScanAuthorizationOutcome.Forbidden, "That target includes loopback, multicast or reserved addresses.");
        }

        if (!authorizedRanges.Any(range => range.Contains(target)))
        {
            return new(ScanAuthorizationOutcome.NotAuthorized, "That target is not inside an authorized range.");
        }

        if (target.AddressCount > maxAddresses)
        {
            return new(ScanAuthorizationOutcome.TooLarge, $"That target has more than {maxAddresses} addresses, which is the limit for one scan.");
        }

        return new(ScanAuthorizationOutcome.Allowed, null);
    }
}
