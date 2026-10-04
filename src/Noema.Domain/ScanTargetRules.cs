using System.Numerics;

namespace Noema.Domain;

/// <summary>
/// Fixed safety rules about what can ever be scanned or authorized, whatever an administrator configures.
/// </summary>
public static class ScanTargetRules
{
    public const int DefaultMaxScanAddresses = 65_536;

    private static readonly CidrRange[] NeverScannable =
    [
        CidrRange.Parse("0.0.0.0/8"),
        CidrRange.Parse("127.0.0.0/8"),
        CidrRange.Parse("224.0.0.0/4"),
        CidrRange.Parse("240.0.0.0/4"),
        CidrRange.Parse("::/128"),
        CidrRange.Parse("::1/128"),
        CidrRange.Parse("ff00::/8")
    ];

    private static readonly CidrRange[] Private =
    [
        CidrRange.Parse("10.0.0.0/8"),
        CidrRange.Parse("172.16.0.0/12"),
        CidrRange.Parse("192.168.0.0/16"),
        CidrRange.Parse("100.64.0.0/10"),
        CidrRange.Parse("169.254.0.0/16"),
        CidrRange.Parse("fc00::/7"),
        CidrRange.Parse("fe80::/10")
    ];

    /// <summary>True when the range touches loopback, multicast, broadcast or similar space, even partly.</summary>
    public static bool IsNeverScannable(CidrRange range)
    {
        ArgumentNullException.ThrowIfNull(range);
        return NeverScannable.Any(blocked => blocked.Contains(range) || range.Contains(blocked));
    }

    /// <summary>True only when the whole range sits inside private address space.</summary>
    public static bool IsPrivate(CidrRange range)
    {
        ArgumentNullException.ThrowIfNull(range);
        return Private.Any(block => block.Contains(range));
    }

    /// <summary>Why a range may not be authorized, or null when it may be.</summary>
    public static string? ValidateForAuthorization(CidrRange range, bool allowPublic)
    {
        ArgumentNullException.ThrowIfNull(range);

        if (IsNeverScannable(range))
        {
            return "That range includes loopback, multicast or reserved addresses and can never be authorized.";
        }

        if (!allowPublic && !IsPrivate(range))
        {
            return "Only private address ranges can be authorized. Public ranges are disabled for this installation.";
        }

        return null;
    }

    public static BigInteger MaxAddressesOrDefault(int? configured) =>
        configured is > 0 ? configured.Value : DefaultMaxScanAddresses;
}
