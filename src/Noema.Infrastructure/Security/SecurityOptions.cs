using System.ComponentModel.DataAnnotations;
using Noema.Domain;

namespace Noema.Infrastructure.Security;

public sealed class SecurityOptions
{
    public const string SectionName = "Security";

    /// <summary>PBKDF2 cost. Raise it as hardware gets faster, old hashes are upgraded when users sign in.</summary>
    [Range(100_000, 10_000_000)]
    public int PasswordHashIterations { get; set; } = Pbkdf2PasswordHasher.DefaultIterations;

    /// <summary>Sign in and refresh attempts allowed per client address each minute.</summary>
    [Range(1, 1000)]
    public int AuthRateLimitPerMinute { get; set; } = 10;

    /// <summary>The most addresses one scan request may cover.</summary>
    [Range(1, 16_777_216)]
    public int MaxScanAddresses { get; set; } = ScanTargetRules.DefaultMaxScanAddresses;

    /// <summary>Off by default so only private networks can be authorized for scanning.</summary>
    public bool AllowPublicRanges { get; set; }
}
