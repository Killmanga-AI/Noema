using Microsoft.Extensions.Options;
using Noema.Domain;
using Noema.Scanning;

namespace Noema.Agent;

/// <summary>
/// What this agent may scan and how hard it may push the network. Set on the agent itself, so the limits hold
/// even if the control plane is wrong. With no allowed ranges the agent runs but refuses every scan.
/// </summary>
public sealed class ScanningOptions
{
    public const string SectionName = "Scanning";

    public string[] AllowedRanges { get; set; } = [];

    /// <summary>Off by default so only private networks can be listed in AllowedRanges.</summary>
    public bool AllowPublicRanges { get; set; }

    public int MaxAddressesPerScan { get; set; } = ScanTargetRules.DefaultMaxScanAddresses;

    public int MaxConcurrency { get; set; } = 64;

    /// <summary>The most probes the agent sends per second across all scans.</summary>
    public double PacketsPerSecond { get; set; } = 200;

    /// <summary>How many probes may go out at once after a quiet moment.</summary>
    public int Burst { get; set; } = 50;

    public int ProbeTimeoutMilliseconds { get; set; } = 2000;

    public int ProbeTimeoutGraceMilliseconds { get; set; } = 1000;

    public int AbortAfterConsecutiveErrors { get; set; } = 25;

    public IReadOnlyList<string> Validate()
    {
        var problems = new List<string>();

        foreach (var text in AllowedRanges ?? [])
        {
            if (!CidrRange.TryParse(text, out var range))
            {
                problems.Add($"Scanning:AllowedRanges has '{text}', which is not a valid range like 192.168.1.0/24.");
                continue;
            }

            var problem = ScanTargetRules.ValidateForAuthorization(range, AllowPublicRanges);
            if (problem is not null)
            {
                problems.Add($"Scanning:AllowedRanges '{text}': {problem}");
            }
        }

        if (MaxAddressesPerScan is < 1 or > 16_777_216)
        {
            problems.Add("Scanning:MaxAddressesPerScan must be between 1 and 16777216.");
        }

        if (double.IsNaN(PacketsPerSecond) || PacketsPerSecond <= 0 || PacketsPerSecond > 10_000)
        {
            problems.Add("Scanning:PacketsPerSecond must be above 0 and at most 10000.");
        }

        if (Burst is < 1 or > 10_000)
        {
            problems.Add("Scanning:Burst must be between 1 and 10000.");
        }

        problems.AddRange(BuildEngineOptions().Validate().Select(p => "Scanning: " + p));
        return problems;
    }

    public ScanEngineOptions BuildEngineOptions() => new()
    {
        MaxConcurrency = MaxConcurrency,
        ProbeTimeout = TimeSpan.FromMilliseconds(ProbeTimeoutMilliseconds),
        ProbeTimeoutGrace = TimeSpan.FromMilliseconds(ProbeTimeoutGraceMilliseconds),
        AbortAfterConsecutiveErrors = AbortAfterConsecutiveErrors
    };

    public ScanScope BuildScope() =>
        new((AllowedRanges ?? []).Select(CidrRange.Parse), MaxAddressesPerScan);
}

public sealed class ScanningOptionsValidator : IValidateOptions<ScanningOptions>
{
    public ValidateOptionsResult Validate(string? name, ScanningOptions options)
    {
        var problems = options.Validate();
        return problems.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(problems);
    }
}
