using Microsoft.Extensions.Options;

namespace Noema.Api.Features.Agents;

public sealed class AgentFleetOptions
{
    public const string SectionName = "Agents";

    /// <summary>How long an agent may stay silent while running a scan before the scan is given up on.</summary>
    public int LeaseSeconds { get; set; } = 120;

    public int ReaperIntervalSeconds { get; set; } = 30;

    /// <summary>An agent not heard from for this long is shown as offline.</summary>
    public int OfflineAfterSeconds { get; set; } = 90;

    /// <summary>A queued scan nobody claims within this time is failed instead of waiting forever.</summary>
    public int QueuedScanExpiryMinutes { get; set; } = 1440;

    public TimeSpan Lease => TimeSpan.FromSeconds(LeaseSeconds);

    public TimeSpan OfflineAfter => TimeSpan.FromSeconds(OfflineAfterSeconds);
}

public sealed class AgentFleetOptionsValidator : IValidateOptions<AgentFleetOptions>
{
    public ValidateOptionsResult Validate(string? name, AgentFleetOptions options)
    {
        var failures = new List<string>();

        if (options.LeaseSeconds is < 30 or > 3600)
        {
            failures.Add("Agents:LeaseSeconds must be between 30 and 3600.");
        }

        if (options.ReaperIntervalSeconds is < 5 or > 600)
        {
            failures.Add("Agents:ReaperIntervalSeconds must be between 5 and 600.");
        }

        if (options.OfflineAfterSeconds is < 15 or > 3600)
        {
            failures.Add("Agents:OfflineAfterSeconds must be between 15 and 3600.");
        }

        if (options.QueuedScanExpiryMinutes is < 5 or > 10_080)
        {
            failures.Add("Agents:QueuedScanExpiryMinutes must be between 5 and 10080.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
