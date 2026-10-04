using Noema.Domain;

namespace Noema.Scanning;

public sealed record ScanJob(Guid ScanRunId, CidrRange Target, ScanProbes Probes);

public enum SweepOutcome
{
    Completed,
    Cancelled,
    Failed,

    /// <summary>The scan was not allowed or could not be set up, and nothing was sent.</summary>
    Refused
}

public sealed record ScanProgress(long TargetsPlanned, long TargetsScanned, long HostsResponded);

public sealed record ScanSummary(
    SweepOutcome Outcome,
    string? Reason,
    long TargetsPlanned,
    long TargetsScanned,
    long HostsResponded,
    long Observations,
    long ProbeErrors,
    long ProbeTimeouts,
    TimeSpan Duration,
    IReadOnlyList<string> ErrorSamples);
