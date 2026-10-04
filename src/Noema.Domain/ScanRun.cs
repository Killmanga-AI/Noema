namespace Noema.Domain;

[Flags]
public enum ScanProbes
{
    None = 0,
    Icmp = 1,
    Arp = 2,
    Dns = 4,
    Tcp = 8,
    Snmp = 16
}

public enum ScanStatus
{
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled
}

/// <summary>
/// One request to scan a range with a set of probes. Moves Queued, Running, then one terminal state,
/// and refuses any other transition.
/// </summary>
public sealed class ScanRun
{
    public const int MaxFailureReasonLength = 1000;

    private const ScanProbes AllProbes = ScanProbes.Icmp | ScanProbes.Arp | ScanProbes.Dns | ScanProbes.Tcp | ScanProbes.Snmp;

    private ScanRun()
    {
    }

    public Guid Id { get; private set; }

    public CidrRange Target { get; private set; } = null!;

    public ScanProbes Probes { get; private set; }

    public ScanStatus Status { get; private set; }

    public DateTimeOffset RequestedAt { get; private set; }

    public DateTimeOffset? StartedAt { get; private set; }

    public DateTimeOffset? FinishedAt { get; private set; }

    public string? FailureReason { get; private set; }

    public bool IsTerminal => Status is ScanStatus.Completed or ScanStatus.Failed or ScanStatus.Cancelled;

    public static ScanRun Request(CidrRange target, ScanProbes probes, DateTimeOffset requestedAt)
    {
        ArgumentNullException.ThrowIfNull(target);
        Guard.Utc(requestedAt, nameof(requestedAt));

        if (probes == ScanProbes.None || (probes & ~AllProbes) != 0)
        {
            throw new ArgumentException("Choose at least one known probe.", nameof(probes));
        }

        return new ScanRun
        {
            Id = Ids.New(requestedAt),
            Target = target,
            Probes = probes,
            Status = ScanStatus.Queued,
            RequestedAt = requestedAt
        };
    }

    public void Start(DateTimeOffset at)
    {
        Guard.Utc(at, nameof(at));
        RequireStatus(ScanStatus.Queued, "start");
        RequireNotBefore(at, RequestedAt);

        Status = ScanStatus.Running;
        StartedAt = at;
    }

    public void Complete(DateTimeOffset at)
    {
        Guard.Utc(at, nameof(at));
        RequireStatus(ScanStatus.Running, "complete");
        RequireNotBefore(at, StartedAt!.Value);

        Status = ScanStatus.Completed;
        FinishedAt = at;
    }

    public void Fail(string reason, DateTimeOffset at)
    {
        Guard.Utc(at, nameof(at));

        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new ArgumentException("A failure needs a reason.", nameof(reason));
        }

        RequireNotTerminal("fail");
        RequireNotBefore(at, StartedAt ?? RequestedAt);

        var trimmed = reason.Trim();
        FailureReason = trimmed.Length > MaxFailureReasonLength ? trimmed[..MaxFailureReasonLength] : trimmed;
        Status = ScanStatus.Failed;
        FinishedAt = at;
    }

    public void Cancel(DateTimeOffset at)
    {
        Guard.Utc(at, nameof(at));
        RequireNotTerminal("cancel");
        RequireNotBefore(at, StartedAt ?? RequestedAt);

        Status = ScanStatus.Cancelled;
        FinishedAt = at;
    }

    private void RequireStatus(ScanStatus expected, string action)
    {
        if (Status != expected)
        {
            throw new InvalidOperationException($"Cannot {action} a scan that is {Status}.");
        }
    }

    private void RequireNotTerminal(string action)
    {
        if (IsTerminal)
        {
            throw new InvalidOperationException($"Cannot {action} a scan that is already {Status}.");
        }
    }

    private static void RequireNotBefore(DateTimeOffset at, DateTimeOffset earliest)
    {
        if (at < earliest)
        {
            throw new ArgumentException("The time cannot be earlier than the previous step of the scan.", nameof(at));
        }
    }
}
