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

public enum BatchDisposition
{
    Accepted,
    Duplicate
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

    /// <summary>Who asked for the scan. Empty for scans created by the system.</summary>
    public Guid? RequestedByUserId { get; private set; }

    /// <summary>When set, only this agent may run the scan. Otherwise any agent that covers the target can.</summary>
    public Guid? RequestedAgentId { get; private set; }

    public Guid? AssignedAgentId { get; private set; }

    /// <summary>The agent must report before this moment or the scan is treated as abandoned.</summary>
    public DateTimeOffset? LeaseExpiresAt { get; private set; }

    public DateTimeOffset? CancelRequestedAt { get; private set; }

    public long TargetsPlanned { get; private set; }

    public long TargetsScanned { get; private set; }

    public long HostsResponded { get; private set; }

    /// <summary>The number of the last observation batch accepted, so a repeated upload is recognised.</summary>
    public int LastBatchSequence { get; private set; }

    public bool IsCancelRequested => CancelRequestedAt.HasValue && !IsTerminal;

    public bool IsTerminal => Status is ScanStatus.Completed or ScanStatus.Failed or ScanStatus.Cancelled;

    public static ScanRun Request(
        CidrRange target,
        ScanProbes probes,
        DateTimeOffset requestedAt,
        Guid? requestedByUserId = null,
        Guid? requestedAgentId = null)
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
            RequestedAt = requestedAt,
            RequestedByUserId = requestedByUserId,
            RequestedAgentId = requestedAgentId
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

    /// <summary>An agent takes a queued scan and starts it. The scan stays its own until it finishes or the lease runs out.</summary>
    public void Claim(Guid agentId, DateTimeOffset at, TimeSpan lease)
    {
        if (agentId == Guid.Empty)
        {
            throw new ArgumentException("A scan is claimed by an agent.", nameof(agentId));
        }

        RequirePositive(lease);

        if (RequestedAgentId is { } pinned && pinned != agentId)
        {
            throw new InvalidOperationException("This scan is reserved for a different agent.");
        }

        Start(at);
        AssignedAgentId = agentId;
        LeaseExpiresAt = at + lease;
    }

    public bool IsAssignedTo(Guid agentId) => AssignedAgentId == agentId;

    /// <summary>Records the agent's progress and pushes the lease out again. Counts never go backwards.</summary>
    public void ReportProgress(Guid agentId, DateTimeOffset at, TimeSpan lease, long targetsPlanned, long targetsScanned, long hostsResponded)
    {
        Guard.Utc(at, nameof(at));
        RequireRunningFor(agentId);
        RequirePositive(lease);

        if (targetsPlanned < 0 || targetsScanned < 0 || hostsResponded < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(targetsScanned), "Counts cannot be negative.");
        }

        if (targetsScanned > targetsPlanned || hostsResponded > targetsScanned)
        {
            throw new ArgumentException("The counts do not add up: scanned cannot exceed planned, and answered cannot exceed scanned.");
        }

        if (targetsScanned < TargetsScanned || hostsResponded < HostsResponded)
        {
            throw new ArgumentException("Progress cannot go backwards.");
        }

        TargetsPlanned = targetsPlanned;
        TargetsScanned = targetsScanned;
        HostsResponded = hostsResponded;
        ExtendLease(at, lease);
    }

    /// <summary>
    /// Accepts the next batch of observations, or recognises a repeat of the last one. Anything else
    /// means a batch was skipped, which is refused so results are never lost silently.
    /// </summary>
    public BatchDisposition AcceptBatch(Guid agentId, int sequence, DateTimeOffset at, TimeSpan lease)
    {
        Guard.Utc(at, nameof(at));
        RequireRunningFor(agentId);
        RequirePositive(lease);

        if (sequence == LastBatchSequence && sequence > 0)
        {
            ExtendLease(at, lease);
            return BatchDisposition.Duplicate;
        }

        if (sequence != LastBatchSequence + 1)
        {
            throw new InvalidOperationException($"Expected batch {LastBatchSequence + 1} but received {sequence}.");
        }

        LastBatchSequence = sequence;
        ExtendLease(at, lease);
        return BatchDisposition.Accepted;
    }

    /// <summary>
    /// A queued scan is cancelled at once. A running scan is flagged so its agent stops at its next report.
    /// Asking again is harmless.
    /// </summary>
    public void RequestCancel(DateTimeOffset at)
    {
        Guard.Utc(at, nameof(at));

        if (IsTerminal)
        {
            throw new InvalidOperationException($"Cannot cancel a scan that is already {Status}.");
        }

        if (Status == ScanStatus.Queued)
        {
            Cancel(at);
            return;
        }

        CancelRequestedAt ??= at;
    }

    /// <summary>Ends a running scan whose agent stopped reporting.</summary>
    public void Abandon(DateTimeOffset at, string reason) => Fail(reason, at);

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

    private void ExtendLease(DateTimeOffset at, TimeSpan lease)
    {
        var candidate = at + lease;
        if (LeaseExpiresAt is null || candidate > LeaseExpiresAt)
        {
            LeaseExpiresAt = candidate;
        }
    }

    private void RequireRunningFor(Guid agentId)
    {
        if (Status != ScanStatus.Running)
        {
            throw new InvalidOperationException($"The scan is {Status}, not running.");
        }

        if (AssignedAgentId != agentId)
        {
            throw new InvalidOperationException("The scan is assigned to a different agent.");
        }
    }

    private static void RequirePositive(TimeSpan lease)
    {
        if (lease <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lease), lease, "The lease must be positive.");
        }
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
