namespace Noema.Contracts;

/// <summary>The scheme name agents use in the Authorization header: "Agent {agentId}:{secret}".</summary>
public static class AgentProtocol
{
    public const string AuthenticationScheme = "Agent";

    public const int MaxObservationsPerBatch = 100;

    public const string OutcomeCompleted = "Completed";
    public const string OutcomeFailed = "Failed";
    public const string OutcomeCancelled = "Cancelled";

    public static string AuthorizationValue(Guid agentId, string secret) => $"{agentId}:{secret}";
}

public sealed record EnrollRequest(
    string EnrollmentToken,
    string AgentName,
    string? Version,
    string? OperatingSystem,
    string[] Capabilities,
    string[] ReportedRanges);

public sealed record EnrollResponse(Guid AgentId, string AgentSecret, string Name);

/// <summary>Sent each time an agent asks for work. Doubles as a heartbeat and refreshes what the agent reports.</summary>
public sealed record ClaimRequest(
    string? Version,
    string? OperatingSystem,
    string[] Capabilities,
    string[] ReportedRanges);

public sealed record ClaimedJob(Guid ScanId, string Target, string[] Probes, DateTimeOffset LeaseExpiresAt);

public sealed record ProgressRequest(long TargetsPlanned, long TargetsScanned, long HostsResponded);

public sealed record ProgressResponse(bool CancelRequested, DateTimeOffset LeaseExpiresAt);

public sealed record ObservationDto(
    string Kind,
    string Address,
    DateTimeOffset ObservedAt,
    string? MacAddress,
    string? DetailJson);

public sealed record ObservationBatch(int Sequence, ObservationDto[] Observations);

public sealed record ObservationBatchResponse(int Accepted, bool Duplicate, bool CancelRequested, DateTimeOffset LeaseExpiresAt);

public sealed record CompleteRequest(
    string Outcome,
    string? Reason,
    long TargetsPlanned,
    long TargetsScanned,
    long HostsResponded);
