namespace Noema.Api.Features.Scans;

public sealed record RequestScanRequest(string? Target, string[]? Probes, Guid? AgentId = null);

public sealed record ScanDetail(
    Guid Id,
    string Target,
    string[] Probes,
    string Status,
    DateTimeOffset RequestedAt,
    DateTimeOffset? StartedAt,
    DateTimeOffset? FinishedAt,
    string? FailureReason,
    Guid? RequestedByUserId,
    Guid? RequestedAgentId,
    Guid? AssignedAgentId,
    bool CancelRequested,
    long TargetsPlanned,
    long TargetsScanned,
    long HostsResponded);

public sealed record ObservationDetail(
    Guid Id,
    string Kind,
    string Address,
    string? MacAddress,
    DateTimeOffset ObservedAt,
    string? DetailJson);
