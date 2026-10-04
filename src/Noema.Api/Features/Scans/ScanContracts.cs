namespace Noema.Api.Features.Scans;

public sealed record RequestScanRequest(string? Target, string[]? Probes);

public sealed record ScanDetail(
    Guid Id,
    string Target,
    string[] Probes,
    string Status,
    DateTimeOffset RequestedAt,
    DateTimeOffset? StartedAt,
    DateTimeOffset? FinishedAt,
    string? FailureReason,
    Guid? RequestedByUserId);
