namespace Noema.Api.Features.Agents;

public sealed record CreateEnrollmentTokenRequest(string? Label, int? ExpiresInHours);

public sealed record CreatedEnrollmentToken(Guid Id, string Token, string? Label, DateTimeOffset ExpiresAt);

public sealed record EnrollmentTokenDetail(
    Guid Id,
    string? Label,
    string Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? UsedAt,
    Guid? AgentId);

public sealed record AgentDetail(
    Guid Id,
    string Name,
    string Status,
    bool Online,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastSeenAt,
    string? LastSeenAddress,
    string? Version,
    string? OperatingSystem,
    string[] Capabilities,
    string[] ReportedRanges,
    DateTimeOffset? RevokedAt);
