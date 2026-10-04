namespace Noema.Api.Features.Audit;

public sealed record AuditEntryDetail(
    Guid Id,
    DateTimeOffset OccurredAt,
    Guid? ActorUserId,
    string? ActorName,
    string Action,
    string? TargetType,
    string? TargetId,
    string Outcome,
    string? DetailJson,
    string? RemoteAddress,
    string? CorrelationId);
