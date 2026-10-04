using System.Text.Json;
using Noema.Domain;
using Noema.Infrastructure.Persistence;

namespace Noema.Api.Security;

public interface IAuditWriter
{
    /// <summary>
    /// Adds an entry to the current unit of work. It is saved together with whatever the caller saves next,
    /// so an action and its audit entry succeed or fail together. Never pass secrets in detail.
    /// </summary>
    void Add(
        string action,
        AuditOutcome outcome,
        Guid? actorId = null,
        string? actorName = null,
        string? targetType = null,
        string? targetId = null,
        object? detail = null);
}

internal sealed class AuditWriter(NoemaDbContext db, IRequestContext request, TimeProvider time) : IAuditWriter
{
    public void Add(
        string action,
        AuditOutcome outcome,
        Guid? actorId = null,
        string? actorName = null,
        string? targetType = null,
        string? targetId = null,
        object? detail = null)
    {
        var detailJson = detail is null ? null : JsonSerializer.Serialize(detail);

        db.AuditEntries.Add(AuditEntry.Create(
            action,
            outcome,
            time.GetUtcNow(),
            actorId,
            actorName,
            targetType,
            targetId,
            detailJson,
            request.RemoteAddress,
            request.CorrelationId));
    }
}
