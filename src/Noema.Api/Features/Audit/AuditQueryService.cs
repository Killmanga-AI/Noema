using Microsoft.EntityFrameworkCore;
using Noema.Api.Common;
using Noema.Domain;
using Noema.Infrastructure.Persistence;

namespace Noema.Api.Features.Audit;

internal sealed class AuditQueryService(NoemaDbContext db)
{
    public async Task<ServiceResult<IReadOnlyList<AuditEntryDetail>>> QueryAsync(
        string? action,
        string? actor,
        string? outcome,
        DateTimeOffset? before,
        int? limit,
        CancellationToken ct)
    {
        var take = limit ?? 50;
        if (take is < 1 or > 200)
        {
            return ServiceResult<IReadOnlyList<AuditEntryDetail>>.Fail(ServiceErrors.Validation("limit", "The limit must be between 1 and 200."));
        }

        var query = db.AuditEntries.AsNoTracking();

        if (!string.IsNullOrWhiteSpace(action))
        {
            var prefix = action.Trim().ToLowerInvariant();
            query = query.Where(a => a.Action == prefix || a.Action.StartsWith(prefix + "."));
        }

        if (!string.IsNullOrWhiteSpace(actor))
        {
            var name = User.NormalizeUsername(actor);
            query = query.Where(a => a.ActorName == name);
        }

        if (!string.IsNullOrWhiteSpace(outcome))
        {
            if (!EnumParsing.TryParseName<AuditOutcome>(outcome, out var parsed))
            {
                return ServiceResult<IReadOnlyList<AuditEntryDetail>>.Fail(ServiceErrors.Validation("outcome", "Use Success, Failure or Denied."));
            }

            query = query.Where(a => a.Outcome == parsed);
        }

        if (before is { } cutoff)
        {
            var utcCutoff = cutoff.ToUniversalTime();
            query = query.Where(a => a.OccurredAt < utcCutoff);
        }

        var entries = await query.OrderByDescending(a => a.OccurredAt).ThenByDescending(a => a.Id).Take(take).ToListAsync(ct);

        IReadOnlyList<AuditEntryDetail> mapped = entries
            .Select(a => new AuditEntryDetail(
                a.Id, a.OccurredAt, a.ActorUserId, a.ActorName, a.Action, a.TargetType, a.TargetId,
                a.Outcome.ToString(), a.DetailJson, a.RemoteAddress?.ToString(), a.CorrelationId))
            .ToList();

        return ServiceResult<IReadOnlyList<AuditEntryDetail>>.Ok(mapped);
    }
}
