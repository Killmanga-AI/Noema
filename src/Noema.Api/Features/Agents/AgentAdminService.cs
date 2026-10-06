using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Noema.Api.Common;
using Noema.Api.Security;
using Noema.Domain;
using Noema.Infrastructure.Persistence;
using Noema.Infrastructure.Security;

namespace Noema.Api.Features.Agents;

internal sealed class AgentAdminService(
    NoemaDbContext db,
    IAuditWriter audit,
    IOptions<AgentFleetOptions> fleet,
    TimeProvider time)
{
    private const int DefaultTokenHours = 24;

    public async Task<ServiceResult<CreatedEnrollmentToken>> CreateTokenAsync(CurrentUser actor, CreateEnrollmentTokenRequest request, CancellationToken ct)
    {
        var hours = request.ExpiresInHours ?? DefaultTokenHours;
        if (hours is < 1 or > 168)
        {
            return ServiceResult<CreatedEnrollmentToken>.Fail(ServiceErrors.Validation("expiresInHours", "A token lasts between 1 and 168 hours."));
        }

        if (request.Label is { Length: > EnrollmentToken.MaxLabelLength })
        {
            return ServiceResult<CreatedEnrollmentToken>.Fail(ServiceErrors.Validation(
                "label", $"A label can be at most {EnrollmentToken.MaxLabelLength} characters."));
        }

        var raw = SecretTokens.NewEnrollmentToken();
        var token = EnrollmentToken.Issue(SecretTokens.Hash(raw), request.Label, actor.Id, time.GetUtcNow(), TimeSpan.FromHours(hours));

        db.EnrollmentTokens.Add(token);
        audit.Add(
            "agent.enrollment_token.created",
            AuditOutcome.Success,
            actor.Id,
            actor.Username,
            "enrollment_token",
            token.Id.ToString(),
            new { label = token.Label, expiresAt = token.ExpiresAt });
        await db.SaveChangesAsync(ct);

        // The raw token is shown this once. Only its hash is kept.
        return ServiceResult<CreatedEnrollmentToken>.Ok(new CreatedEnrollmentToken(token.Id, raw, token.Label, token.ExpiresAt));
    }

    public async Task<IReadOnlyList<EnrollmentTokenDetail>> ListTokensAsync(CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var tokens = await db.EnrollmentTokens.AsNoTracking().OrderByDescending(t => t.CreatedAt).Take(100).ToListAsync(ct);

        return tokens
            .Select(t => new EnrollmentTokenDetail(
                t.Id,
                t.Label,
                t.IsUsed ? "Used" : t.IsUsable(now) ? "Pending" : "Expired",
                t.CreatedAt,
                t.ExpiresAt,
                t.UsedAt,
                t.AgentId))
            .ToList();
    }

    public async Task<ServiceResult<Unit>> DeleteTokenAsync(CurrentUser actor, Guid id, CancellationToken ct)
    {
        var token = await db.EnrollmentTokens.SingleOrDefaultAsync(t => t.Id == id, ct);
        if (token is null)
        {
            return ServiceResult<Unit>.Fail(ServiceErrors.NotFound("No such enrollment token."));
        }

        if (token.IsUsed)
        {
            return ServiceResult<Unit>.Fail(ServiceErrors.Conflict("A used token is kept as a record of how the agent enrolled."));
        }

        db.EnrollmentTokens.Remove(token);
        audit.Add("agent.enrollment_token.deleted", AuditOutcome.Success, actor.Id, actor.Username, "enrollment_token", token.Id.ToString());
        await db.SaveChangesAsync(ct);

        return ServiceResult<Unit>.Ok(default);
    }

    public async Task<IReadOnlyList<AgentDetail>> ListAgentsAsync(CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var agents = await db.Agents.AsNoTracking().OrderBy(a => a.Name).ThenBy(a => a.CreatedAt).ToListAsync(ct);

        return agents.Select(a => ToDetail(a, now)).ToList();
    }

    public async Task<ServiceResult<AgentDetail>> RevokeAsync(CurrentUser actor, Guid id, CancellationToken ct)
    {
        var agent = await db.Agents.SingleOrDefaultAsync(a => a.Id == id, ct);
        if (agent is null)
        {
            return ServiceResult<AgentDetail>.Fail(ServiceErrors.NotFound("No such agent."));
        }

        var now = time.GetUtcNow();
        if (!agent.IsRevoked)
        {
            agent.Revoke(now);

            // Anything it was running is over, and scans reserved for it can never run now.
            var stranded = await db.ScanRuns
                .Where(s => (s.AssignedAgentId == id && s.Status == ScanStatus.Running)
                    || (s.RequestedAgentId == id && s.Status == ScanStatus.Queued))
                .ToListAsync(ct);

            foreach (var scan in stranded)
            {
                if (scan.Status == ScanStatus.Running)
                {
                    scan.Abandon(now, "The agent was revoked.");
                }
                else
                {
                    scan.Cancel(now);
                }
            }

            audit.Add("agent.revoked", AuditOutcome.Success, actor.Id, actor.Username, "agent", agent.Id.ToString(), new { agent.Name, endedScans = stranded.Count });

            try
            {
                await db.SaveChangesAsync(ct);
            }
            catch (DbUpdateConcurrencyException)
            {
                return ServiceResult<AgentDetail>.Fail(ServiceErrors.Conflict("The agent was changed by another request. Try again."));
            }
        }

        return ServiceResult<AgentDetail>.Ok(ToDetail(agent, now));
    }

    private AgentDetail ToDetail(Agent agent, DateTimeOffset now) =>
        new(
            agent.Id,
            agent.Name,
            agent.Status.ToString(),
            agent.IsOnline(now, fleet.Value.OfflineAfter),
            agent.CreatedAt,
            agent.LastSeenAt,
            agent.LastSeenAddress?.ToString(),
            agent.Version,
            agent.OperatingSystem,
            ScanProbeNames.ToNames(agent.Capabilities),
            agent.ReportedRanges.Select(r => r.ToString()).ToArray(),
            agent.RevokedAt);
}
