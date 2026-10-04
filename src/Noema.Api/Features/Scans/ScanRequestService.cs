using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Noema.Api.Common;
using Noema.Api.Security;
using Noema.Domain;
using Noema.Infrastructure.Persistence;
using Noema.Infrastructure.Security;

namespace Noema.Api.Features.Scans;

internal sealed class ScanRequestService(
    NoemaDbContext db,
    IOptions<SecurityOptions> security,
    IAuditWriter audit,
    TimeProvider time)
{
    private const int MaxProbeEntries = 16;

    public async Task<ServiceResult<ScanDetail>> RequestAsync(CurrentUser actor, RequestScanRequest request, CancellationToken ct)
    {
        var errors = new Dictionary<string, string[]>();

        if (!CidrRange.TryParse(request.Target, out var target))
        {
            errors["target"] = ["Use network notation such as 192.168.1.0/24 with no host bits set."];
        }

        var probes = ScanProbes.None;
        if (request.Probes is null || request.Probes.Length == 0)
        {
            errors["probes"] = ["Choose at least one probe: Icmp, Arp, Dns, Tcp or Snmp."];
        }
        else if (request.Probes.Length > MaxProbeEntries)
        {
            errors["probes"] = ["Too many probes in the request."];
        }
        else
        {
            foreach (var name in request.Probes)
            {
                if (!EnumParsing.TryParseName<ScanProbes>(name, out var probe) || probe == ScanProbes.None)
                {
                    errors["probes"] = [$"'{name}' is not a known probe. Use Icmp, Arp, Dns, Tcp or Snmp."];
                    break;
                }

                probes |= probe;
            }
        }

        if (errors.Count > 0)
        {
            return ServiceResult<ScanDetail>.Fail(ServiceErrors.Validation(errors));
        }

        var authorized = await db.AuthorizedRanges.AsNoTracking().Select(r => r.Range).ToListAsync(ct);
        var decision = ScanAuthorizationPolicy.Evaluate(target!, authorized, ScanTargetRules.MaxAddressesOrDefault(security.Value.MaxScanAddresses));

        if (!decision.IsAllowed)
        {
            audit.Add(
                "scan.denied",
                AuditOutcome.Denied,
                actor.Id,
                actor.Username,
                "scan",
                target!.ToString(),
                new { outcome = decision.Outcome.ToString(), target = target.ToString() });
            await db.SaveChangesAsync(ct);

            return decision.Outcome == ScanAuthorizationOutcome.NotAuthorized
                ? ServiceResult<ScanDetail>.Fail(ServiceErrors.Forbidden(decision.Reason!))
                : ServiceResult<ScanDetail>.Fail(ServiceErrors.Validation("target", decision.Reason!));
        }

        var run = ScanRun.Request(target!, probes, time.GetUtcNow(), actor.Id);
        db.ScanRuns.Add(run);
        audit.Add(
            "scan.requested",
            AuditOutcome.Success,
            actor.Id,
            actor.Username,
            "scan",
            run.Id.ToString(),
            new { target = target!.ToString(), probes = ProbeNames(run.Probes) });
        await db.SaveChangesAsync(ct);

        return ServiceResult<ScanDetail>.Ok(ToDetail(run));
    }

    public async Task<ServiceResult<ScanDetail>> GetAsync(Guid id, CancellationToken ct)
    {
        var run = await db.ScanRuns.AsNoTracking().SingleOrDefaultAsync(s => s.Id == id, ct);

        return run is null
            ? ServiceResult<ScanDetail>.Fail(ServiceErrors.NotFound("No such scan."))
            : ServiceResult<ScanDetail>.Ok(ToDetail(run));
    }

    public async Task<ServiceResult<IReadOnlyList<ScanDetail>>> ListAsync(string? status, int? limit, CancellationToken ct)
    {
        var take = limit ?? 50;
        if (take is < 1 or > 100)
        {
            return ServiceResult<IReadOnlyList<ScanDetail>>.Fail(ServiceErrors.Validation("limit", "The limit must be between 1 and 100."));
        }

        var query = db.ScanRuns.AsNoTracking();

        if (!string.IsNullOrWhiteSpace(status))
        {
            if (!EnumParsing.TryParseName<ScanStatus>(status, out var parsed))
            {
                return ServiceResult<IReadOnlyList<ScanDetail>>.Fail(ServiceErrors.Validation("status", "Unknown status."));
            }

            query = query.Where(s => s.Status == parsed);
        }

        var runs = await query.OrderByDescending(s => s.RequestedAt).ThenByDescending(s => s.Id).Take(take).ToListAsync(ct);
        return ServiceResult<IReadOnlyList<ScanDetail>>.Ok(runs.Select(ToDetail).ToList());
    }

    private static string[] ProbeNames(ScanProbes probes) =>
        Enum.GetValues<ScanProbes>().Where(p => p != ScanProbes.None && probes.HasFlag(p)).Select(p => p.ToString()).ToArray();

    private static ScanDetail ToDetail(ScanRun run) =>
        new(run.Id, run.Target.ToString(), ProbeNames(run.Probes), run.Status.ToString(), run.RequestedAt, run.StartedAt, run.FinishedAt, run.FailureReason, run.RequestedByUserId);
}
