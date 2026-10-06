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

        Agent? pinned = null;
        if (request.AgentId is { } agentId)
        {
            pinned = await db.Agents.AsNoTracking().SingleOrDefaultAsync(a => a.Id == agentId, ct);
            if (pinned is null || pinned.IsRevoked)
            {
                return ServiceResult<ScanDetail>.Fail(ServiceErrors.Validation("agentId", "That agent does not exist or has been revoked."));
            }

            if (!pinned.CanServe(target!, probes))
            {
                return ServiceResult<ScanDetail>.Fail(ServiceErrors.Validation(
                    "agentId", "That agent does not cover this target or does not have these probes."));
            }
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

        var run = ScanRun.Request(target!, probes, time.GetUtcNow(), actor.Id, pinned?.Id);
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

    public async Task<ServiceResult<ScanDetail>> CancelAsync(CurrentUser actor, Guid id, CancellationToken ct)
    {
        var run = await db.ScanRuns.SingleOrDefaultAsync(s => s.Id == id, ct);
        if (run is null)
        {
            return ServiceResult<ScanDetail>.Fail(ServiceErrors.NotFound("No such scan."));
        }

        if (run.IsTerminal)
        {
            return ServiceResult<ScanDetail>.Fail(ServiceErrors.Conflict($"The scan has already ended as {run.Status}."));
        }

        var wasRunning = run.Status == ScanStatus.Running;
        run.RequestCancel(time.GetUtcNow());
        audit.Add("scan.cancel_requested", AuditOutcome.Success, actor.Id, actor.Username, "scan", run.Id.ToString(), new { wasRunning });

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            return ServiceResult<ScanDetail>.Fail(ServiceErrors.Conflict("The scan changed at the same moment. Look at it again and retry."));
        }

        return ServiceResult<ScanDetail>.Ok(ToDetail(run));
    }

    public async Task<ServiceResult<IReadOnlyList<ObservationDetail>>> ObservationsAsync(Guid scanId, Guid? after, int? limit, CancellationToken ct)
    {
        var take = limit ?? 100;
        if (take is < 1 or > 200)
        {
            return ServiceResult<IReadOnlyList<ObservationDetail>>.Fail(ServiceErrors.Validation("limit", "The limit must be between 1 and 200."));
        }

        if (!await db.ScanRuns.AsNoTracking().AnyAsync(s => s.Id == scanId, ct))
        {
            return ServiceResult<IReadOnlyList<ObservationDetail>>.Fail(ServiceErrors.NotFound("No such scan."));
        }

        // Ids are time ordered, so paging by id walks the observations in the order they were seen.
        // Postgres compares uuids itself, which is why the cursor query is written in SQL.
        var items = after is { } cursor
            ? await db.Observations
                .FromSqlInterpolated($"SELECT * FROM observations WHERE scan_run_id = {scanId} AND id > {cursor} ORDER BY id LIMIT {take}")
                .AsNoTracking()
                .OrderBy(o => o.Id)
                .ToListAsync(ct)
            : await db.Observations.AsNoTracking().Where(o => o.ScanRunId == scanId).OrderBy(o => o.Id).Take(take).ToListAsync(ct);

        IReadOnlyList<ObservationDetail> mapped = items
            .Select(o => new ObservationDetail(o.Id, o.Kind.ToString(), o.Address.ToString(), o.MacAddress?.ToString(), o.ObservedAt, o.DetailJson))
            .ToList();

        return ServiceResult<IReadOnlyList<ObservationDetail>>.Ok(mapped);
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

    private static string[] ProbeNames(ScanProbes probes) => ScanProbeNames.ToNames(probes);

    private static ScanDetail ToDetail(ScanRun run) =>
        new(
            run.Id,
            run.Target.ToString(),
            ProbeNames(run.Probes),
            run.Status.ToString(),
            run.RequestedAt,
            run.StartedAt,
            run.FinishedAt,
            run.FailureReason,
            run.RequestedByUserId,
            run.RequestedAgentId,
            run.AssignedAgentId,
            run.IsCancelRequested,
            run.TargetsPlanned,
            run.TargetsScanned,
            run.HostsResponded);
}
