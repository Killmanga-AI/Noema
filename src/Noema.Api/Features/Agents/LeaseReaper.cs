using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Noema.Api.Security;
using Noema.Domain;
using Noema.Infrastructure.Persistence;

namespace Noema.Api.Features.Agents;

/// <summary>
/// Cleans up scans that nobody is working on. A running scan whose agent stopped reporting is failed, and a
/// queued scan that no agent claimed in time is failed too, so nothing sits in limbo forever.
/// </summary>
internal sealed class LeaseReaper(
    IServiceScopeFactory scopeFactory,
    IOptions<AgentFleetOptions> fleet,
    TimeProvider time,
    ILogger<LeaseReaper> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(fleet.Value.ReaperIntervalSeconds), time);

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                try
                {
                    var reaped = await ReapOnceAsync(time.GetUtcNow(), stoppingToken);
                    if (reaped > 0)
                    {
                        logger.LogWarning("Ended {Count} scans that nobody was working on", reaped);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogError(ex, "Cleaning up abandoned scans failed, will try again");
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal shutdown.
        }
    }

    /// <summary>One pass. Returns how many scans were ended. Public so tests can run it at a chosen moment.</summary>
    public async Task<int> ReapOnceAsync(DateTimeOffset now, CancellationToken ct)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<NoemaDbContext>();
        var audit = scope.ServiceProvider.GetRequiredService<IAuditWriter>();

        var lost = await db.ScanRuns
            .Where(s => s.Status == ScanStatus.Running && s.LeaseExpiresAt != null && s.LeaseExpiresAt < now)
            .ToListAsync(ct);

        foreach (var scan in lost)
        {
            scan.Abandon(now, "The agent stopped reporting before the scan finished.");
            audit.Add("scan.abandoned", AuditOutcome.Failure, targetType: "scan", targetId: scan.Id.ToString(), detail: new { reason = "lease_expired" });
        }

        var queueCutoff = now - TimeSpan.FromMinutes(fleet.Value.QueuedScanExpiryMinutes);
        var stale = await db.ScanRuns
            .Where(s => s.Status == ScanStatus.Queued && s.RequestedAt < queueCutoff)
            .ToListAsync(ct);

        foreach (var scan in stale)
        {
            scan.Fail("No agent picked up the scan in time.", now);
            audit.Add("scan.expired", AuditOutcome.Failure, targetType: "scan", targetId: scan.Id.ToString(), detail: new { reason = "unclaimed" });
        }

        if (lost.Count + stale.Count == 0)
        {
            return 0;
        }

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            // An agent reported in at the same moment. It is alive after all, the next pass will look again.
            return 0;
        }

        return lost.Count + stale.Count;
    }
}
