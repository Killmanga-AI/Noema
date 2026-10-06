using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Noema.Api.Common;
using Noema.Api.Security;
using Noema.Contracts;
using Noema.Domain;
using Noema.Infrastructure.Persistence;
using Noema.Infrastructure.Security;

namespace Noema.Api.Features.Agents;

/// <summary>
/// What agents talk to. Every call after enrollment is made as one specific agent and can only touch scans
/// assigned to that agent. A scan that is missing and a scan that belongs to someone else look identical.
/// </summary>
internal sealed class AgentProtocolService(
    NoemaDbContext db,
    IAuditWriter audit,
    IRequestContext request,
    IOptions<AgentFleetOptions> fleet,
    TimeProvider time)
{
    private const int MaxClaimAttempts = 3;
    private const int MaxSaveAttempts = 3;
    private const int CandidateScanWindow = 50;
    private const int MaxTextLength = 200;
    private static readonly TimeSpan ClockSkewAllowance = TimeSpan.FromMinutes(5);

    private TimeSpan Lease => fleet.Value.Lease;

    public async Task<ServiceResult<EnrollResponse>> EnrollAsync(EnrollRequest body, CancellationToken ct)
    {
        var errors = new Dictionary<string, string[]>();

        if (string.IsNullOrWhiteSpace(body.EnrollmentToken) || body.EnrollmentToken.Length > 100)
        {
            errors["enrollmentToken"] = ["An enrollment token is required."];
        }

        if (!Agent.IsValidName(body.AgentName))
        {
            errors["agentName"] = ["An agent name is 2 to 64 characters: letters, digits, dot, dash, underscore or space."];
        }

        var profile = ParseProfile(body.Version, body.OperatingSystem, body.Capabilities, body.ReportedRanges, errors);
        if (errors.Count > 0 || profile is null)
        {
            return ServiceResult<EnrollResponse>.Fail(ServiceErrors.Validation(errors));
        }

        var now = time.GetUtcNow();
        var hash = SecretTokens.Hash(body.EnrollmentToken.Trim());
        var token = await db.EnrollmentTokens.SingleOrDefaultAsync(t => t.TokenHash == hash, ct);

        if (token is null || !token.IsUsable(now))
        {
            // Unknown, used and expired tokens all get the same answer.
            audit.Add(
                "agent.enroll_failed",
                AuditOutcome.Denied,
                targetType: "agent",
                detail: new { reason = token is null ? "unknown_token" : token.IsUsed ? "token_used" : "token_expired" });
            await db.SaveChangesAsync(ct);
            return ServiceResult<EnrollResponse>.Fail(ServiceErrors.Unauthorized("The enrollment token is not valid."));
        }

        var secret = SecretTokens.NewAgentSecret();
        Agent agent;
        try
        {
            agent = Agent.Enroll(
                body.AgentName,
                SecretTokens.Hash(secret),
                now,
                profile.Version,
                profile.OperatingSystem,
                profile.Capabilities,
                profile.Ranges,
                request.RemoteAddress);
        }
        catch (ArgumentException ex)
        {
            // Nothing has been used up yet, so the token still works for a corrected request.
            return ServiceResult<EnrollResponse>.Fail(ServiceErrors.Validation("reportedRanges", ex.Message));
        }

        token.Redeem(agent.Id, now);
        db.Agents.Add(agent);
        audit.Add(
            "agent.enrolled",
            AuditOutcome.Success,
            actorName: "agent:" + agent.Name,
            targetType: "agent",
            targetId: agent.Id.ToString(),
            detail: new { tokenId = token.Id, capabilities = ScanProbeNames.ToNames(agent.Capabilities) });

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            // Another agent used the same token a moment earlier.
            return ServiceResult<EnrollResponse>.Fail(ServiceErrors.Unauthorized("The enrollment token is not valid."));
        }

        return ServiceResult<EnrollResponse>.Ok(new EnrollResponse(agent.Id, secret, agent.Name));
    }

    /// <summary>Checks in as a heartbeat and hands out the oldest queued scan this agent can serve, if any.</summary>
    public async Task<ServiceResult<ClaimedJob?>> ClaimAsync(CurrentAgent current, ClaimRequest body, CancellationToken ct)
    {
        var errors = new Dictionary<string, string[]>();
        var profile = ParseProfile(body.Version, body.OperatingSystem, body.Capabilities, body.ReportedRanges, errors);
        if (errors.Count > 0 || profile is null)
        {
            return ServiceResult<ClaimedJob?>.Fail(ServiceErrors.Validation(errors));
        }

        var now = time.GetUtcNow();
        var agent = await db.Agents.SingleOrDefaultAsync(a => a.Id == current.Id, ct);
        if (agent is null || agent.IsRevoked)
        {
            return ServiceResult<ClaimedJob?>.Fail(ServiceErrors.Unauthorized("The agent is not valid."));
        }

        try
        {
            agent.RecordContact(now, request.RemoteAddress, profile.Version, profile.OperatingSystem, profile.Capabilities, profile.Ranges);
        }
        catch (ArgumentException ex)
        {
            return ServiceResult<ClaimedJob?>.Fail(ServiceErrors.Validation("reportedRanges", ex.Message));
        }

        // An agent asking for work is idle, so a scan still marked running for it was lost when it restarted.
        var orphaned = await db.ScanRuns
            .Where(s => s.AssignedAgentId == agent.Id && s.Status == ScanStatus.Running)
            .ToListAsync(ct);

        foreach (var scan in orphaned)
        {
            scan.Abandon(now, "The agent restarted before the scan finished.");
            audit.Add("scan.abandoned", AuditOutcome.Failure, actorName: "agent:" + agent.Name, targetType: "scan", targetId: scan.Id.ToString());
        }

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            db.ChangeTracker.Clear();
            var stillValid = await db.Agents.AsNoTracking().AnyAsync(a => a.Id == current.Id && a.Status == AgentStatus.Active, ct);
            return stillValid
                ? ServiceResult<ClaimedJob?>.Fail(ServiceErrors.Unavailable("Busy, try again."))
                : ServiceResult<ClaimedJob?>.Fail(ServiceErrors.Unauthorized("The agent is not valid."));
        }

        for (var attempt = 0; attempt < MaxClaimAttempts; attempt++)
        {
            var candidates = await db.ScanRuns
                .Where(s => s.Status == ScanStatus.Queued && (s.RequestedAgentId == null || s.RequestedAgentId == agent.Id))
                .OrderBy(s => s.RequestedAt).ThenBy(s => s.Id)
                .Take(CandidateScanWindow)
                .ToListAsync(ct);

            var match = candidates.FirstOrDefault(s => agent.CanServe(s.Target, s.Probes));
            if (match is null)
            {
                return ServiceResult<ClaimedJob?>.Ok(null);
            }

            match.Claim(agent.Id, now, Lease);
            audit.Add(
                "scan.claimed",
                AuditOutcome.Success,
                actorName: "agent:" + agent.Name,
                targetType: "scan",
                targetId: match.Id.ToString(),
                detail: new { target = match.Target.ToString() });

            try
            {
                await db.SaveChangesAsync(ct);
                return ServiceResult<ClaimedJob?>.Ok(
                    new ClaimedJob(match.Id, match.Target.ToString(), ScanProbeNames.ToNames(match.Probes), match.LeaseExpiresAt!.Value));
            }
            catch (DbUpdateConcurrencyException)
            {
                // Another agent took it, or it was cancelled, in the same instant. Look again.
                db.ChangeTracker.Clear();
                agent = await db.Agents.SingleOrDefaultAsync(a => a.Id == current.Id, ct);
                if (agent is null || agent.IsRevoked)
                {
                    return ServiceResult<ClaimedJob?>.Fail(ServiceErrors.Unauthorized("The agent is not valid."));
                }
            }
        }

        return ServiceResult<ClaimedJob?>.Ok(null);
    }

    public Task<ServiceResult<ProgressResponse>> ReportProgressAsync(CurrentAgent current, Guid scanId, ProgressRequest body, CancellationToken ct) =>
        WithScanAsync<ProgressResponse>(current, scanId, ct, (scan, now) =>
        {
            try
            {
                scan.ReportProgress(current.Id, now, Lease, body.TargetsPlanned, body.TargetsScanned, body.HostsResponded);
            }
            catch (ArgumentException ex)
            {
                return ServiceResult<ProgressResponse>.Fail(ServiceErrors.Validation("progress", ex.Message));
            }

            return null;
        },
        scan => new ProgressResponse(scan.IsCancelRequested, scan.LeaseExpiresAt!.Value));

    public async Task<ServiceResult<ObservationBatchResponse>> UploadObservationsAsync(
        CurrentAgent current, Guid scanId, ObservationBatch body, CancellationToken ct)
    {
        if (body.Sequence < 1)
        {
            return ServiceResult<ObservationBatchResponse>.Fail(ServiceErrors.Validation("sequence", "Batches are numbered from 1."));
        }

        if (body.Observations is null || body.Observations.Length is < 1 or > AgentProtocol.MaxObservationsPerBatch)
        {
            return ServiceResult<ObservationBatchResponse>.Fail(ServiceErrors.Validation(
                "observations", $"Send between 1 and {AgentProtocol.MaxObservationsPerBatch} observations per batch."));
        }

        var accepted = 0;
        var duplicate = false;

        return await WithScanAsync<ObservationBatchResponse>(current, scanId, ct, (scan, now) =>
        {
            var parsed = new List<Observation>(body.Observations.Length);

            for (var i = 0; i < body.Observations.Length; i++)
            {
                var problem = TryBuild(scan, body.Observations[i], now, out var observation);
                if (problem is not null)
                {
                    return ServiceResult<ObservationBatchResponse>.Fail(ServiceErrors.Validation($"observations[{i}]", problem));
                }

                parsed.Add(observation!);
            }

            BatchDisposition disposition;
            try
            {
                disposition = scan.AcceptBatch(current.Id, body.Sequence, now, Lease);
            }
            catch (InvalidOperationException ex)
            {
                return ServiceResult<ObservationBatchResponse>.Fail(ServiceErrors.Conflict(ex.Message));
            }

            duplicate = disposition == BatchDisposition.Duplicate;
            accepted = duplicate ? 0 : parsed.Count;

            if (!duplicate)
            {
                db.Observations.AddRange(parsed);
            }

            return null;
        },
        scan => new ObservationBatchResponse(accepted, duplicate, scan.IsCancelRequested, scan.LeaseExpiresAt!.Value));
    }

    public async Task<ServiceResult<Unit>> CompleteAsync(CurrentAgent current, Guid scanId, CompleteRequest body, CancellationToken ct)
    {
        if (!TryParseOutcome(body.Outcome, out var outcome))
        {
            return ServiceResult<Unit>.Fail(ServiceErrors.Validation("outcome", "Use Completed, Failed or Cancelled."));
        }

        if (outcome == ScanStatus.Failed && string.IsNullOrWhiteSpace(body.Reason))
        {
            return ServiceResult<Unit>.Fail(ServiceErrors.Validation("reason", "A failed scan needs a reason."));
        }

        for (var attempt = 0; attempt < MaxSaveAttempts; attempt++)
        {
            var scan = await db.ScanRuns.SingleOrDefaultAsync(s => s.Id == scanId && s.AssignedAgentId == current.Id, ct);
            if (scan is null)
            {
                return ServiceResult<Unit>.Fail(ServiceErrors.NotFound("No such scan."));
            }

            // A repeat of the same ending, for example after a lost reply, is fine.
            if (scan.IsTerminal)
            {
                return scan.Status == outcome
                    ? ServiceResult<Unit>.Ok(default)
                    : ServiceResult<Unit>.Fail(ServiceErrors.Conflict($"The scan already ended as {scan.Status}."));
            }

            if (scan.Status != ScanStatus.Running)
            {
                return ServiceResult<Unit>.Fail(ServiceErrors.Conflict($"The scan is {scan.Status}, not running."));
            }

            var now = time.GetUtcNow();

            try
            {
                scan.ReportProgress(current.Id, now, Lease, body.TargetsPlanned, body.TargetsScanned, body.HostsResponded);
            }
            catch (ArgumentException)
            {
                // Final counts that do not add up are not worth refusing the ending for.
            }

            switch (outcome)
            {
                case ScanStatus.Completed:
                    scan.Complete(now);
                    break;
                case ScanStatus.Failed:
                    scan.Fail(body.Reason!, now);
                    break;
                default:
                    scan.Cancel(now);
                    break;
            }

            audit.Add(
                "scan." + outcome.ToString().ToLowerInvariant(),
                outcome == ScanStatus.Completed ? AuditOutcome.Success : AuditOutcome.Failure,
                actorName: "agent:" + current.Name,
                targetType: "scan",
                targetId: scan.Id.ToString(),
                detail: new { scan.TargetsScanned, scan.HostsResponded });

            try
            {
                await db.SaveChangesAsync(ct);
                return ServiceResult<Unit>.Ok(default);
            }
            catch (DbUpdateConcurrencyException)
            {
                db.ChangeTracker.Clear();
            }
        }

        return ServiceResult<Unit>.Fail(ServiceErrors.Unavailable("Busy, try again."));
    }

    /// <summary>
    /// Loads a scan that belongs to the calling agent and is running, applies a change, and saves.
    /// Retries when a cancel request or another update lands at the same instant.
    /// </summary>
    private async Task<ServiceResult<T>> WithScanAsync<T>(
        CurrentAgent current,
        Guid scanId,
        CancellationToken ct,
        Func<ScanRun, DateTimeOffset, ServiceResult<T>?> apply,
        Func<ScanRun, T> result)
    {
        for (var attempt = 0; attempt < MaxSaveAttempts; attempt++)
        {
            var scan = await db.ScanRuns.SingleOrDefaultAsync(s => s.Id == scanId && s.AssignedAgentId == current.Id, ct);
            if (scan is null)
            {
                return ServiceResult<T>.Fail(ServiceErrors.NotFound("No such scan."));
            }

            if (scan.Status != ScanStatus.Running)
            {
                return ServiceResult<T>.Fail(ServiceErrors.Conflict($"The scan is {scan.Status}, not running."));
            }

            var failure = apply(scan, time.GetUtcNow());
            if (failure is not null)
            {
                return failure;
            }

            try
            {
                await db.SaveChangesAsync(ct);
                return ServiceResult<T>.Ok(result(scan));
            }
            catch (DbUpdateConcurrencyException)
            {
                db.ChangeTracker.Clear();
            }
        }

        return ServiceResult<T>.Fail(ServiceErrors.Unavailable("Busy, try again."));
    }

    private static string? TryBuild(ScanRun scan, ObservationDto dto, DateTimeOffset now, out Observation? observation)
    {
        observation = null;

        if (!EnumParsing.TryParseName<ObservationKind>(dto.Kind, out var kind))
        {
            return "Unknown observation kind.";
        }

        if (string.IsNullOrWhiteSpace(dto.Address) || dto.Address.Length > 64 || !IPAddress.TryParse(dto.Address, out var address))
        {
            return "The address is not a valid IP address.";
        }

        if (!IpAddressNormalizer.IsAssignable(address) || !scan.Target.Contains(address))
        {
            return "The address is outside the scan target.";
        }

        MacAddress? mac = null;
        if (!string.IsNullOrWhiteSpace(dto.MacAddress))
        {
            if (!MacAddress.TryParse(dto.MacAddress, out var parsedMac))
            {
                return "The MAC address is not valid.";
            }

            mac = parsedMac;
        }

        var earliest = (scan.StartedAt ?? scan.RequestedAt) - ClockSkewAllowance;
        if (dto.ObservedAt.Offset != TimeSpan.Zero || dto.ObservedAt < earliest || dto.ObservedAt > now + ClockSkewAllowance)
        {
            return "The observation time is not UTC or is outside the scan window. Check that the agent's clock is correct.";
        }

        try
        {
            observation = Observation.Create(scan.Id, kind, address, dto.ObservedAt, mac, dto.DetailJson);
            return null;
        }
        catch (ArgumentException ex)
        {
            return ex.Message;
        }
    }

    private static bool TryParseOutcome(string? text, out ScanStatus status)
    {
        status = ScanStatus.Failed;

        return text switch
        {
            AgentProtocol.OutcomeCompleted => Set(ScanStatus.Completed, out status),
            AgentProtocol.OutcomeFailed => Set(ScanStatus.Failed, out status),
            AgentProtocol.OutcomeCancelled => Set(ScanStatus.Cancelled, out status),
            _ => false
        };

        static bool Set(ScanStatus value, out ScanStatus target)
        {
            target = value;
            return true;
        }
    }

    private sealed record Profile(string? Version, string? OperatingSystem, ScanProbes Capabilities, List<CidrRange> Ranges);

    private static Profile? ParseProfile(
        string? version,
        string? operatingSystem,
        string[]? capabilities,
        string[]? reportedRanges,
        Dictionary<string, string[]> errors)
    {
        if (version is { Length: > MaxTextLength })
        {
            errors["version"] = ["The version text is too long."];
        }

        if (operatingSystem is { Length: > MaxTextLength })
        {
            errors["operatingSystem"] = ["The operating system text is too long."];
        }

        var probes = ScanProbeNames.TryParse(capabilities, 16, out var probeProblem);
        if (probes is null)
        {
            errors["capabilities"] = [probeProblem!];
        }

        var ranges = new List<CidrRange>();
        if ((reportedRanges?.Length ?? 0) > Agent.MaxReportedRanges)
        {
            errors["reportedRanges"] = [$"Report at most {Agent.MaxReportedRanges} ranges."];
        }
        else
        {
            foreach (var text in reportedRanges ?? [])
            {
                if (!CidrRange.TryParse(text, out var range))
                {
                    errors["reportedRanges"] = [$"'{text}' is not a valid range."];
                    break;
                }

                ranges.Add(range);
            }
        }

        return errors.Count > 0 || probes is null ? null : new Profile(version, operatingSystem, probes.Value, ranges);
    }
}
