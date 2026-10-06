using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Noema.Agent.ControlPlane;
using Noema.Contracts;
using Noema.Domain;
using Noema.Scanning;

namespace Noema.Agent.Jobs;

public enum JobRunOutcome
{
    /// <summary>The scan ran and the control plane was told how it ended.</summary>
    Reported,

    /// <summary>The control plane no longer wants this scan, or could not be reached to report. Nothing more to do.</summary>
    Abandoned,

    /// <summary>The agent was shutting down. The scan was stopped and reported as failed if the control plane could be reached.</summary>
    Stopped
}

public sealed class JobRunnerOptions
{
    /// <summary>How often a running scan sends its findings and progress. Each report also renews the scan's lease.</summary>
    public TimeSpan ReportInterval { get; set; } = TimeSpan.FromSeconds(5);

    public int BatchSize { get; set; } = AgentProtocol.MaxObservationsPerBatch;

    /// <summary>How many times one upload is tried when the network or server is having a bad moment.</summary>
    public int UploadAttempts { get; set; } = 3;

    public TimeSpan RetryInitialDelay { get; set; } = TimeSpan.FromSeconds(1);

    public TimeSpan RetryMaxDelay { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>How long the agent spends telling the control plane how a scan ended when it is already shutting down.</summary>
    public TimeSpan FinalReportTimeout { get; set; } = TimeSpan.FromSeconds(10);
}

/// <summary>
/// Runs one claimed scan from start to finish: runs the engine, ships findings and progress to the control plane
/// while it works, obeys a cancel request, and always tries to say how the scan ended.
/// </summary>
public sealed class JobRunner(
    ScanEngine engine,
    IControlPlaneClient client,
    JobRunnerOptions options,
    TimeProvider time,
    Func<double>? random = null,
    ILogger? logger = null)
{
    private readonly Func<double> nextRandom = random ?? (() => Random.Shared.NextDouble());
    private readonly ILogger log = logger ?? NullLogger.Instance;

    public async Task<JobRunOutcome> RunAsync(ClaimedJob job, CancellationToken stopping)
    {
        ArgumentNullException.ThrowIfNull(job);

        if (!CidrRange.TryParse(job.Target, out var target) || !TryParseProbes(job.Probes, out var probes))
        {
            await TryCompleteAsync(job.ScanId, Failed("The agent could not understand the job.", 0, 0, 0), stopping).ConfigureAwait(false);
            return JobRunOutcome.Reported;
        }

        var state = new RunState();
        var sink = new BufferingObservationSink();
        var progress = new ProgressTracker();
        using var runStop = CancellationTokenSource.CreateLinkedTokenSource(stopping);

        var engineTask = Task.Run(() => engine.RunAsync(new ScanJob(job.ScanId, target, probes), sink, progress, runStop.Token), CancellationToken.None);

        ControlPlaneException? failure = null;
        try
        {
            while (!engineTask.IsCompleted && !stopping.IsCancellationRequested)
            {
                using var tickStop = CancellationTokenSource.CreateLinkedTokenSource(stopping);
                var tick = Task.Delay(options.ReportInterval, time, tickStop.Token);
                await Task.WhenAny(engineTask, tick).ConfigureAwait(false);
                await tickStop.CancelAsync().ConfigureAwait(false);

                if (engineTask.IsCompleted || stopping.IsCancellationRequested)
                {
                    break;
                }

                await ReportAsync(job.ScanId, sink, progress, state, runStop, stopping).ConfigureAwait(false);
            }
        }
        catch (ControlPlaneException ex)
        {
            failure = ex;
            await runStop.CancelAsync().ConfigureAwait(false);
        }

        ScanSummary summary;
        try
        {
            summary = await engineTask.ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogError(ex, "The scan engine failed on scan {ScanId}", job.ScanId);
            summary = new ScanSummary(SweepOutcome.Failed, "The scan engine failed: " + ex.Message, 0, 0, 0, 0, 0, 0, TimeSpan.Zero, []);
        }

        var stoppedByHost = stopping.IsCancellationRequested;
        using var finalWindow = new CancellationTokenSource(options.FinalReportTimeout, time);
        var reportToken = stoppedByHost ? finalWindow.Token : stopping;

        if (failure is null)
        {
            try
            {
                await FlushAsync(job.ScanId, sink, state, reportToken).ConfigureAwait(false);
            }
            catch (ControlPlaneException ex)
            {
                failure = ex;
            }
        }

        if (failure is not null)
        {
            return await HandleFailureAsync(job.ScanId, failure, progress.Snapshot(), reportToken).ConfigureAwait(false);
        }

        var completion = ToCompleteRequest(summary, stoppedByHost);
        var outcome = await TryCompleteAsync(job.ScanId, completion, reportToken).ConfigureAwait(false);
        log.LogInformation("Scan {ScanId} ended as {Outcome}: {Scanned} addresses, {Responded} hosts answered", job.ScanId, completion.Outcome, completion.TargetsScanned, completion.HostsResponded);

        if (outcome == JobRunOutcome.Reported && stoppedByHost)
        {
            return JobRunOutcome.Stopped;
        }

        return outcome;
    }

    /// <summary>Turns how the engine ended into what the control plane is told.</summary>
    public static CompleteRequest ToCompleteRequest(ScanSummary summary, bool agentWasStopped)
    {
        ArgumentNullException.ThrowIfNull(summary);

        if (agentWasStopped && summary.Outcome == SweepOutcome.Cancelled)
        {
            return Failed("The agent was stopped before the scan finished.", summary.TargetsPlanned, summary.TargetsScanned, summary.HostsResponded);
        }

        return summary.Outcome switch
        {
            SweepOutcome.Completed => new CompleteRequest(AgentProtocol.OutcomeCompleted, null, summary.TargetsPlanned, summary.TargetsScanned, summary.HostsResponded),
            SweepOutcome.Cancelled => new CompleteRequest(AgentProtocol.OutcomeCancelled, null, summary.TargetsPlanned, summary.TargetsScanned, summary.HostsResponded),
            SweepOutcome.Refused => Failed(summary.Reason ?? "The agent refused the scan.", summary.TargetsPlanned, summary.TargetsScanned, summary.HostsResponded),
            _ => Failed(summary.Reason ?? "The scan failed.", summary.TargetsPlanned, summary.TargetsScanned, summary.HostsResponded)
        };
    }

    private async Task ReportAsync(
        Guid scanId,
        BufferingObservationSink sink,
        ProgressTracker progress,
        RunState state,
        CancellationTokenSource runStop,
        CancellationToken ct)
    {
        await FlushAsync(scanId, sink, state, ct).ConfigureAwait(false);

        var snapshot = progress.Snapshot();
        var request = new ProgressRequest(snapshot.TargetsPlanned, snapshot.TargetsScanned, snapshot.HostsResponded);
        var response = await RetryAsync(() => client.ReportProgressAsync(scanId, request, ct), ct).ConfigureAwait(false);

        if (response.CancelRequested || state.CancelRequested)
        {
            state.CancelRequested = true;
            log.LogInformation("Scan {ScanId} was cancelled from the control plane, stopping", scanId);
            await runStop.CancelAsync().ConfigureAwait(false);
        }
    }

    private async Task FlushAsync(Guid scanId, BufferingObservationSink sink, RunState state, CancellationToken ct)
    {
        while (sink.Count > 0)
        {
            var observations = sink.Take(options.BatchSize);
            if (observations.Count == 0)
            {
                return;
            }

            var batch = new ObservationBatch(++state.Sequence, observations.Select(ToDto).ToArray());
            var response = await RetryAsync(() => client.UploadObservationsAsync(scanId, batch, ct), ct).ConfigureAwait(false);
            state.CancelRequested |= response.CancelRequested;
        }
    }

    private async Task<JobRunOutcome> HandleFailureAsync(Guid scanId, ControlPlaneException failure, ScanProgress progress, CancellationToken ct)
    {
        switch (failure.Kind)
        {
            case ControlPlaneErrorKind.Unauthorized:
                throw failure;

            case ControlPlaneErrorKind.NotFound:
            case ControlPlaneErrorKind.Conflict:
                log.LogWarning("Scan {ScanId} is no longer wanted by the control plane: {Message}", scanId, failure.Message);
                return JobRunOutcome.Abandoned;

            case ControlPlaneErrorKind.Rejected:
                var reason = "The control plane rejected the results: " + failure.Message;
                await TryCompleteAsync(scanId, Failed(reason, progress.TargetsPlanned, progress.TargetsScanned, progress.HostsResponded), ct).ConfigureAwait(false);
                return JobRunOutcome.Reported;

            default:
                log.LogWarning("Lost contact with the control plane during scan {ScanId}: {Message}", scanId, failure.Message);
                await TryCompleteAsync(
                    scanId,
                    Failed("The agent lost contact with the control plane.", progress.TargetsPlanned, progress.TargetsScanned, progress.HostsResponded),
                    ct).ConfigureAwait(false);
                return JobRunOutcome.Abandoned;
        }
    }

    /// <summary>Reports the ending. Only a refused credential escapes, everything else is logged and the run is over either way.</summary>
    private async Task<JobRunOutcome> TryCompleteAsync(Guid scanId, CompleteRequest request, CancellationToken ct)
    {
        try
        {
            await RetryAsync(async () =>
            {
                await client.CompleteAsync(scanId, request, ct).ConfigureAwait(false);
                return true;
            }, ct).ConfigureAwait(false);

            return JobRunOutcome.Reported;
        }
        catch (ControlPlaneException ex) when (ex.Kind == ControlPlaneErrorKind.Unauthorized)
        {
            throw;
        }
        catch (ControlPlaneException ex) when (ex.Kind is ControlPlaneErrorKind.NotFound or ControlPlaneErrorKind.Conflict)
        {
            log.LogWarning("The control plane no longer needs the report for scan {ScanId}: {Message}", scanId, ex.Message);
            return JobRunOutcome.Abandoned;
        }
        catch (ControlPlaneException ex)
        {
            log.LogWarning("Could not tell the control plane how scan {ScanId} ended: {Message}", scanId, ex.Message);
            return JobRunOutcome.Abandoned;
        }
        catch (OperationCanceledException)
        {
            return JobRunOutcome.Abandoned;
        }
    }

    private async Task<T> RetryAsync<T>(Func<Task<T>> action, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await action().ConfigureAwait(false);
            }
            catch (ControlPlaneException ex) when (ex.Kind == ControlPlaneErrorKind.Transient && attempt < options.UploadAttempts)
            {
                var delay = Backoff.Delay(attempt, options.RetryInitialDelay, options.RetryMaxDelay, nextRandom());
                log.LogDebug("Retrying in {Delay} after: {Message}", delay, ex.Message);
                await Task.Delay(delay, time, ct).ConfigureAwait(false);
            }
        }
    }

    private static ObservationDto ToDto(ProbeObservation observation) =>
        new(
            observation.Kind.ToString(),
            observation.Address.ToString(),
            observation.ObservedAt,
            observation.MacAddress?.ToString(),
            observation.DetailJson);

    private static CompleteRequest Failed(string reason, long planned, long scanned, long responded) =>
        new(AgentProtocol.OutcomeFailed, reason, planned, scanned, responded);

    private static bool TryParseProbes(string[]? names, out ScanProbes probes)
    {
        probes = ScanProbes.None;

        foreach (var name in names ?? [])
        {
            if (!name.All(char.IsAsciiLetter) || !Enum.TryParse<ScanProbes>(name, ignoreCase: true, out var probe) || probe == ScanProbes.None)
            {
                return false;
            }

            probes |= probe;
        }

        return probes != ScanProbes.None;
    }

    private sealed class RunState
    {
        public int Sequence;
        public bool CancelRequested;
    }
}
