using System.Net;
using Noema.Domain;

namespace Noema.Scanning;

/// <summary>
/// Runs one scan job: checks the target is allowed, expands it to addresses, and probes them with bounded
/// concurrency, a shared packet rate, a timeout per probe, and a stop when the setup is clearly broken.
/// Nothing is sent until the scope check passes.
/// </summary>
public sealed class ScanEngine
{
    private const int MaxErrorSamples = 5;

    private readonly IReadOnlyDictionary<ScanProbes, IProbe> probes;
    private readonly ScanScope scope;
    private readonly ScanEngineOptions options;
    private readonly IRateLimiter rateLimiter;
    private readonly TimeProvider time;

    public ScanEngine(
        IEnumerable<IProbe> probes,
        ScanScope scope,
        ScanEngineOptions options,
        IRateLimiter rateLimiter,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(probes);
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(rateLimiter);

        var problems = options.Validate();
        if (problems.Count > 0)
        {
            throw new ArgumentException(string.Join(" ", problems), nameof(options));
        }

        var registry = new Dictionary<ScanProbes, IProbe>();
        foreach (var probe in probes)
        {
            if (!registry.TryAdd(probe.Kind, probe))
            {
                throw new ArgumentException($"More than one probe is registered for {probe.Kind}.", nameof(probes));
            }
        }

        this.probes = registry;
        this.scope = scope;
        this.options = options;
        this.rateLimiter = rateLimiter;
        time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>The probes this engine can run.</summary>
    public ScanProbes AvailableProbes => probes.Keys.Aggregate(ScanProbes.None, (all, kind) => all | kind);

    public async Task<ScanSummary> RunAsync(
        ScanJob job,
        IObservationSink sink,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(job);
        ArgumentNullException.ThrowIfNull(sink);

        var startedAt = time.GetTimestamp();

        var decision = scope.Authorize(job.Target);
        if (!decision.IsAllowed)
        {
            return Refused(decision.Reason!, startedAt);
        }

        var selected = SelectProbes(job.Probes, out var problem);
        if (selected is null)
        {
            return Refused(problem!, startedAt);
        }

        var planned = (long)TargetExpander.Count(job.Target);
        var discovery = selected.Where(p => p.Phase == ProbePhase.Discovery).ToArray();
        var enrichment = selected.Where(p => p.Phase == ProbePhase.Enrichment).ToArray();

        var run = new Run(planned, sink, progress, discovery, enrichment);
        using var runCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        run.Stop = runCancellation;

        var wasCancelled = false;
        try
        {
            await Parallel.ForEachAsync(
                TargetExpander.Expand(job.Target, scope.MaxAddresses),
                new ParallelOptions { MaxDegreeOfParallelism = options.MaxConcurrency, CancellationToken = runCancellation.Token },
                (address, token) => ScanTargetAsync(run, address, token));
        }
        catch (OperationCanceledException)
        {
            wasCancelled = true;
        }

        var outcome = run.AbortReason is not null
            ? SweepOutcome.Failed
            : wasCancelled ? SweepOutcome.Cancelled : SweepOutcome.Completed;

        return new ScanSummary(
            outcome,
            run.AbortReason,
            planned,
            Interlocked.Read(ref run.Scanned),
            Interlocked.Read(ref run.Responded),
            Interlocked.Read(ref run.Written),
            Interlocked.Read(ref run.Errors),
            Interlocked.Read(ref run.Timeouts),
            time.GetElapsedTime(startedAt),
            run.Samples());
    }

    private IReadOnlyList<IProbe>? SelectProbes(ScanProbes requested, out string? problem)
    {
        problem = null;

        if (requested == ScanProbes.None)
        {
            problem = "No probes were requested.";
            return null;
        }

        var selected = new List<IProbe>();
        foreach (var kind in Enum.GetValues<ScanProbes>().Where(k => k != ScanProbes.None && requested.HasFlag(k)))
        {
            if (!probes.TryGetValue(kind, out var probe))
            {
                problem = $"This agent cannot run the {kind} probe.";
                return null;
            }

            selected.Add(probe);
        }

        var unknown = requested & ~Enum.GetValues<ScanProbes>().Aggregate(ScanProbes.None, (all, kind) => all | kind);
        if (unknown != ScanProbes.None)
        {
            problem = "The request contains probes this agent does not know.";
            return null;
        }

        return selected;
    }

    private async ValueTask ScanTargetAsync(Run run, IPAddress address, CancellationToken token)
    {
        var responded = false;
        var hostIsUp = run.Discovery.Length == 0;

        foreach (var probe in run.Discovery)
        {
            var result = await RunProbeAsync(run, probe, address, token).ConfigureAwait(false);
            if (result.Status == ProbeStatus.Responded)
            {
                hostIsUp = true;
                responded = true;
            }
        }

        if (hostIsUp)
        {
            foreach (var probe in run.Enrichment)
            {
                var result = await RunProbeAsync(run, probe, address, token).ConfigureAwait(false);
                responded |= result.Status == ProbeStatus.Responded;
            }
        }

        if (responded)
        {
            Interlocked.Increment(ref run.Responded);
        }

        var scanned = Interlocked.Increment(ref run.Scanned);
        ReportProgress(run, scanned);
    }

    private async ValueTask<ProbeResult> RunProbeAsync(Run run, IProbe probe, IPAddress address, CancellationToken token)
    {
        await rateLimiter.WaitAsync(token).ConfigureAwait(false);

        ProbeResult result;
        using var timeout = new CancellationTokenSource(options.ProbeTimeout + options.ProbeTimeoutGrace, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, timeout.Token);

        try
        {
            result = await probe.ProbeAsync(address, options.ProbeTimeout, linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            result = ProbeResult.TimedOut;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result = ProbeResult.Failure($"{probe.Kind} probe failed for {address}: {ex.Message}");
        }

        if (result.Status is ProbeStatus.Error or ProbeStatus.TimedOut)
        {
            RecordFailure(run, result, probe, address);
        }
        else
        {
            Interlocked.Exchange(ref run.ConsecutiveErrors, 0);
        }

        foreach (var observation in result.Observations)
        {
            await WriteAsync(run, observation, token).ConfigureAwait(false);
        }

        return result;
    }

    private void RecordFailure(Run run, ProbeResult result, IProbe probe, IPAddress address)
    {
        if (result.Status == ProbeStatus.TimedOut)
        {
            Interlocked.Increment(ref run.Timeouts);
        }

        Interlocked.Increment(ref run.Errors);
        var message = result.Status == ProbeStatus.TimedOut
            ? $"{probe.Kind} probe did not finish in time for {address}."
            : result.Error!;
        run.AddSample(message);

        if (Interlocked.Increment(ref run.ConsecutiveErrors) >= options.AbortAfterConsecutiveErrors)
        {
            run.Abort($"Stopped after {options.AbortAfterConsecutiveErrors} probe errors in a row. Last error: {message}");
        }
    }

    private static async ValueTask WriteAsync(Run run, ProbeObservation observation, CancellationToken token)
    {
        await run.SinkLock.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await run.Sink.WriteAsync(observation, token).ConfigureAwait(false);
            Interlocked.Increment(ref run.Written);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            run.Abort($"Could not store results: {ex.Message}");
        }
        finally
        {
            run.SinkLock.Release();
        }
    }

    private static void ReportProgress(Run run, long scanned)
    {
        if (run.Progress is null)
        {
            return;
        }

        try
        {
            run.Progress.Report(new ScanProgress(run.Planned, scanned, Interlocked.Read(ref run.Responded)));
        }
        catch (Exception)
        {
            // A faulty progress listener must never break a scan.
        }
    }

    private ScanSummary Refused(string reason, long startedAt) =>
        new(SweepOutcome.Refused, reason, 0, 0, 0, 0, 0, 0, time.GetElapsedTime(startedAt), []);

    private sealed class Run(
        long planned,
        IObservationSink sink,
        IProgress<ScanProgress>? progress,
        IProbe[] discovery,
        IProbe[] enrichment)
    {
        private readonly object sampleGate = new();
        private readonly List<string> samples = [];
        private string? abortReason;

        public long Planned { get; } = planned;

        public IObservationSink Sink { get; } = sink;

        public IProgress<ScanProgress>? Progress { get; } = progress;

        public IProbe[] Discovery { get; } = discovery;

        public IProbe[] Enrichment { get; } = enrichment;

        public SemaphoreSlim SinkLock { get; } = new(1, 1);

        public CancellationTokenSource Stop { get; set; } = null!;

        public long Scanned;
        public long Responded;
        public long Written;
        public long Errors;
        public long Timeouts;
        public int ConsecutiveErrors;

        public string? AbortReason => Volatile.Read(ref abortReason);

        public void Abort(string reason)
        {
            if (Interlocked.CompareExchange(ref abortReason, reason, null) is null)
            {
                Stop.Cancel();
            }
        }

        public void AddSample(string message)
        {
            lock (sampleGate)
            {
                if (samples.Count < MaxErrorSamples && !samples.Contains(message))
                {
                    samples.Add(message);
                }
            }
        }

        public IReadOnlyList<string> Samples()
        {
            lock (sampleGate)
            {
                return samples.ToArray();
            }
        }
    }
}
