using System.Net;
using Microsoft.Extensions.Hosting;
using Noema.Agent.ControlPlane;
using Noema.Contracts;
using Noema.Domain;
using Noema.Scanning;

namespace Noema.Agent.Tests;

internal sealed class FuncProbe(
    ScanProbes kind,
    ProbePhase phase,
    Func<IPAddress, CancellationToken, ValueTask<ProbeResult>> run) : IProbe
{
    public int Calls;

    public ScanProbes Kind => kind;

    public ProbePhase Phase => phase;

    public ValueTask<ProbeResult> ProbeAsync(IPAddress target, TimeSpan timeout, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref Calls);
        return run(target, cancellationToken);
    }

    public static FuncProbe IcmpUp(TimeProvider time, params string[] live)
    {
        var hosts = live.Select(IPAddress.Parse).ToHashSet();
        return new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, (address, _) =>
            ValueTask.FromResult(hosts.Contains(address)
                ? ProbeResult.Responded(new ProbeObservation(ObservationKind.IcmpEchoReply, address, time.GetUtcNow(), DetailJson: "{\"rttMs\":1.0}"))
                : ProbeResult.NoResponse));
    }
}

internal static class TestEngine
{
    public static ScanEngine Create(IProbe probe, TimeProvider time, string allowed = "192.168.1.0/24", int concurrency = 4) =>
        new(
            [probe],
            new ScanScope([CidrRange.Parse(allowed)], 65_536),
            new ScanEngineOptions { MaxConcurrency = concurrency, AbortAfterConsecutiveErrors = 1000 },
            NoRateLimiter.Instance,
            time);
}

/// <summary>A control plane client that records what it is sent and can be told to fail.</summary>
internal sealed class FakeControlPlaneClient : IControlPlaneClient
{
    private readonly object gate = new();

    public List<ClaimRequest> Claims { get; } = [];

    public List<ObservationBatch> Uploads { get; } = [];

    public List<(Guid ScanId, ProgressRequest Request)> Progress { get; } = [];

    public List<(Guid ScanId, CompleteRequest Request)> Completes { get; } = [];

    public Queue<ClaimedJob?> Jobs { get; } = new();

    public Func<int, ClaimedJob?>? ClaimBehavior { get; set; }

    public Func<ObservationBatch, int, ObservationBatchResponse?>? UploadBehavior { get; set; }

    public Func<ProgressRequest, int, ProgressResponse?>? ProgressBehavior { get; set; }

    public Func<CompleteRequest, int, Exception?>? CompleteBehavior { get; set; }

    public int ClaimCalls;
    public int UploadCalls;
    public int ProgressCalls;
    public int CompleteCalls;

    public Task<ClaimedJob?> ClaimAsync(ClaimRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var call = Interlocked.Increment(ref ClaimCalls);
        lock (gate)
        {
            Claims.Add(request);
        }

        if (ClaimBehavior is not null)
        {
            return Task.FromResult(ClaimBehavior(call));
        }

        lock (gate)
        {
            return Task.FromResult(Jobs.Count > 0 ? Jobs.Dequeue() : null);
        }
    }

    public Task<ProgressResponse> ReportProgressAsync(Guid scanId, ProgressRequest request, CancellationToken cancellationToken)
    {
        var call = Interlocked.Increment(ref ProgressCalls);
        lock (gate)
        {
            Progress.Add((scanId, request));
        }

        var response = ProgressBehavior?.Invoke(request, call);
        return Task.FromResult(response ?? new ProgressResponse(false, DateTimeOffset.UtcNow.AddMinutes(2)));
    }

    public Task<ObservationBatchResponse> UploadObservationsAsync(Guid scanId, ObservationBatch batch, CancellationToken cancellationToken)
    {
        var call = Interlocked.Increment(ref UploadCalls);
        var response = UploadBehavior?.Invoke(batch, call);

        lock (gate)
        {
            Uploads.Add(batch);
        }

        return Task.FromResult(response ?? new ObservationBatchResponse(batch.Observations.Length, false, false, DateTimeOffset.UtcNow.AddMinutes(2)));
    }

    public Task CompleteAsync(Guid scanId, CompleteRequest request, CancellationToken cancellationToken)
    {
        var call = Interlocked.Increment(ref CompleteCalls);
        var fault = CompleteBehavior?.Invoke(request, call);
        if (fault is not null)
        {
            throw fault;
        }

        lock (gate)
        {
            Completes.Add((scanId, request));
        }

        return Task.CompletedTask;
    }
}

internal sealed class FakeLifetime : IHostApplicationLifetime
{
    public int StopCalls;

    public CancellationToken ApplicationStarted => CancellationToken.None;

    public CancellationToken ApplicationStopping => CancellationToken.None;

    public CancellationToken ApplicationStopped => CancellationToken.None;

    public void StopApplication() => Interlocked.Increment(ref StopCalls);
}

internal static class Wait
{
    public static async Task UntilAsync(Func<bool> condition, string what, int timeoutMilliseconds = 5000)
    {
        var deadline = Environment.TickCount64 + timeoutMilliseconds;
        while (!condition())
        {
            if (Environment.TickCount64 > deadline)
            {
                throw new TimeoutException($"Timed out waiting for {what}.");
            }

            await Task.Delay(5);
        }
    }
}

internal static class Jobs
{
    public static ClaimedJob Job(string target = "192.168.1.0/28", params string[] probes) =>
        new(Guid.NewGuid(), target, probes.Length == 0 ? ["Icmp"] : probes, DateTimeOffset.UtcNow.AddMinutes(2));

    public static ControlPlaneException Fault(ControlPlaneErrorKind kind, string message = "boom") => new(kind, message);
}
