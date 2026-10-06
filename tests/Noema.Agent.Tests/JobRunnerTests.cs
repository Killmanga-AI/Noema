using Microsoft.Extensions.Time.Testing;
using Noema.Agent.ControlPlane;
using Noema.Agent.Jobs;
using Noema.Contracts;
using Noema.Domain;
using Noema.Scanning;

namespace Noema.Agent.Tests;

public sealed class JobRunnerTests
{
    // Tests that drive the runner's report ticks with a fake clock give the engine the real clock. Otherwise advancing
    // fake time would also trip the engine's own per-probe timeouts and change what is being tested.

    private static JobRunner Runner(
        ScanEngine engine,
        FakeControlPlaneClient client,
        TimeProvider time,
        Action<JobRunnerOptions>? configure = null)
    {
        var options = new JobRunnerOptions
        {
            ReportInterval = TimeSpan.FromHours(1),
            BatchSize = 100,
            UploadAttempts = 3,
            RetryInitialDelay = TimeSpan.FromMilliseconds(1),
            RetryMaxDelay = TimeSpan.FromMilliseconds(2),
            FinalReportTimeout = TimeSpan.FromSeconds(5)
        };
        configure?.Invoke(options);

        return new JobRunner(engine, client, options, time, () => 0.0);
    }

    [Fact]
    public async Task A_finished_scan_uploads_everything_in_order_and_reports_how_it_ended()
    {
        var time = TimeProvider.System;
        var client = new FakeControlPlaneClient();
        var live = Enumerable.Range(1, 7).Select(i => $"192.168.1.{i}").ToArray();
        var engine = TestEngine.Create(FuncProbe.IcmpUp(time, live), time);
        var runner = Runner(engine, client, time, o => o.BatchSize = 3);
        var job = Jobs.Job("192.168.1.0/28");

        var outcome = await runner.RunAsync(job, CancellationToken.None);

        Assert.Equal(JobRunOutcome.Reported, outcome);
        Assert.Equal([1, 2, 3], client.Uploads.Select(u => u.Sequence));
        Assert.Equal([3, 3, 1], client.Uploads.Select(u => u.Observations.Length));
        Assert.Equal(live.Order(StringComparer.Ordinal), client.Uploads.SelectMany(u => u.Observations).Select(o => o.Address).Order(StringComparer.Ordinal));

        var (scanId, completion) = Assert.Single(client.Completes);
        Assert.Equal(job.ScanId, scanId);
        Assert.Equal("Completed", completion.Outcome);
        Assert.Equal(14, completion.TargetsPlanned);
        Assert.Equal(14, completion.TargetsScanned);
        Assert.Equal(7, completion.HostsResponded);
    }

    [Fact]
    public async Task Observations_are_sent_with_their_kind_address_time_and_detail()
    {
        var time = TimeProvider.System;
        var client = new FakeControlPlaneClient();
        var engine = TestEngine.Create(FuncProbe.IcmpUp(time, "192.168.1.5"), time);

        await Runner(engine, client, time).RunAsync(Jobs.Job("192.168.1.0/28"), CancellationToken.None);

        var observation = Assert.Single(client.Uploads.SelectMany(u => u.Observations));
        Assert.Equal("IcmpEchoReply", observation.Kind);
        Assert.Equal("192.168.1.5", observation.Address);
        Assert.Null(observation.MacAddress);
        Assert.Contains("rttMs", observation.DetailJson);
        Assert.True(Math.Abs((DateTimeOffset.UtcNow - observation.ObservedAt).TotalMinutes) < 1);
    }

    [Fact]
    public async Task A_scan_that_finds_nothing_uploads_nothing_and_still_completes()
    {
        var time = TimeProvider.System;
        var client = new FakeControlPlaneClient();
        var engine = TestEngine.Create(FuncProbe.IcmpUp(time), time);

        var outcome = await Runner(engine, client, time).RunAsync(Jobs.Job("192.168.1.0/28"), CancellationToken.None);

        Assert.Equal(JobRunOutcome.Reported, outcome);
        Assert.Empty(client.Uploads);
        Assert.Equal("Completed", Assert.Single(client.Completes).Request.Outcome);
    }

    [Fact]
    public async Task A_long_scan_reports_progress_and_findings_on_every_tick()
    {
        var time = new FakeTimeProvider();
        var client = new FakeControlPlaneClient();
        var release = new TaskCompletionSource();
        var started = new TaskCompletionSource();
        var seen = 0;
        var probe = new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, async (address, token) =>
        {
            if (Interlocked.Increment(ref seen) == 6)
            {
                started.TrySetResult();
                await release.Task.WaitAsync(token);
            }

            return ProbeResult.Responded(new ProbeObservation(ObservationKind.IcmpEchoReply, address, time.GetUtcNow()));
        });
        var engine = TestEngine.Create(probe, TimeProvider.System, concurrency: 1);
        var runner = Runner(engine, client, time, o => o.ReportInterval = TimeSpan.FromSeconds(5));

        var run = runner.RunAsync(Jobs.Job("192.168.1.0/28"), CancellationToken.None);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5));

        time.Advance(TimeSpan.FromSeconds(5));
        await Wait.UntilAsync(() => client.ProgressCalls >= 1, "the first progress report");

        Assert.True(client.Uploads.SelectMany(u => u.Observations).Count() >= 5);
        var (_, first) = client.Progress[0];
        Assert.Equal(14, first.TargetsPlanned);
        Assert.True(first.TargetsScanned >= 5);

        release.SetResult();
        Assert.Equal(JobRunOutcome.Reported, await run.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(14, client.Uploads.SelectMany(u => u.Observations).Count());
        Assert.Equal("Completed", Assert.Single(client.Completes).Request.Outcome);
    }

    [Fact]
    public async Task A_cancel_request_from_the_control_plane_stops_the_scan_and_it_is_reported_as_cancelled()
    {
        var time = new FakeTimeProvider();
        var client = new FakeControlPlaneClient { ProgressBehavior = (_, _) => new ProgressResponse(true, DateTimeOffset.UtcNow.AddMinutes(2)) };
        var entered = new TaskCompletionSource();
        var probe = new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, async (_, token) =>
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return ProbeResult.NoResponse;
        });
        var engine = TestEngine.Create(probe, TimeProvider.System, concurrency: 1);
        var runner = Runner(engine, client, time, o => o.ReportInterval = TimeSpan.FromSeconds(5));

        var run = runner.RunAsync(Jobs.Job("192.168.1.0/24"), CancellationToken.None);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        time.Advance(TimeSpan.FromSeconds(5));

        var outcome = await run.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(JobRunOutcome.Reported, outcome);
        Assert.Equal("Cancelled", Assert.Single(client.Completes).Request.Outcome);
    }

    [Fact]
    public async Task A_cancel_request_noticed_while_uploading_also_stops_the_scan()
    {
        var time = new FakeTimeProvider();
        var client = new FakeControlPlaneClient
        {
            UploadBehavior = (batch, _) => new ObservationBatchResponse(batch.Observations.Length, false, true, DateTimeOffset.UtcNow.AddMinutes(2))
        };
        var gate = new TaskCompletionSource();
        var seen = 0;
        var probe = new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, async (address, token) =>
        {
            if (Interlocked.Increment(ref seen) == 3)
            {
                await gate.Task.WaitAsync(token);
            }

            return ProbeResult.Responded(new ProbeObservation(ObservationKind.IcmpEchoReply, address, time.GetUtcNow()));
        });
        var engine = TestEngine.Create(probe, TimeProvider.System, concurrency: 1);
        var runner = Runner(engine, client, time, o => o.ReportInterval = TimeSpan.FromSeconds(5));

        var run = runner.RunAsync(Jobs.Job("192.168.1.0/24"), CancellationToken.None);
        await Wait.UntilAsync(() => seen >= 3, "the engine to reach the gate");
        time.Advance(TimeSpan.FromSeconds(5));

        var outcome = await run.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(JobRunOutcome.Reported, outcome);
        Assert.Equal("Cancelled", Assert.Single(client.Completes).Request.Outcome);
    }

    [Fact]
    public async Task Stopping_the_agent_mid_scan_stops_the_engine_and_reports_the_scan_as_failed()
    {
        var time = new FakeTimeProvider();
        var client = new FakeControlPlaneClient();
        var entered = new TaskCompletionSource();
        var probe = new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, async (_, token) =>
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return ProbeResult.NoResponse;
        });
        var engine = TestEngine.Create(probe, TimeProvider.System, concurrency: 1);
        var runner = Runner(engine, client, time);
        using var stopping = new CancellationTokenSource();

        var run = runner.RunAsync(Jobs.Job("192.168.1.0/24"), stopping.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await stopping.CancelAsync();

        var outcome = await run.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(JobRunOutcome.Stopped, outcome);
        var completion = Assert.Single(client.Completes).Request;
        Assert.Equal("Failed", completion.Outcome);
        Assert.Contains("agent was stopped", completion.Reason);
    }

    [Fact]
    public async Task A_transient_upload_failure_is_retried_with_the_same_batch_number()
    {
        var time = TimeProvider.System;
        var client = new FakeControlPlaneClient
        {
            UploadBehavior = (_, call) => call <= 2 ? throw Jobs.Fault(ControlPlaneErrorKind.Transient, "server busy") : null
        };
        var engine = TestEngine.Create(FuncProbe.IcmpUp(time, "192.168.1.5"), time);

        var outcome = await Runner(engine, client, time).RunAsync(Jobs.Job("192.168.1.0/28"), CancellationToken.None);

        Assert.Equal(JobRunOutcome.Reported, outcome);
        Assert.Equal(3, client.UploadCalls);
        Assert.All(client.Uploads, upload => Assert.Equal(1, upload.Sequence));
        Assert.Equal("Completed", Assert.Single(client.Completes).Request.Outcome);
    }

    [Fact]
    public async Task When_uploads_keep_failing_the_scan_is_reported_as_lost_contact_and_abandoned()
    {
        var time = TimeProvider.System;
        var client = new FakeControlPlaneClient
        {
            UploadBehavior = (_, _) => throw Jobs.Fault(ControlPlaneErrorKind.Transient, "down")
        };
        var engine = TestEngine.Create(FuncProbe.IcmpUp(time, "192.168.1.5"), time);

        var outcome = await Runner(engine, client, time).RunAsync(Jobs.Job("192.168.1.0/28"), CancellationToken.None);

        Assert.Equal(JobRunOutcome.Abandoned, outcome);
        Assert.Equal(3, client.UploadCalls);
        var completion = Assert.Single(client.Completes).Request;
        Assert.Equal("Failed", completion.Outcome);
        Assert.Contains("lost contact", completion.Reason);
    }

    [Fact]
    public async Task A_refused_credential_while_uploading_escapes_so_the_agent_can_stop()
    {
        var time = TimeProvider.System;
        var client = new FakeControlPlaneClient
        {
            UploadBehavior = (_, _) => throw Jobs.Fault(ControlPlaneErrorKind.Unauthorized)
        };
        var engine = TestEngine.Create(FuncProbe.IcmpUp(time, "192.168.1.5"), time);

        var thrown = await Assert.ThrowsAsync<ControlPlaneException>(() => Runner(engine, client, time).RunAsync(Jobs.Job("192.168.1.0/28"), CancellationToken.None));

        Assert.Equal(ControlPlaneErrorKind.Unauthorized, thrown.Kind);
        Assert.Equal(1, client.UploadCalls);
    }

    [Theory]
    [InlineData(ControlPlaneErrorKind.NotFound)]
    [InlineData(ControlPlaneErrorKind.Conflict)]
    public async Task A_scan_the_control_plane_no_longer_wants_is_abandoned_without_a_completion_call(ControlPlaneErrorKind kind)
    {
        var time = TimeProvider.System;
        var client = new FakeControlPlaneClient
        {
            UploadBehavior = (_, _) => throw Jobs.Fault(kind, "gone")
        };
        var engine = TestEngine.Create(FuncProbe.IcmpUp(time, "192.168.1.5"), time);

        var outcome = await Runner(engine, client, time).RunAsync(Jobs.Job("192.168.1.0/28"), CancellationToken.None);

        Assert.Equal(JobRunOutcome.Abandoned, outcome);
        Assert.Equal(0, client.CompleteCalls);
        Assert.Equal(1, client.UploadCalls);
    }

    [Fact]
    public async Task A_batch_the_control_plane_rejects_ends_the_scan_as_failed_with_the_reason()
    {
        var time = TimeProvider.System;
        var client = new FakeControlPlaneClient
        {
            UploadBehavior = (_, _) => throw Jobs.Fault(ControlPlaneErrorKind.Rejected, "clock is wrong")
        };
        var engine = TestEngine.Create(FuncProbe.IcmpUp(time, "192.168.1.5"), time);

        var outcome = await Runner(engine, client, time).RunAsync(Jobs.Job("192.168.1.0/28"), CancellationToken.None);

        Assert.Equal(JobRunOutcome.Reported, outcome);
        var completion = Assert.Single(client.Completes).Request;
        Assert.Equal("Failed", completion.Outcome);
        Assert.Contains("rejected", completion.Reason);
        Assert.Contains("clock is wrong", completion.Reason);
    }

    [Fact]
    public async Task A_progress_call_that_finds_the_scan_gone_abandons_it()
    {
        var time = new FakeTimeProvider();
        var client = new FakeControlPlaneClient { ProgressBehavior = (_, _) => throw Jobs.Fault(ControlPlaneErrorKind.Conflict, "scan is Failed") };
        var entered = new TaskCompletionSource();
        var probe = new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, async (_, token) =>
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return ProbeResult.NoResponse;
        });
        var engine = TestEngine.Create(probe, TimeProvider.System, concurrency: 1);
        var runner = Runner(engine, client, time, o => o.ReportInterval = TimeSpan.FromSeconds(5));

        var run = runner.RunAsync(Jobs.Job("192.168.1.0/24"), CancellationToken.None);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        time.Advance(TimeSpan.FromSeconds(5));

        Assert.Equal(JobRunOutcome.Abandoned, await run.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(0, client.CompleteCalls);
    }

    [Fact]
    public async Task A_scan_the_agent_refuses_is_reported_as_failed_with_the_reason()
    {
        var time = TimeProvider.System;
        var client = new FakeControlPlaneClient();
        var engine = TestEngine.Create(FuncProbe.IcmpUp(time), time, allowed: "10.0.0.0/8");

        var outcome = await Runner(engine, client, time).RunAsync(Jobs.Job("192.168.1.0/24"), CancellationToken.None);

        Assert.Equal(JobRunOutcome.Reported, outcome);
        var completion = Assert.Single(client.Completes).Request;
        Assert.Equal("Failed", completion.Outcome);
        Assert.Contains("not inside an authorized range", completion.Reason);
        Assert.Empty(client.Uploads);
    }

    [Theory]
    [InlineData("not-a-range", "Icmp")]
    [InlineData("192.168.1.0/24", "Teleport")]
    [InlineData("192.168.1.0/24", "3")]
    [InlineData("192.168.1.0/24", "None")]
    public async Task A_job_the_agent_cannot_understand_is_reported_as_failed_without_scanning(string target, string probe)
    {
        var time = TimeProvider.System;
        var client = new FakeControlPlaneClient();
        var icmp = FuncProbe.IcmpUp(time);
        var engine = TestEngine.Create(icmp, time);

        var outcome = await Runner(engine, client, time).RunAsync(Jobs.Job(target, probe), CancellationToken.None);

        Assert.Equal(JobRunOutcome.Reported, outcome);
        Assert.Equal("Failed", Assert.Single(client.Completes).Request.Outcome);
        Assert.Equal(0, icmp.Calls);
    }

    [Fact]
    public async Task A_completion_the_control_plane_no_longer_needs_is_not_an_error()
    {
        var time = TimeProvider.System;
        var client = new FakeControlPlaneClient { CompleteBehavior = (_, _) => Jobs.Fault(ControlPlaneErrorKind.Conflict, "already ended") };
        var engine = TestEngine.Create(FuncProbe.IcmpUp(time), time);

        var outcome = await Runner(engine, client, time).RunAsync(Jobs.Job("192.168.1.0/28"), CancellationToken.None);

        Assert.Equal(JobRunOutcome.Abandoned, outcome);
    }

    [Fact]
    public async Task A_completion_that_fails_transiently_is_retried()
    {
        var time = TimeProvider.System;
        var client = new FakeControlPlaneClient { CompleteBehavior = (_, call) => call == 1 ? Jobs.Fault(ControlPlaneErrorKind.Transient, "blip") : null };
        var engine = TestEngine.Create(FuncProbe.IcmpUp(time), time);

        var outcome = await Runner(engine, client, time).RunAsync(Jobs.Job("192.168.1.0/28"), CancellationToken.None);

        Assert.Equal(JobRunOutcome.Reported, outcome);
        Assert.Equal(2, client.CompleteCalls);
        Assert.Single(client.Completes);
    }

    [Fact]
    public async Task A_refused_credential_when_completing_escapes()
    {
        var time = TimeProvider.System;
        var client = new FakeControlPlaneClient { CompleteBehavior = (_, _) => Jobs.Fault(ControlPlaneErrorKind.Unauthorized) };
        var engine = TestEngine.Create(FuncProbe.IcmpUp(time), time);

        var thrown = await Assert.ThrowsAsync<ControlPlaneException>(() => Runner(engine, client, time).RunAsync(Jobs.Job("192.168.1.0/28"), CancellationToken.None));

        Assert.Equal(ControlPlaneErrorKind.Unauthorized, thrown.Kind);
    }

    [Fact]
    public async Task A_scan_that_aborts_on_probe_errors_is_reported_as_failed_with_the_cause()
    {
        var time = TimeProvider.System;
        var client = new FakeControlPlaneClient();
        var probe = new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, (_, _) => ValueTask.FromResult(ProbeResult.Failure("Operation not permitted")));
        var engine = new ScanEngine(
            [probe],
            new ScanScope([CidrRange.Parse("192.168.1.0/24")], 1024),
            new ScanEngineOptions { MaxConcurrency = 1, AbortAfterConsecutiveErrors = 5 },
            NoRateLimiter.Instance,
            time);

        await Runner(engine, client, time).RunAsync(Jobs.Job("192.168.1.0/24"), CancellationToken.None);

        var completion = Assert.Single(client.Completes).Request;
        Assert.Equal("Failed", completion.Outcome);
        Assert.Contains("Operation not permitted", completion.Reason);
    }

    [Fact]
    public void Engine_outcomes_map_to_what_the_control_plane_is_told()
    {
        ScanSummary Summary(SweepOutcome outcome, string? reason = null) => new(outcome, reason, 10, 8, 2, 2, 0, 0, TimeSpan.Zero, []);

        var completed = JobRunner.ToCompleteRequest(Summary(SweepOutcome.Completed), false);
        Assert.Equal("Completed", completed.Outcome);
        Assert.Equal(10, completed.TargetsPlanned);
        Assert.Equal(8, completed.TargetsScanned);
        Assert.Equal(2, completed.HostsResponded);

        Assert.Equal("Cancelled", JobRunner.ToCompleteRequest(Summary(SweepOutcome.Cancelled), false).Outcome);
        Assert.Equal("Failed", JobRunner.ToCompleteRequest(Summary(SweepOutcome.Cancelled), true).Outcome);
        Assert.Contains("agent was stopped", JobRunner.ToCompleteRequest(Summary(SweepOutcome.Cancelled), true).Reason);
        Assert.Equal("boom", JobRunner.ToCompleteRequest(Summary(SweepOutcome.Failed, "boom"), false).Reason);
        Assert.Equal("The scan failed.", JobRunner.ToCompleteRequest(Summary(SweepOutcome.Failed), false).Reason);
        Assert.Equal("nope", JobRunner.ToCompleteRequest(Summary(SweepOutcome.Refused, "nope"), false).Reason);
        Assert.Equal("Failed", JobRunner.ToCompleteRequest(Summary(SweepOutcome.Refused, "nope"), false).Outcome);
    }
}
