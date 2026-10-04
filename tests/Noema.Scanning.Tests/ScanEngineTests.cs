using System.Net;
using Microsoft.Extensions.Time.Testing;
using Noema.Domain;

namespace Noema.Scanning.Tests;

public sealed class ScanEngineTests
{
    private static readonly Guid RunId = Guid.NewGuid();

    private sealed class ListSink : IObservationSink
    {
        private readonly object gate = new();
        public List<ProbeObservation> Items { get; } = [];
        public int ConcurrentWrites;
        public int MaxConcurrentWrites;

        public async ValueTask WriteAsync(ProbeObservation observation, CancellationToken cancellationToken)
        {
            var now = Interlocked.Increment(ref ConcurrentWrites);
            lock (gate)
            {
                MaxConcurrentWrites = Math.Max(MaxConcurrentWrites, now);
            }

            await Task.Yield();
            lock (gate)
            {
                Items.Add(observation);
            }

            Interlocked.Decrement(ref ConcurrentWrites);
        }
    }

    private sealed class FuncProbe(
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
    }

    private sealed class CountingLimiter : IRateLimiter
    {
        public int Waits;

        public ValueTask WaitAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref Waits);
            return ValueTask.CompletedTask;
        }
    }

    private static ProbeObservation Echo(IPAddress address, TimeProvider time) =>
        new(ObservationKind.IcmpEchoReply, address, time.GetUtcNow());

    private static FuncProbe IcmpUp(TimeProvider time, params string[] liveHosts)
    {
        var live = liveHosts.Select(IPAddress.Parse).ToHashSet();
        return new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, (address, _) =>
            ValueTask.FromResult(live.Contains(address) ? ProbeResult.Responded(Echo(address, time)) : ProbeResult.NoResponse));
    }

    private static ScanEngine Engine(
        FuncProbe[] probes,
        FakeTimeProvider time,
        string allowed = "192.168.1.0/24",
        int maxAddresses = 1024,
        IRateLimiter? limiter = null,
        Action<ScanEngineOptions>? configure = null)
    {
        var options = new ScanEngineOptions { MaxConcurrency = 8, AbortAfterConsecutiveErrors = 5 };
        configure?.Invoke(options);

        return new ScanEngine(probes, new ScanScope([CidrRange.Parse(allowed)], maxAddresses), options, limiter ?? NoRateLimiter.Instance, time);
    }

    private static ScanJob Job(string target, ScanProbes probes = ScanProbes.Icmp) => new(RunId, CidrRange.Parse(target), probes);

    [Fact]
    public async Task Finds_the_hosts_that_answer_and_reports_the_scan()
    {
        var time = new FakeTimeProvider();
        var sink = new ListSink();
        var engine = Engine([IcmpUp(time, "192.168.1.1", "192.168.1.50", "192.168.1.200")], time);

        var summary = await engine.RunAsync(Job("192.168.1.0/24"), sink);

        Assert.Equal(SweepOutcome.Completed, summary.Outcome);
        Assert.Null(summary.Reason);
        Assert.Equal(254, summary.TargetsPlanned);
        Assert.Equal(254, summary.TargetsScanned);
        Assert.Equal(3, summary.HostsResponded);
        Assert.Equal(3, summary.Observations);
        Assert.Equal(0, summary.ProbeErrors);
        Assert.Equal(
            ["192.168.1.1", "192.168.1.200", "192.168.1.50"],
            sink.Items.Select(o => o.Address.ToString()).OrderBy(a => a, StringComparer.Ordinal).ToList());
    }

    [Fact]
    public async Task Nothing_is_sent_when_the_target_is_outside_the_agents_scope()
    {
        var time = new FakeTimeProvider();
        var probe = IcmpUp(time);
        var sink = new ListSink();
        var engine = Engine([probe], time, allowed: "192.168.1.0/24");

        var summary = await engine.RunAsync(Job("10.0.0.0/24"), sink);

        Assert.Equal(SweepOutcome.Refused, summary.Outcome);
        Assert.NotNull(summary.Reason);
        Assert.Equal(0, probe.Calls);
        Assert.Empty(sink.Items);
    }

    [Theory]
    [InlineData("127.0.0.0/24")]
    [InlineData("224.0.0.0/24")]
    public async Task Reserved_targets_are_refused_even_if_the_scope_covers_them(string target)
    {
        var time = new FakeTimeProvider();
        var probe = IcmpUp(time);
        var engine = Engine([probe], time, allowed: "0.0.0.0/0");

        var summary = await engine.RunAsync(Job(target), new ListSink());

        Assert.Equal(SweepOutcome.Refused, summary.Outcome);
        Assert.Equal(0, probe.Calls);
    }

    [Fact]
    public async Task Targets_over_the_size_limit_are_refused_without_sending()
    {
        var time = new FakeTimeProvider();
        var probe = IcmpUp(time);
        var engine = Engine([probe], time, allowed: "192.168.0.0/16", maxAddresses: 100);

        var summary = await engine.RunAsync(Job("192.168.1.0/24"), new ListSink());

        Assert.Equal(SweepOutcome.Refused, summary.Outcome);
        Assert.Equal(0, probe.Calls);
    }

    [Fact]
    public async Task Requests_for_probes_the_agent_does_not_have_are_refused()
    {
        var time = new FakeTimeProvider();
        var probe = IcmpUp(time);
        var engine = Engine([probe], time);

        var summary = await engine.RunAsync(Job("192.168.1.0/24", ScanProbes.Icmp | ScanProbes.Snmp), new ListSink());

        Assert.Equal(SweepOutcome.Refused, summary.Outcome);
        Assert.Contains("Snmp", summary.Reason);
        Assert.Equal(0, probe.Calls);
    }

    [Fact]
    public async Task A_request_with_no_probes_is_refused()
    {
        var time = new FakeTimeProvider();
        var engine = Engine([IcmpUp(time)], time);

        var summary = await engine.RunAsync(Job("192.168.1.0/24", ScanProbes.None), new ListSink());

        Assert.Equal(SweepOutcome.Refused, summary.Outcome);
    }

    [Fact]
    public async Task Enrichment_probes_only_run_against_hosts_that_answered_discovery()
    {
        var time = new FakeTimeProvider();
        var seen = new List<string>();
        var enrich = new FuncProbe(ScanProbes.Dns, ProbePhase.Enrichment, (address, _) =>
        {
            lock (seen)
            {
                seen.Add(address.ToString());
            }

            return ValueTask.FromResult(ProbeResult.Responded(
                new ProbeObservation(ObservationKind.ReverseDnsName, address, time.GetUtcNow(), DetailJson: "{\"name\":\"host\"}")));
        });
        var sink = new ListSink();
        var engine = Engine([IcmpUp(time, "192.168.1.5", "192.168.1.9"), enrich], time);

        var summary = await engine.RunAsync(Job("192.168.1.0/24", ScanProbes.Icmp | ScanProbes.Dns), sink);

        Assert.Equal(["192.168.1.5", "192.168.1.9"], seen.OrderBy(a => a, StringComparer.Ordinal).ToList());
        Assert.Equal(4, summary.Observations);
        Assert.Equal(2, summary.HostsResponded);
    }

    [Fact]
    public async Task With_no_discovery_probe_the_enrichment_probes_run_on_every_address()
    {
        var time = new FakeTimeProvider();
        var enrich = new FuncProbe(ScanProbes.Tcp, ProbePhase.Enrichment, (_, _) => ValueTask.FromResult(ProbeResult.NoResponse));
        var engine = Engine([enrich], time);

        await engine.RunAsync(Job("192.168.1.0/28", ScanProbes.Tcp), new ListSink());

        Assert.Equal(14, enrich.Calls);
    }

    [Fact]
    public async Task Every_probe_attempt_takes_one_permit_from_the_rate_limiter()
    {
        var time = new FakeTimeProvider();
        var limiter = new CountingLimiter();
        var enrich = new FuncProbe(ScanProbes.Dns, ProbePhase.Enrichment, (_, _) => ValueTask.FromResult(ProbeResult.NoResponse));
        var engine = Engine([IcmpUp(time, "192.168.1.1"), enrich], time, limiter: limiter);

        await engine.RunAsync(Job("192.168.1.0/28", ScanProbes.Icmp | ScanProbes.Dns), new ListSink());

        // 14 pings plus one reverse lookup for the single host that answered.
        Assert.Equal(15, limiter.Waits);
    }

    [Fact]
    public async Task Concurrency_never_exceeds_the_configured_limit()
    {
        var time = new FakeTimeProvider();
        var current = 0;
        var peak = 0;
        var probe = new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, async (_, _) =>
        {
            var now = Interlocked.Increment(ref current);
            int seenPeak;
            while (now > (seenPeak = Volatile.Read(ref peak)) && Interlocked.CompareExchange(ref peak, now, seenPeak) != seenPeak)
            {
            }

            await Task.Delay(5);
            Interlocked.Decrement(ref current);
            return ProbeResult.NoResponse;
        });
        var engine = Engine([probe], time, configure: o => o.MaxConcurrency = 4);

        var summary = await engine.RunAsync(Job("192.168.1.0/24"), new ListSink());

        Assert.Equal(SweepOutcome.Completed, summary.Outcome);
        Assert.True(peak <= 4, $"Peak concurrency was {peak}");
        Assert.True(peak >= 2, "Expected some parallelism");
    }

    [Fact]
    public async Task The_sink_is_never_written_to_by_two_threads_at_once()
    {
        var time = new FakeTimeProvider();
        var sink = new ListSink();
        var live = Enumerable.Range(1, 60).Select(i => $"192.168.1.{i}").ToArray();
        var engine = Engine([IcmpUp(time, live)], time, configure: o => o.MaxConcurrency = 16);

        await engine.RunAsync(Job("192.168.1.0/24"), sink);

        Assert.Equal(1, sink.MaxConcurrentWrites);
        Assert.Equal(60, sink.Items.Count);
    }

    [Fact]
    public async Task Cancelling_stops_the_scan_early_and_reports_partial_results()
    {
        var time = new FakeTimeProvider();
        using var cancellation = new CancellationTokenSource();
        var started = 0;
        var probe = new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, async (_, token) =>
        {
            if (Interlocked.Increment(ref started) == 20)
            {
                cancellation.Cancel();
            }

            await Task.Delay(2, token);
            return ProbeResult.NoResponse;
        });
        var engine = Engine([probe], time, configure: o => o.MaxConcurrency = 2);

        var summary = await engine.RunAsync(Job("192.168.1.0/24"), new ListSink(), null, cancellation.Token);

        Assert.Equal(SweepOutcome.Cancelled, summary.Outcome);
        Assert.True(summary.TargetsScanned < summary.TargetsPlanned);
        Assert.True(probe.Calls < 254);
    }

    [Fact]
    public async Task A_token_cancelled_before_the_start_sends_nothing()
    {
        var time = new FakeTimeProvider();
        var probe = IcmpUp(time);
        var engine = Engine([probe], time);

        var summary = await engine.RunAsync(Job("192.168.1.0/24"), new ListSink(), null, new CancellationToken(true));

        Assert.Equal(SweepOutcome.Cancelled, summary.Outcome);
        Assert.Equal(0, probe.Calls);
    }

    [Fact]
    public async Task A_probe_that_hangs_is_stopped_after_the_timeout_plus_grace_and_counted()
    {
        var time = new FakeTimeProvider();
        var entered = new TaskCompletionSource();
        var probe = new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, async (_, token) =>
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return ProbeResult.NoResponse;
        });
        var engine = Engine(
            [probe],
            time,
            configure: o =>
            {
                o.MaxConcurrency = 1;
                o.ProbeTimeout = TimeSpan.FromSeconds(2);
                o.ProbeTimeoutGrace = TimeSpan.FromSeconds(1);
                o.AbortAfterConsecutiveErrors = 100;
            });

        var run = engine.RunAsync(Job("192.168.1.0/30"), new ListSink());
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        time.Advance(TimeSpan.FromSeconds(2.5));
        await Task.Delay(50);
        Assert.False(run.IsCompleted == false && probe.Calls > 1, "The probe was cut off before timeout plus grace");

        for (var i = 0; i < 20 && !run.IsCompleted; i++)
        {
            time.Advance(TimeSpan.FromSeconds(4));
            await Task.Delay(20);
        }

        var summary = await run.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(SweepOutcome.Completed, summary.Outcome);
        Assert.Equal(2, summary.ProbeTimeouts);
        Assert.Equal(2, summary.ProbeErrors);
        Assert.Equal(2, summary.TargetsScanned);
    }

    [Fact]
    public async Task Consecutive_probe_errors_abort_the_scan_as_failed_with_the_cause()
    {
        var time = new FakeTimeProvider();
        var probe = new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, (_, _) =>
            ValueTask.FromResult(ProbeResult.Failure("Operation not permitted")));
        var engine = Engine([probe], time, configure: o =>
        {
            o.MaxConcurrency = 1;
            o.AbortAfterConsecutiveErrors = 5;
        });

        var summary = await engine.RunAsync(Job("192.168.1.0/24"), new ListSink());

        Assert.Equal(SweepOutcome.Failed, summary.Outcome);
        Assert.Contains("5 probe errors in a row", summary.Reason);
        Assert.Contains("Operation not permitted", summary.Reason);
        Assert.Equal(5, probe.Calls);
        Assert.Contains("Operation not permitted", Assert.Single(summary.ErrorSamples));
    }

    [Fact]
    public async Task A_success_resets_the_error_streak_so_scattered_errors_do_not_abort()
    {
        var time = new FakeTimeProvider();
        var calls = 0;
        var probe = new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, (_, _) =>
        {
            var n = Interlocked.Increment(ref calls);
            return ValueTask.FromResult(n % 3 == 0 ? ProbeResult.NoResponse : ProbeResult.Failure("flaky"));
        });
        var engine = Engine([probe], time, configure: o =>
        {
            o.MaxConcurrency = 1;
            o.AbortAfterConsecutiveErrors = 3;
        });

        var summary = await engine.RunAsync(Job("192.168.1.0/24"), new ListSink());

        Assert.Equal(SweepOutcome.Completed, summary.Outcome);
        Assert.True(summary.ProbeErrors > 100);
    }

    [Fact]
    public async Task A_probe_that_throws_is_counted_as_an_error_and_does_not_crash_the_scan()
    {
        var time = new FakeTimeProvider();
        var probe = new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, (_, _) => throw new InvalidOperationException("kaboom"));
        var engine = Engine([probe], time, configure: o =>
        {
            o.MaxConcurrency = 1;
            o.AbortAfterConsecutiveErrors = 3;
        });

        var summary = await engine.RunAsync(Job("192.168.1.0/24"), new ListSink());

        Assert.Equal(SweepOutcome.Failed, summary.Outcome);
        Assert.Contains("kaboom", summary.Reason);
    }

    [Fact]
    public async Task A_failing_sink_aborts_the_scan_instead_of_losing_results_silently()
    {
        var time = new FakeTimeProvider();
        var sink = new ThrowingSink();
        var engine = Engine([IcmpUp(time, Enumerable.Range(1, 50).Select(i => $"192.168.1.{i}").ToArray())], time, configure: o => o.MaxConcurrency = 1);

        var summary = await engine.RunAsync(Job("192.168.1.0/24"), sink);

        Assert.Equal(SweepOutcome.Failed, summary.Outcome);
        Assert.Contains("Could not store results", summary.Reason);
        Assert.Contains("disk full", summary.Reason);
        Assert.True(summary.TargetsScanned < 254);
    }

    private sealed class ThrowingSink : IObservationSink
    {
        public ValueTask WriteAsync(ProbeObservation observation, CancellationToken cancellationToken) =>
            throw new IOException("disk full");
    }

    [Fact]
    public async Task Progress_is_reported_once_per_scanned_address_and_a_broken_listener_is_harmless()
    {
        var time = new FakeTimeProvider();
        var reports = new List<ScanProgress>();
        var engine = Engine([IcmpUp(time, "192.168.1.3")], time, configure: o => o.MaxConcurrency = 1);

        await engine.RunAsync(Job("192.168.1.0/28"), new ListSink(), new ListProgress(reports));

        Assert.Equal(14, reports.Count);
        Assert.Equal(14, reports[^1].TargetsScanned);
        Assert.Equal(14, reports[^1].TargetsPlanned);
        Assert.Equal(1, reports[^1].HostsResponded);

        var summary = await engine.RunAsync(Job("192.168.1.0/28"), new ListSink(), new BrokenProgress());
        Assert.Equal(SweepOutcome.Completed, summary.Outcome);
    }

    private sealed class ListProgress(List<ScanProgress> target) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value)
        {
            lock (target)
            {
                target.Add(value);
            }
        }
    }

    private sealed class BrokenProgress : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value) => throw new InvalidOperationException("listener bug");
    }

    [Fact]
    public async Task The_summary_records_how_long_the_scan_took_on_the_engine_clock()
    {
        var time = new FakeTimeProvider();
        var probe = new FuncProbe(ScanProbes.Icmp, ProbePhase.Discovery, (_, _) =>
        {
            time.Advance(TimeSpan.FromMilliseconds(10));
            return ValueTask.FromResult(ProbeResult.NoResponse);
        });
        var engine = Engine([probe], time, configure: o => o.MaxConcurrency = 1);

        var summary = await engine.RunAsync(Job("192.168.1.0/29"), new ListSink());

        Assert.Equal(TimeSpan.FromMilliseconds(60), summary.Duration);
    }

    [Fact]
    public void Bad_engine_setup_is_rejected_up_front()
    {
        var time = new FakeTimeProvider();
        var scope = new ScanScope([CidrRange.Parse("192.168.1.0/24")], 100);

        Assert.Throws<ArgumentException>(() => new ScanEngine([IcmpUp(time), IcmpUp(time)], scope, new ScanEngineOptions(), NoRateLimiter.Instance));
        Assert.Throws<ArgumentException>(() => new ScanEngine([IcmpUp(time)], scope, new ScanEngineOptions { MaxConcurrency = 0 }, NoRateLimiter.Instance));
        Assert.Throws<ArgumentNullException>(() => new ScanEngine(null!, scope, new ScanEngineOptions(), NoRateLimiter.Instance));
    }

    [Fact]
    public void The_engine_reports_which_probes_it_can_run()
    {
        var time = new FakeTimeProvider();
        var engine = Engine([IcmpUp(time), new FuncProbe(ScanProbes.Dns, ProbePhase.Enrichment, (_, _) => ValueTask.FromResult(ProbeResult.NoResponse))], time);

        Assert.Equal(ScanProbes.Icmp | ScanProbes.Dns, engine.AvailableProbes);
    }
}
