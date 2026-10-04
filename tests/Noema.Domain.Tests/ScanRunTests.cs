namespace Noema.Domain.Tests;

public sealed class ScanRunTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private static readonly CidrRange Lan = CidrRange.Parse("192.168.1.0/24");

    private static ScanRun NewRun() => ScanRun.Request(Lan, ScanProbes.Icmp | ScanProbes.Arp, T0);

    [Fact]
    public void A_new_request_is_queued()
    {
        var run = NewRun();

        Assert.NotEqual(Guid.Empty, run.Id);
        Assert.Equal(ScanStatus.Queued, run.Status);
        Assert.Equal(Lan, run.Target);
        Assert.Equal(ScanProbes.Icmp | ScanProbes.Arp, run.Probes);
        Assert.Equal(T0, run.RequestedAt);
        Assert.Null(run.StartedAt);
        Assert.Null(run.FinishedAt);
        Assert.False(run.IsTerminal);
    }

    [Fact]
    public void A_request_needs_at_least_one_known_probe()
    {
        Assert.Throws<ArgumentException>(() => ScanRun.Request(Lan, ScanProbes.None, T0));
        Assert.Throws<ArgumentException>(() => ScanRun.Request(Lan, (ScanProbes)1024, T0));
        Assert.Throws<ArgumentException>(() => ScanRun.Request(Lan, ScanProbes.Icmp | (ScanProbes)1024, T0));
    }

    [Fact]
    public void A_request_needs_a_target_and_a_utc_time()
    {
        Assert.Throws<ArgumentNullException>(() => ScanRun.Request(null!, ScanProbes.Icmp, T0));
        Assert.Throws<ArgumentException>(() =>
            ScanRun.Request(Lan, ScanProbes.Icmp, new DateTimeOffset(2026, 10, 4, 14, 0, 0, TimeSpan.FromHours(2))));
    }

    [Fact]
    public void Happy_path_runs_queued_running_completed()
    {
        var run = NewRun();

        run.Start(T0.AddSeconds(1));
        Assert.Equal(ScanStatus.Running, run.Status);
        Assert.Equal(T0.AddSeconds(1), run.StartedAt);

        run.Complete(T0.AddMinutes(1));
        Assert.Equal(ScanStatus.Completed, run.Status);
        Assert.Equal(T0.AddMinutes(1), run.FinishedAt);
        Assert.True(run.IsTerminal);
    }

    [Fact]
    public void A_queued_scan_can_be_cancelled_or_failed()
    {
        var cancelled = NewRun();
        cancelled.Cancel(T0.AddSeconds(5));
        Assert.Equal(ScanStatus.Cancelled, cancelled.Status);
        Assert.Null(cancelled.StartedAt);

        var failed = NewRun();
        failed.Fail("Agent offline", T0.AddSeconds(5));
        Assert.Equal(ScanStatus.Failed, failed.Status);
        Assert.Equal("Agent offline", failed.FailureReason);
    }

    [Fact]
    public void A_running_scan_can_be_cancelled_or_failed()
    {
        var cancelled = NewRun();
        cancelled.Start(T0.AddSeconds(1));
        cancelled.Cancel(T0.AddSeconds(2));
        Assert.Equal(ScanStatus.Cancelled, cancelled.Status);

        var failed = NewRun();
        failed.Start(T0.AddSeconds(1));
        failed.Fail("Timeout", T0.AddSeconds(2));
        Assert.Equal(ScanStatus.Failed, failed.Status);
    }

    [Fact]
    public void Illegal_transitions_are_refused()
    {
        var queued = NewRun();
        Assert.Throws<InvalidOperationException>(() => queued.Complete(T0.AddSeconds(1)));

        var running = NewRun();
        running.Start(T0.AddSeconds(1));
        Assert.Throws<InvalidOperationException>(() => running.Start(T0.AddSeconds(2)));
    }

    [Fact]
    public void Terminal_states_are_final()
    {
        var completed = NewRun();
        completed.Start(T0.AddSeconds(1));
        completed.Complete(T0.AddSeconds(2));

        Assert.Throws<InvalidOperationException>(() => completed.Start(T0.AddSeconds(3)));
        Assert.Throws<InvalidOperationException>(() => completed.Complete(T0.AddSeconds(3)));
        Assert.Throws<InvalidOperationException>(() => completed.Fail("late", T0.AddSeconds(3)));
        Assert.Throws<InvalidOperationException>(() => completed.Cancel(T0.AddSeconds(3)));

        var cancelled = NewRun();
        cancelled.Cancel(T0.AddSeconds(1));
        Assert.Throws<InvalidOperationException>(() => cancelled.Cancel(T0.AddSeconds(2)));
        Assert.Throws<InvalidOperationException>(() => cancelled.Fail("late", T0.AddSeconds(2)));

        var failed = NewRun();
        failed.Fail("boom", T0.AddSeconds(1));
        Assert.Throws<InvalidOperationException>(() => failed.Cancel(T0.AddSeconds(2)));
    }

    [Fact]
    public void Time_cannot_run_backwards_through_the_lifecycle()
    {
        var early = NewRun();
        Assert.Throws<ArgumentException>(() => early.Start(T0.AddSeconds(-1)));

        var run = NewRun();
        run.Start(T0.AddMinutes(1));
        Assert.Throws<ArgumentException>(() => run.Complete(T0.AddSeconds(30)));
        Assert.Throws<ArgumentException>(() => run.Cancel(T0.AddSeconds(30)));
        Assert.Throws<ArgumentException>(() => run.Fail("x", T0.AddSeconds(30)));
    }

    [Fact]
    public void Transitions_reject_non_utc_times()
    {
        var local = new DateTimeOffset(2026, 10, 4, 14, 0, 0, TimeSpan.FromHours(2));

        Assert.Throws<ArgumentException>(() => NewRun().Start(local));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void A_failure_needs_a_reason(string? reason)
    {
        Assert.Throws<ArgumentException>(() => NewRun().Fail(reason!, T0.AddSeconds(1)));
    }

    [Fact]
    public void Long_failure_reasons_are_truncated_not_rejected()
    {
        var run = NewRun();

        run.Fail(new string('x', ScanRun.MaxFailureReasonLength + 500), T0.AddSeconds(1));

        Assert.Equal(ScanRun.MaxFailureReasonLength, run.FailureReason!.Length);
    }
}
