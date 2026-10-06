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

    [Fact]
    public void Remembers_who_requested_the_scan()
    {
        var requester = Guid.NewGuid();

        Assert.Equal(requester, ScanRun.Request(Lan, ScanProbes.Icmp, T0, requester).RequestedByUserId);
        Assert.Null(ScanRun.Request(Lan, ScanProbes.Icmp, T0).RequestedByUserId);
    }
}

public sealed class ScanRunAgentTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private static readonly CidrRange Lan = CidrRange.Parse("192.168.1.0/24");
    private static readonly TimeSpan Lease = TimeSpan.FromMinutes(2);

    private static ScanRun NewRun(Guid? pinned = null) => ScanRun.Request(Lan, ScanProbes.Icmp, T0, null, pinned);

    private static ScanRun Claimed(Guid agent)
    {
        var run = NewRun();
        run.Claim(agent, T0.AddSeconds(1), Lease);
        return run;
    }

    [Fact]
    public void Claiming_starts_the_scan_and_assigns_it_with_a_lease()
    {
        var agent = Guid.NewGuid();
        var run = NewRun();

        run.Claim(agent, T0.AddSeconds(5), Lease);

        Assert.Equal(ScanStatus.Running, run.Status);
        Assert.Equal(T0.AddSeconds(5), run.StartedAt);
        Assert.Equal(agent, run.AssignedAgentId);
        Assert.True(run.IsAssignedTo(agent));
        Assert.False(run.IsAssignedTo(Guid.NewGuid()));
        Assert.Equal(T0.AddSeconds(5) + Lease, run.LeaseExpiresAt);
    }

    [Fact]
    public void A_pinned_scan_can_only_be_claimed_by_that_agent()
    {
        var pinned = Guid.NewGuid();
        var run = NewRun(pinned);

        Assert.Equal(pinned, run.RequestedAgentId);
        Assert.Throws<InvalidOperationException>(() => run.Claim(Guid.NewGuid(), T0.AddSeconds(1), Lease));
        Assert.Equal(ScanStatus.Queued, run.Status);

        run.Claim(pinned, T0.AddSeconds(1), Lease);
        Assert.Equal(ScanStatus.Running, run.Status);
    }

    [Fact]
    public void A_scan_can_be_claimed_only_once_and_only_while_queued()
    {
        var run = NewRun();
        run.Claim(Guid.NewGuid(), T0.AddSeconds(1), Lease);

        Assert.Throws<InvalidOperationException>(() => run.Claim(Guid.NewGuid(), T0.AddSeconds(2), Lease));

        var cancelled = NewRun();
        cancelled.Cancel(T0.AddSeconds(1));
        Assert.Throws<InvalidOperationException>(() => cancelled.Claim(Guid.NewGuid(), T0.AddSeconds(2), Lease));
    }

    [Fact]
    public void Claim_rejects_bad_input()
    {
        Assert.Throws<ArgumentException>(() => NewRun().Claim(Guid.Empty, T0, Lease));
        Assert.Throws<ArgumentOutOfRangeException>(() => NewRun().Claim(Guid.NewGuid(), T0, TimeSpan.Zero));
        Assert.Throws<ArgumentException>(() => NewRun().Claim(Guid.NewGuid(), T0.AddSeconds(-1), Lease));
    }

    [Fact]
    public void Progress_updates_counts_and_pushes_the_lease_out()
    {
        var agent = Guid.NewGuid();
        var run = Claimed(agent);

        run.ReportProgress(agent, T0.AddSeconds(30), Lease, 254, 100, 7);

        Assert.Equal(254, run.TargetsPlanned);
        Assert.Equal(100, run.TargetsScanned);
        Assert.Equal(7, run.HostsResponded);
        Assert.Equal(T0.AddSeconds(30) + Lease, run.LeaseExpiresAt);
    }

    [Fact]
    public void A_late_progress_report_never_shortens_the_lease()
    {
        var agent = Guid.NewGuid();
        var run = Claimed(agent);
        run.ReportProgress(agent, T0.AddMinutes(10), Lease, 254, 10, 1);
        var before = run.LeaseExpiresAt;

        run.ReportProgress(agent, T0.AddMinutes(1), Lease, 254, 20, 2);

        Assert.Equal(before, run.LeaseExpiresAt);
    }

    [Fact]
    public void Progress_must_add_up_and_never_go_backwards_or_negative()
    {
        var agent = Guid.NewGuid();
        var run = Claimed(agent);
        run.ReportProgress(agent, T0.AddSeconds(5), Lease, 100, 50, 5);

        Assert.Throws<ArgumentException>(() => run.ReportProgress(agent, T0.AddSeconds(6), Lease, 100, 101, 5));
        Assert.Throws<ArgumentException>(() => run.ReportProgress(agent, T0.AddSeconds(6), Lease, 100, 50, 51));
        Assert.Throws<ArgumentException>(() => run.ReportProgress(agent, T0.AddSeconds(6), Lease, 100, 40, 5));
        Assert.Throws<ArgumentException>(() => run.ReportProgress(agent, T0.AddSeconds(6), Lease, 100, 50, 4));
        Assert.Throws<ArgumentOutOfRangeException>(() => run.ReportProgress(agent, T0.AddSeconds(6), Lease, -1, 0, 0));
        run.ReportProgress(agent, T0.AddSeconds(6), Lease, 100, 50, 5);
    }

    [Fact]
    public void Only_the_assigned_agent_can_report_on_a_running_scan()
    {
        var agent = Guid.NewGuid();
        var run = Claimed(agent);

        Assert.Throws<InvalidOperationException>(() => run.ReportProgress(Guid.NewGuid(), T0.AddSeconds(5), Lease, 10, 1, 0));
        Assert.Throws<InvalidOperationException>(() => run.AcceptBatch(Guid.NewGuid(), 1, T0.AddSeconds(5), Lease));

        var queued = NewRun();
        Assert.Throws<InvalidOperationException>(() => queued.ReportProgress(agent, T0.AddSeconds(5), Lease, 10, 1, 0));

        run.Complete(T0.AddSeconds(10));
        Assert.Throws<InvalidOperationException>(() => run.ReportProgress(agent, T0.AddSeconds(11), Lease, 10, 1, 0));
    }

    [Fact]
    public void Batches_are_accepted_in_order_and_a_repeat_of_the_last_one_is_recognised()
    {
        var agent = Guid.NewGuid();
        var run = Claimed(agent);

        Assert.Equal(BatchDisposition.Accepted, run.AcceptBatch(agent, 1, T0.AddSeconds(5), Lease));
        Assert.Equal(BatchDisposition.Duplicate, run.AcceptBatch(agent, 1, T0.AddSeconds(6), Lease));
        Assert.Equal(BatchDisposition.Accepted, run.AcceptBatch(agent, 2, T0.AddSeconds(7), Lease));
        Assert.Equal(BatchDisposition.Duplicate, run.AcceptBatch(agent, 2, T0.AddSeconds(8), Lease));
        Assert.Equal(2, run.LastBatchSequence);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(5)]
    [InlineData(-1)]
    public void A_skipped_or_nonsensical_batch_number_is_refused(int sequence)
    {
        var agent = Guid.NewGuid();
        var run = Claimed(agent);

        Assert.Throws<InvalidOperationException>(() => run.AcceptBatch(agent, sequence, T0.AddSeconds(5), Lease));
        Assert.Equal(0, run.LastBatchSequence);
    }

    [Fact]
    public void An_old_batch_number_is_refused_once_newer_ones_were_accepted()
    {
        var agent = Guid.NewGuid();
        var run = Claimed(agent);
        run.AcceptBatch(agent, 1, T0.AddSeconds(5), Lease);
        run.AcceptBatch(agent, 2, T0.AddSeconds(6), Lease);

        Assert.Throws<InvalidOperationException>(() => run.AcceptBatch(agent, 1, T0.AddSeconds(7), Lease));
    }

    [Fact]
    public void Cancelling_a_queued_scan_ends_it_at_once()
    {
        var run = NewRun();

        run.RequestCancel(T0.AddSeconds(3));

        Assert.Equal(ScanStatus.Cancelled, run.Status);
        Assert.Equal(T0.AddSeconds(3), run.FinishedAt);
        Assert.False(run.IsCancelRequested);
    }

    [Fact]
    public void Cancelling_a_running_scan_only_flags_it_and_asking_again_keeps_the_first_time()
    {
        var run = Claimed(Guid.NewGuid());

        run.RequestCancel(T0.AddSeconds(10));
        run.RequestCancel(T0.AddSeconds(20));

        Assert.Equal(ScanStatus.Running, run.Status);
        Assert.True(run.IsCancelRequested);
        Assert.Equal(T0.AddSeconds(10), run.CancelRequestedAt);
    }

    [Fact]
    public void A_finished_scan_cannot_be_cancelled_and_stops_reporting_a_pending_request()
    {
        var run = Claimed(Guid.NewGuid());
        run.RequestCancel(T0.AddSeconds(10));
        run.Cancel(T0.AddSeconds(11));

        Assert.False(run.IsCancelRequested);
        Assert.Throws<InvalidOperationException>(() => run.RequestCancel(T0.AddSeconds(12)));
    }

    [Fact]
    public void Abandoning_fails_the_scan_with_the_reason()
    {
        var run = Claimed(Guid.NewGuid());

        run.Abandon(T0.AddMinutes(5), "The agent stopped reporting.");

        Assert.Equal(ScanStatus.Failed, run.Status);
        Assert.Equal("The agent stopped reporting.", run.FailureReason);
        Assert.Equal(T0.AddMinutes(5), run.FinishedAt);
    }
}
