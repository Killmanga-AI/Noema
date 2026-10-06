using System.Net;
using Noema.Agent.Jobs;
using Noema.Domain;
using Noema.Scanning;

namespace Noema.Agent.Tests;

public sealed class BackoffTests
{
    private static readonly TimeSpan Initial = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan Max = TimeSpan.FromMinutes(5);

    [Theory]
    [InlineData(1, 10)]
    [InlineData(2, 20)]
    [InlineData(3, 40)]
    [InlineData(4, 80)]
    [InlineData(5, 160)]
    public void Without_jitter_the_wait_doubles_each_attempt(int attempt, int expectedSeconds)
    {
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), Backoff.Delay(attempt, Initial, Max, 0.0));
    }

    [Fact]
    public void The_wait_never_exceeds_the_maximum_however_many_attempts()
    {
        Assert.Equal(Max, Backoff.Delay(6, Initial, Max, 0.0));
        Assert.Equal(Max, Backoff.Delay(50, Initial, Max, 0.0));
        Assert.Equal(Max, Backoff.Delay(int.MaxValue, Initial, Max, 0.0));
    }

    [Fact]
    public void Jitter_takes_off_at_most_half()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), Backoff.Delay(1, Initial, Max, 1.0));
        Assert.Equal(TimeSpan.FromSeconds(7.5), Backoff.Delay(1, Initial, Max, 0.5));

        for (var attempt = 1; attempt <= 12; attempt++)
        {
            var full = Backoff.Delay(attempt, Initial, Max, 0.0);
            var jittered = Backoff.Delay(attempt, Initial, Max, 0.999);
            Assert.True(jittered <= full);
            Assert.True(jittered.Ticks >= full.Ticks / 2);
        }
    }

    [Fact]
    public void Out_of_range_randomness_is_clamped()
    {
        Assert.Equal(Backoff.Delay(1, Initial, Max, 0.0), Backoff.Delay(1, Initial, Max, -3.0));
        Assert.Equal(Backoff.Delay(1, Initial, Max, 1.0), Backoff.Delay(1, Initial, Max, 7.0));
    }

    [Fact]
    public void Bad_input_is_rejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Backoff.Delay(0, Initial, Max, 0.0));
        Assert.Throws<ArgumentException>(() => Backoff.Delay(1, TimeSpan.Zero, Max, 0.0));
        Assert.Throws<ArgumentException>(() => Backoff.Delay(1, Max, Initial, 0.0));
    }
}

public sealed class BufferingObservationSinkTests
{
    private static ProbeObservation Observation(int host) =>
        new(ObservationKind.IcmpEchoReply, IPAddress.Parse($"192.168.1.{host}"), DateTimeOffset.UtcNow);

    [Fact]
    public async Task Observations_come_back_oldest_first_in_the_requested_batch_size()
    {
        var sink = new BufferingObservationSink();
        for (var i = 1; i <= 5; i++)
        {
            await sink.WriteAsync(Observation(i), CancellationToken.None);
        }

        var first = sink.Take(2);
        var second = sink.Take(10);

        Assert.Equal(["192.168.1.1", "192.168.1.2"], first.Select(o => o.Address.ToString()));
        Assert.Equal(["192.168.1.3", "192.168.1.4", "192.168.1.5"], second.Select(o => o.Address.ToString()));
        Assert.Equal(0, sink.Count);
        Assert.Empty(sink.Take(5));
    }

    [Fact]
    public async Task Writing_from_many_threads_loses_nothing()
    {
        var sink = new BufferingObservationSink();

        await Task.WhenAll(Enumerable.Range(0, 8).Select(t => Task.Run(async () =>
        {
            for (var i = 0; i < 250; i++)
            {
                await sink.WriteAsync(Observation((i % 250) + 1), CancellationToken.None);
            }
        })));

        Assert.Equal(2000, sink.Count);
    }

    [Fact]
    public void Taking_needs_a_positive_size()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new BufferingObservationSink().Take(0));
    }

    [Fact]
    public void The_progress_tracker_returns_the_latest_report_and_zeros_before_any()
    {
        var tracker = new ProgressTracker();
        Assert.Equal(new ScanProgress(0, 0, 0), tracker.Snapshot());

        tracker.Report(new ScanProgress(254, 10, 1));
        tracker.Report(new ScanProgress(254, 20, 2));

        Assert.Equal(new ScanProgress(254, 20, 2), tracker.Snapshot());
    }
}
