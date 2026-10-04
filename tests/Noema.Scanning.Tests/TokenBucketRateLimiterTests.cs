using Microsoft.Extensions.Time.Testing;

namespace Noema.Scanning.Tests;

public sealed class TokenBucketRateLimiterTests
{
    [Fact]
    public async Task The_burst_is_available_immediately()
    {
        var time = new FakeTimeProvider();
        var limiter = new TokenBucketRateLimiter(10, 5, time);

        for (var i = 0; i < 5; i++)
        {
            var wait = limiter.WaitAsync();
            Assert.True(wait.IsCompletedSuccessfully);
            await wait;
        }
    }

    [Fact]
    public async Task After_the_burst_callers_wait_for_the_next_permit()
    {
        var time = new FakeTimeProvider();
        var limiter = new TokenBucketRateLimiter(10, 2, time);
        await limiter.WaitAsync();
        await limiter.WaitAsync();

        var pending = limiter.WaitAsync().AsTask();

        Assert.False(pending.IsCompleted);
        time.Advance(TimeSpan.FromMilliseconds(50));
        Assert.False(pending.IsCompleted);
        time.Advance(TimeSpan.FromMilliseconds(60));
        await pending.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task Permits_refill_with_time_but_never_beyond_the_burst()
    {
        var time = new FakeTimeProvider();
        var limiter = new TokenBucketRateLimiter(10, 3, time);
        for (var i = 0; i < 3; i++)
        {
            await limiter.WaitAsync();
        }

        time.Advance(TimeSpan.FromSeconds(60));

        for (var i = 0; i < 3; i++)
        {
            Assert.True(limiter.WaitAsync().IsCompletedSuccessfully);
        }

        Assert.False(limiter.WaitAsync().AsTask().IsCompleted);
    }

    [Fact]
    public async Task A_steady_rate_is_held_over_time()
    {
        var time = new FakeTimeProvider();
        var limiter = new TokenBucketRateLimiter(100, 1, time);
        await limiter.WaitAsync();

        var granted = 0;
        var worker = Task.Run(async () =>
        {
            for (var i = 0; i < 20; i++)
            {
                await limiter.WaitAsync();
                Interlocked.Increment(ref granted);
            }
        });

        // Two simulated seconds hands out 20 permits at 100 per second only if the pacing is correct.
        for (var step = 0; step < 200 && !worker.IsCompleted; step++)
        {
            await Task.Delay(1);
            time.Advance(TimeSpan.FromMilliseconds(10));
        }

        await worker.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(20, granted);
    }

    [Fact]
    public async Task A_cancelled_caller_stops_waiting()
    {
        var time = new FakeTimeProvider();
        var limiter = new TokenBucketRateLimiter(1, 1, time);
        await limiter.WaitAsync();
        using var cancellation = new CancellationTokenSource();

        var pending = limiter.WaitAsync(cancellation.Token).AsTask();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
    }

    [Fact]
    public async Task An_already_cancelled_token_fails_even_when_a_permit_is_free()
    {
        var limiter = new TokenBucketRateLimiter(10, 5, new FakeTimeProvider());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await limiter.WaitAsync(new CancellationToken(true)));
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(-1, 1)]
    [InlineData(double.NaN, 1)]
    [InlineData(double.PositiveInfinity, 1)]
    [InlineData(10, 0)]
    public void Bad_settings_are_rejected(double rate, int burst)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TokenBucketRateLimiter(rate, burst));
    }

    [Fact]
    public async Task The_no_op_limiter_never_waits_but_still_honours_cancellation()
    {
        await NoRateLimiter.Instance.WaitAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await NoRateLimiter.Instance.WaitAsync(new CancellationToken(true)));
    }
}
