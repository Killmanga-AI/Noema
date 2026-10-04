namespace Noema.Scanning;

/// <summary>
/// Allows a steady number of packets per second with a short burst. One limiter is shared by everything
/// the agent sends, so the total network load stays bounded however many scans run.
/// </summary>
public sealed class TokenBucketRateLimiter : IRateLimiter
{
    private static readonly TimeSpan MinimumDelay = TimeSpan.FromMilliseconds(1);

    private readonly double permitsPerSecond;
    private readonly double capacity;
    private readonly TimeProvider time;
    private readonly object gate = new();

    private double tokens;
    private long lastRefill;

    public TokenBucketRateLimiter(double permitsPerSecond, int burst, TimeProvider? timeProvider = null)
    {
        if (double.IsNaN(permitsPerSecond) || double.IsInfinity(permitsPerSecond) || permitsPerSecond <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(permitsPerSecond), permitsPerSecond, "The rate must be a positive number.");
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(burst, 1);

        this.permitsPerSecond = permitsPerSecond;
        capacity = burst;
        time = timeProvider ?? TimeProvider.System;
        tokens = burst;
        lastRefill = time.GetTimestamp();
    }

    public async ValueTask WaitAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TimeSpan delay;
            lock (gate)
            {
                Refill();

                if (tokens >= 1)
                {
                    tokens -= 1;
                    return;
                }

                delay = TimeSpan.FromSeconds((1 - tokens) / permitsPerSecond);
            }

            await Task.Delay(delay < MinimumDelay ? MinimumDelay : delay, time, cancellationToken).ConfigureAwait(false);
        }
    }

    private void Refill()
    {
        var now = time.GetTimestamp();
        var elapsed = time.GetElapsedTime(lastRefill, now);
        lastRefill = now;
        tokens = Math.Min(capacity, tokens + (elapsed.TotalSeconds * permitsPerSecond));
    }
}
