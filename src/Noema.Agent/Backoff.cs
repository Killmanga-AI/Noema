namespace Noema.Agent;

/// <summary>Waiting times for retries: doubling each time up to a cap, with jitter so many agents do not retry in step.</summary>
public static class Backoff
{
    /// <summary>
    /// The wait before retry number attempt, counting from 1. Doubles from the initial delay up to the maximum,
    /// then takes off up to half at random. randomFraction is a number from 0 up to but not including 1.
    /// </summary>
    public static TimeSpan Delay(int attempt, TimeSpan initial, TimeSpan maximum, double randomFraction)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(attempt, 1);
        if (initial <= TimeSpan.Zero || maximum < initial)
        {
            throw new ArgumentException("The initial delay must be positive and not above the maximum.");
        }

        var exponent = Math.Min(attempt - 1, 30);
        var ticks = Math.Min(initial.Ticks * Math.Pow(2, exponent), maximum.Ticks);
        var fraction = Math.Clamp(randomFraction, 0.0, 1.0);

        return TimeSpan.FromTicks((long)(ticks * (1.0 - (0.5 * fraction))));
    }
}
