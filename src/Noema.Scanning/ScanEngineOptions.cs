namespace Noema.Scanning;

public sealed class ScanEngineOptions
{
    /// <summary>How many addresses are probed at the same time.</summary>
    public int MaxConcurrency { get; set; } = 64;

    /// <summary>How long one probe may wait for an answer.</summary>
    public TimeSpan ProbeTimeout { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>Extra time after the probe timeout before the engine gives up on a probe that is not responding to it.</summary>
    public TimeSpan ProbeTimeoutGrace { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>A scan stops as failed after this many probe errors in a row, instead of grinding through a broken setup.</summary>
    public int AbortAfterConsecutiveErrors { get; set; } = 25;

    public IReadOnlyList<string> Validate()
    {
        var problems = new List<string>();

        if (MaxConcurrency is < 1 or > 1024)
        {
            problems.Add("MaxConcurrency must be between 1 and 1024.");
        }

        if (ProbeTimeout < TimeSpan.FromMilliseconds(100) || ProbeTimeout > TimeSpan.FromSeconds(30))
        {
            problems.Add("ProbeTimeout must be between 100 milliseconds and 30 seconds.");
        }

        if (ProbeTimeoutGrace < TimeSpan.FromMilliseconds(100) || ProbeTimeoutGrace > TimeSpan.FromSeconds(10))
        {
            problems.Add("ProbeTimeoutGrace must be between 100 milliseconds and 10 seconds.");
        }

        if (AbortAfterConsecutiveErrors is < 1 or > 10_000)
        {
            problems.Add("AbortAfterConsecutiveErrors must be between 1 and 10000.");
        }

        return problems;
    }
}
