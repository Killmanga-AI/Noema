namespace Noema.Scanning;

public interface IRateLimiter
{
    /// <summary>Completes when one more packet may be sent.</summary>
    ValueTask WaitAsync(CancellationToken cancellationToken = default);
}

public sealed class NoRateLimiter : IRateLimiter
{
    public static NoRateLimiter Instance { get; } = new();

    public ValueTask WaitAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.CompletedTask;
    }
}
