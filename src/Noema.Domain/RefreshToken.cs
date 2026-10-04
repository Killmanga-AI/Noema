namespace Noema.Domain;

/// <summary>
/// A long lived session credential. Only a hash of the token is stored, so a database leak does not hand out sessions.
/// Each use replaces the token with a new one, and presenting a used token again means it was copied.
/// </summary>
public sealed class RefreshToken
{
    private RefreshToken()
    {
    }

    public Guid Id { get; private set; }

    public Guid UserId { get; private set; }

    public string TokenHash { get; private set; } = null!;

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset ExpiresAt { get; private set; }

    public DateTimeOffset? RevokedAt { get; private set; }

    public Guid? ReplacedByTokenId { get; private set; }

    public static RefreshToken Issue(Guid userId, string tokenHash, DateTimeOffset now, TimeSpan lifetime)
    {
        Guard.Utc(now, nameof(now));

        if (userId == Guid.Empty)
        {
            throw new ArgumentException("A token belongs to a user.", nameof(userId));
        }

        if (string.IsNullOrWhiteSpace(tokenHash))
        {
            throw new ArgumentException("A token hash is required.", nameof(tokenHash));
        }

        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), lifetime, "The lifetime must be positive.");
        }

        return new RefreshToken
        {
            Id = Ids.New(now),
            UserId = userId,
            TokenHash = tokenHash,
            CreatedAt = now,
            ExpiresAt = now + lifetime
        };
    }

    public bool IsRevoked => RevokedAt.HasValue;

    public bool IsExpired(DateTimeOffset now) => now >= ExpiresAt;

    public bool IsActive(DateTimeOffset now) => !IsRevoked && !IsExpired(now);

    /// <summary>Revokes the token. A repeat call keeps the first revocation time.</summary>
    public void Revoke(DateTimeOffset now, Guid? replacedByTokenId = null)
    {
        Guard.Utc(now, nameof(now));

        if (RevokedAt is not null)
        {
            return;
        }

        RevokedAt = now;
        ReplacedByTokenId = replacedByTokenId;
    }
}
