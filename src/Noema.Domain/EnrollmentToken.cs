namespace Noema.Domain;

/// <summary>
/// A one-time permission for one agent to enroll. An administrator creates it, hands it to the machine that
/// will run the agent, and it stops working the moment it is used or expires. Only its hash is stored.
/// </summary>
public sealed class EnrollmentToken
{
    public static readonly TimeSpan MinLifetime = TimeSpan.FromMinutes(1);
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromDays(7);
    public const int MaxLabelLength = 64;

    private EnrollmentToken()
    {
    }

    public Guid Id { get; private set; }

    public string TokenHash { get; private set; } = null!;

    /// <summary>A note for administrators, such as "warehouse office". Not used for anything else.</summary>
    public string? Label { get; private set; }

    public Guid CreatedByUserId { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset ExpiresAt { get; private set; }

    public DateTimeOffset? UsedAt { get; private set; }

    public Guid? AgentId { get; private set; }

    public bool IsUsed => UsedAt.HasValue;

    public static EnrollmentToken Issue(
        string tokenHash,
        string? label,
        Guid createdByUserId,
        DateTimeOffset now,
        TimeSpan lifetime)
    {
        Guard.Utc(now, nameof(now));

        if (string.IsNullOrWhiteSpace(tokenHash))
        {
            throw new ArgumentException("A token hash is required.", nameof(tokenHash));
        }

        if (createdByUserId == Guid.Empty)
        {
            throw new ArgumentException("A token is created by a user.", nameof(createdByUserId));
        }

        if (lifetime < MinLifetime || lifetime > MaxLifetime)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), lifetime, "A token lasts between 1 minute and 7 days.");
        }

        var trimmed = string.IsNullOrWhiteSpace(label) ? null : label.Trim();
        if (trimmed is { Length: > MaxLabelLength })
        {
            throw new ArgumentException($"A label can be at most {MaxLabelLength} characters.", nameof(label));
        }

        return new EnrollmentToken
        {
            Id = Ids.New(now),
            TokenHash = tokenHash,
            Label = trimmed,
            CreatedByUserId = createdByUserId,
            CreatedAt = now,
            ExpiresAt = now + lifetime
        };
    }

    public bool IsUsable(DateTimeOffset now) => !IsUsed && now < ExpiresAt;

    /// <summary>Marks the token as used by the agent that enrolled with it.</summary>
    public void Redeem(Guid agentId, DateTimeOffset now)
    {
        Guard.Utc(now, nameof(now));

        if (agentId == Guid.Empty)
        {
            throw new ArgumentException("An enrollment creates an agent.", nameof(agentId));
        }

        if (IsUsed)
        {
            throw new InvalidOperationException("This enrollment token has already been used.");
        }

        if (now >= ExpiresAt)
        {
            throw new InvalidOperationException("This enrollment token has expired.");
        }

        UsedAt = now;
        AgentId = agentId;
    }
}
