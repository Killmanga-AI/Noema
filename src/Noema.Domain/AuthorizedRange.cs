namespace Noema.Domain;

/// <summary>
/// A network range this installation is allowed to scan. Scans outside every authorized range are refused.
/// </summary>
public sealed class AuthorizedRange
{
    public const int MaxDescriptionLength = 200;

    private AuthorizedRange()
    {
    }

    public Guid Id { get; private set; }

    public CidrRange Range { get; private set; } = null!;

    public string? Description { get; private set; }

    public Guid CreatedByUserId { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public static AuthorizedRange Create(
        CidrRange range,
        string? description,
        Guid createdByUserId,
        DateTimeOffset now,
        bool allowPublic)
    {
        ArgumentNullException.ThrowIfNull(range);
        Guard.Utc(now, nameof(now));

        var problem = ScanTargetRules.ValidateForAuthorization(range, allowPublic);
        if (problem is not null)
        {
            throw new ArgumentException(problem, nameof(range));
        }

        var trimmed = string.IsNullOrWhiteSpace(description) ? null : description.Trim();
        if (trimmed is { Length: > MaxDescriptionLength })
        {
            throw new ArgumentException($"A description can be at most {MaxDescriptionLength} characters.", nameof(description));
        }

        return new AuthorizedRange
        {
            Id = Ids.New(now),
            Range = range,
            Description = trimmed,
            CreatedByUserId = createdByUserId,
            CreatedAt = now
        };
    }
}
