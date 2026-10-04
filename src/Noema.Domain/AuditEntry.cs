using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Noema.Domain;

public enum AuditOutcome
{
    Success,
    Failure,
    Denied
}

/// <summary>
/// One line in the audit trail: who did what, to what, from where, and how it went.
/// Entries are append only. Never put secrets such as passwords or tokens in them.
/// </summary>
public sealed class AuditEntry
{
    public const int MaxDetailLength = 4096;
    public const int MaxActorNameLength = 64;

    private static readonly Regex ActionPattern = new(
        "^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$",
        RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    private AuditEntry()
    {
    }

    public Guid Id { get; private set; }

    public DateTimeOffset OccurredAt { get; private set; }

    public Guid? ActorUserId { get; private set; }

    /// <summary>The actor's username at the time, kept so the trail still reads well if the user is later removed.</summary>
    public string? ActorName { get; private set; }

    /// <summary>Dotted lower case name such as auth.login.failed.</summary>
    public string Action { get; private set; } = null!;

    public string? TargetType { get; private set; }

    public string? TargetId { get; private set; }

    public AuditOutcome Outcome { get; private set; }

    public string? DetailJson { get; private set; }

    public IPAddress? RemoteAddress { get; private set; }

    public string? CorrelationId { get; private set; }

    public static AuditEntry Create(
        string action,
        AuditOutcome outcome,
        DateTimeOffset occurredAt,
        Guid? actorUserId = null,
        string? actorName = null,
        string? targetType = null,
        string? targetId = null,
        string? detailJson = null,
        IPAddress? remoteAddress = null,
        string? correlationId = null)
    {
        Guard.Utc(occurredAt, nameof(occurredAt));

        if (string.IsNullOrWhiteSpace(action) || action.Length > 64 || !ActionPattern.IsMatch(action))
        {
            throw new ArgumentException("An action looks like auth.login.failed: lower case words joined by dots, at most 64 characters.", nameof(action));
        }

        if (!Enum.IsDefined(outcome))
        {
            throw new ArgumentOutOfRangeException(nameof(outcome), outcome, "Unknown outcome.");
        }

        return new AuditEntry
        {
            Id = Ids.New(occurredAt),
            OccurredAt = occurredAt,
            ActorUserId = actorUserId,
            ActorName = Limit(actorName, MaxActorNameLength),
            Action = action,
            TargetType = Limit(targetType, 64),
            TargetId = Limit(targetId, 128),
            Outcome = outcome,
            DetailJson = ValidateDetail(detailJson),
            RemoteAddress = remoteAddress is null ? null : IpAddressNormalizer.Normalize(remoteAddress),
            CorrelationId = Limit(correlationId, 64)
        };
    }

    private static string? Limit(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        return trimmed.Length > max ? trimmed[..max] : trimmed;
    }

    private static string? ValidateDetail(string? detailJson)
    {
        if (string.IsNullOrWhiteSpace(detailJson))
        {
            return null;
        }

        if (detailJson.Length > MaxDetailLength)
        {
            throw new ArgumentException($"Detail can be at most {MaxDetailLength} characters.", nameof(detailJson));
        }

        try
        {
            using (JsonDocument.Parse(detailJson))
            {
            }
        }
        catch (JsonException)
        {
            throw new ArgumentException("Detail must be valid JSON.", nameof(detailJson));
        }

        return detailJson;
    }
}
