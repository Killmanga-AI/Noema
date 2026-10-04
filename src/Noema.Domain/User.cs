using System.Text.RegularExpressions;

namespace Noema.Domain;

/// <summary>
/// A person who can sign in. Holds the lockout rules so they apply the same way everywhere.
/// The password itself is never stored, only a hash produced by the infrastructure layer.
/// </summary>
public sealed class User
{
    public const int MaxFailedLogins = 5;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    private static readonly Regex UsernamePattern = new(
        "^[a-z0-9][a-z0-9._-]{2,63}$",
        RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    private User()
    {
    }

    public Guid Id { get; private set; }

    /// <summary>Lower case, 3 to 64 characters of letters, digits, dot, dash and underscore.</summary>
    public string Username { get; private set; } = null!;

    public string PasswordHash { get; private set; } = null!;

    public UserRole Role { get; private set; }

    public bool IsDisabled { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset PasswordChangedAt { get; private set; }

    public DateTimeOffset? LastLoginAt { get; private set; }

    public int FailedLoginCount { get; private set; }

    public DateTimeOffset? LockedUntil { get; private set; }

    public static string NormalizeUsername(string? username) => (username ?? string.Empty).Trim().ToLowerInvariant();

    public static bool IsValidUsername(string? username) => UsernamePattern.IsMatch(NormalizeUsername(username));

    public static User Create(string username, string passwordHash, UserRole role, DateTimeOffset now)
    {
        Guard.Utc(now, nameof(now));

        var normalized = NormalizeUsername(username);
        if (!UsernamePattern.IsMatch(normalized))
        {
            throw new ArgumentException(
                "A username is 3 to 64 characters: letters, digits, dot, dash or underscore, starting with a letter or digit.",
                nameof(username));
        }

        if (string.IsNullOrWhiteSpace(passwordHash))
        {
            throw new ArgumentException("A password hash is required.", nameof(passwordHash));
        }

        if (!Enum.IsDefined(role))
        {
            throw new ArgumentOutOfRangeException(nameof(role), role, "Unknown role.");
        }

        return new User
        {
            Id = Ids.New(now),
            Username = normalized,
            PasswordHash = passwordHash,
            Role = role,
            CreatedAt = now,
            PasswordChangedAt = now
        };
    }

    public bool IsLockedOut(DateTimeOffset now) => LockedUntil is { } until && now < until;

    /// <summary>A disabled or locked account cannot sign in or refresh a session.</summary>
    public bool CanSignIn(DateTimeOffset now) => !IsDisabled && !IsLockedOut(now);

    public void RecordSuccessfulLogin(DateTimeOffset now)
    {
        Guard.Utc(now, nameof(now));

        LastLoginAt = now;
        FailedLoginCount = 0;
        LockedUntil = null;
    }

    /// <summary>Counts a failed attempt. Returns true when this failure locked the account.</summary>
    public bool RecordFailedLogin(DateTimeOffset now)
    {
        Guard.Utc(now, nameof(now));

        FailedLoginCount++;

        if (FailedLoginCount < MaxFailedLogins)
        {
            return false;
        }

        LockedUntil = now + LockoutDuration;
        FailedLoginCount = 0;
        return true;
    }

    public void ChangePasswordHash(string passwordHash, DateTimeOffset now)
    {
        Guard.Utc(now, nameof(now));

        if (string.IsNullOrWhiteSpace(passwordHash))
        {
            throw new ArgumentException("A password hash is required.", nameof(passwordHash));
        }

        PasswordHash = passwordHash;
        PasswordChangedAt = now;
    }

    /// <summary>Stores a stronger hash of the same password, for example after the hashing cost is raised. Not a password change.</summary>
    public void ReplacePasswordHash(string passwordHash)
    {
        if (string.IsNullOrWhiteSpace(passwordHash))
        {
            throw new ArgumentException("A password hash is required.", nameof(passwordHash));
        }

        PasswordHash = passwordHash;
    }

    /// <summary>Clears a lockout and the failure count without enabling a disabled account.</summary>
    public void Unlock()
    {
        FailedLoginCount = 0;
        LockedUntil = null;
    }

    public void ChangeRole(UserRole role)
    {
        if (!Enum.IsDefined(role))
        {
            throw new ArgumentOutOfRangeException(nameof(role), role, "Unknown role.");
        }

        Role = role;
    }

    public void Disable() => IsDisabled = true;

    /// <summary>Enabling also clears any lockout so an administrator can recover an account.</summary>
    public void Enable()
    {
        IsDisabled = false;
        FailedLoginCount = 0;
        LockedUntil = null;
    }
}
