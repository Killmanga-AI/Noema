namespace Noema.Domain.Tests;

public sealed class UserTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);

    private static User NewUser(UserRole role = UserRole.Operator) => User.Create("latif", "hash-1", role, T0);

    [Fact]
    public void Create_normalizes_the_username_and_starts_clean()
    {
        var user = User.Create("  Latif.Rajabu  ", "hash-1", UserRole.Admin, T0);

        Assert.NotEqual(Guid.Empty, user.Id);
        Assert.Equal("latif.rajabu", user.Username);
        Assert.Equal(UserRole.Admin, user.Role);
        Assert.False(user.IsDisabled);
        Assert.Equal(0, user.FailedLoginCount);
        Assert.Null(user.LockedUntil);
        Assert.Null(user.LastLoginAt);
        Assert.Equal(T0, user.CreatedAt);
        Assert.Equal(T0, user.PasswordChangedAt);
    }

    [Theory]
    [InlineData("ab")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("has space")]
    [InlineData("-leading")]
    [InlineData(".leading")]
    [InlineData("bad!char")]
    [InlineData("user@example.com")]
    [InlineData("caf\u00e9user")]
    public void Create_rejects_invalid_usernames(string username)
    {
        Assert.Throws<ArgumentException>(() => User.Create(username, "hash", UserRole.Operator, T0));
        Assert.False(User.IsValidUsername(username));
    }

    [Fact]
    public void Create_rejects_usernames_over_64_characters()
    {
        Assert.Throws<ArgumentException>(() => User.Create(new string('a', 65), "hash", UserRole.Operator, T0));
        Assert.NotNull(User.Create(new string('a', 64), "hash", UserRole.Operator, T0));
    }

    [Fact]
    public void Create_rejects_empty_hash_unknown_role_and_non_utc_time()
    {
        Assert.Throws<ArgumentException>(() => User.Create("latif", "  ", UserRole.Operator, T0));
        Assert.Throws<ArgumentOutOfRangeException>(() => User.Create("latif", "hash", (UserRole)99, T0));
        Assert.Throws<ArgumentException>(() =>
            User.Create("latif", "hash", UserRole.Operator, new DateTimeOffset(2026, 10, 4, 14, 0, 0, TimeSpan.FromHours(2))));
    }

    [Fact]
    public void Failures_below_the_limit_do_not_lock_the_account()
    {
        var user = NewUser();

        for (var i = 0; i < User.MaxFailedLogins - 1; i++)
        {
            Assert.False(user.RecordFailedLogin(T0.AddSeconds(i)));
        }

        Assert.False(user.IsLockedOut(T0.AddMinutes(1)));
        Assert.Equal(User.MaxFailedLogins - 1, user.FailedLoginCount);
    }

    [Fact]
    public void The_failure_that_hits_the_limit_locks_the_account_for_the_lockout_period()
    {
        var user = NewUser();
        var locked = false;

        for (var i = 0; i < User.MaxFailedLogins; i++)
        {
            locked = user.RecordFailedLogin(T0);
        }

        Assert.True(locked);
        Assert.True(user.IsLockedOut(T0));
        Assert.True(user.IsLockedOut(T0 + User.LockoutDuration - TimeSpan.FromSeconds(1)));
        Assert.False(user.IsLockedOut(T0 + User.LockoutDuration));
        Assert.False(user.CanSignIn(T0));
        Assert.True(user.CanSignIn(T0 + User.LockoutDuration));
    }

    [Fact]
    public void After_a_lockout_the_user_gets_a_fresh_set_of_attempts()
    {
        var user = NewUser();
        for (var i = 0; i < User.MaxFailedLogins; i++)
        {
            user.RecordFailedLogin(T0);
        }

        var later = T0 + User.LockoutDuration + TimeSpan.FromSeconds(1);

        Assert.Equal(0, user.FailedLoginCount);
        Assert.False(user.RecordFailedLogin(later));
        Assert.False(user.IsLockedOut(later));
    }

    [Fact]
    public void A_successful_login_clears_failures_and_lockout_and_records_the_time()
    {
        var user = NewUser();
        user.RecordFailedLogin(T0);
        user.RecordFailedLogin(T0);

        user.RecordSuccessfulLogin(T0.AddMinutes(1));

        Assert.Equal(0, user.FailedLoginCount);
        Assert.Null(user.LockedUntil);
        Assert.Equal(T0.AddMinutes(1), user.LastLoginAt);
    }

    [Fact]
    public void A_disabled_user_cannot_sign_in_and_enabling_clears_the_lockout()
    {
        var user = NewUser();
        for (var i = 0; i < User.MaxFailedLogins; i++)
        {
            user.RecordFailedLogin(T0);
        }

        user.Disable();
        Assert.True(user.IsDisabled);
        Assert.False(user.CanSignIn(T0 + TimeSpan.FromDays(1)));

        user.Enable();
        Assert.False(user.IsDisabled);
        Assert.Null(user.LockedUntil);
        Assert.True(user.CanSignIn(T0));
    }

    [Fact]
    public void Changing_the_password_hash_records_when_and_rejects_blank_hashes()
    {
        var user = NewUser();

        user.ChangePasswordHash("hash-2", T0.AddDays(1));

        Assert.Equal("hash-2", user.PasswordHash);
        Assert.Equal(T0.AddDays(1), user.PasswordChangedAt);
        Assert.Throws<ArgumentException>(() => user.ChangePasswordHash(" ", T0.AddDays(2)));
    }

    [Fact]
    public void Role_changes_reject_unknown_roles()
    {
        var user = NewUser();

        user.ChangeRole(UserRole.Admin);
        Assert.Equal(UserRole.Admin, user.Role);
        Assert.Throws<ArgumentOutOfRangeException>(() => user.ChangeRole((UserRole)42));
    }

    [Fact]
    public void ReplacePasswordHash_changes_the_hash_but_not_the_password_changed_time()
    {
        var user = NewUser();

        user.ReplacePasswordHash("stronger-hash");

        Assert.Equal("stronger-hash", user.PasswordHash);
        Assert.Equal(T0, user.PasswordChangedAt);
        Assert.Throws<ArgumentException>(() => user.ReplacePasswordHash(" "));
    }

    [Fact]
    public void Unlock_clears_the_lockout_without_enabling_a_disabled_account()
    {
        var user = NewUser();
        for (var i = 0; i < User.MaxFailedLogins; i++)
        {
            user.RecordFailedLogin(T0);
        }

        user.Disable();
        user.Unlock();

        Assert.Null(user.LockedUntil);
        Assert.Equal(0, user.FailedLoginCount);
        Assert.True(user.IsDisabled);
        Assert.False(user.CanSignIn(T0));
    }
}
