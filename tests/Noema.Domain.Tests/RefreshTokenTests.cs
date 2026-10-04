namespace Noema.Domain.Tests;

public sealed class RefreshTokenTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid UserId = Guid.NewGuid();
    private static readonly TimeSpan Week = TimeSpan.FromDays(7);

    [Fact]
    public void A_new_token_is_active_until_it_expires()
    {
        var token = RefreshToken.Issue(UserId, "hash", T0, Week);

        Assert.NotEqual(Guid.Empty, token.Id);
        Assert.Equal(UserId, token.UserId);
        Assert.Equal(T0 + Week, token.ExpiresAt);
        Assert.True(token.IsActive(T0));
        Assert.True(token.IsActive(T0 + Week - TimeSpan.FromSeconds(1)));
        Assert.False(token.IsActive(T0 + Week));
        Assert.True(token.IsExpired(T0 + Week));
    }

    [Fact]
    public void A_revoked_token_is_not_active_and_remembers_its_replacement()
    {
        var token = RefreshToken.Issue(UserId, "hash", T0, Week);
        var replacement = Guid.NewGuid();

        token.Revoke(T0.AddMinutes(5), replacement);

        Assert.True(token.IsRevoked);
        Assert.False(token.IsActive(T0.AddMinutes(6)));
        Assert.Equal(T0.AddMinutes(5), token.RevokedAt);
        Assert.Equal(replacement, token.ReplacedByTokenId);
    }

    [Fact]
    public void Revoking_twice_keeps_the_first_revocation()
    {
        var token = RefreshToken.Issue(UserId, "hash", T0, Week);
        var first = Guid.NewGuid();

        token.Revoke(T0.AddMinutes(5), first);
        token.Revoke(T0.AddMinutes(30), Guid.NewGuid());

        Assert.Equal(T0.AddMinutes(5), token.RevokedAt);
        Assert.Equal(first, token.ReplacedByTokenId);
    }

    [Fact]
    public void Issue_rejects_bad_input()
    {
        Assert.Throws<ArgumentException>(() => RefreshToken.Issue(Guid.Empty, "hash", T0, Week));
        Assert.Throws<ArgumentException>(() => RefreshToken.Issue(UserId, " ", T0, Week));
        Assert.Throws<ArgumentOutOfRangeException>(() => RefreshToken.Issue(UserId, "hash", T0, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => RefreshToken.Issue(UserId, "hash", T0, TimeSpan.FromDays(-1)));
        Assert.Throws<ArgumentException>(() =>
            RefreshToken.Issue(UserId, "hash", new DateTimeOffset(2026, 10, 4, 14, 0, 0, TimeSpan.FromHours(2)), Week));
    }
}
