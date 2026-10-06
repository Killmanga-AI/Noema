namespace Noema.Domain.Tests;

public sealed class EnrollmentTokenTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid Admin = Guid.NewGuid();

    private static EnrollmentToken NewToken(TimeSpan? lifetime = null, string? label = "warehouse") =>
        EnrollmentToken.Issue("hash", label, Admin, T0, lifetime ?? TimeSpan.FromHours(24));

    [Fact]
    public void A_new_token_is_usable_until_it_expires()
    {
        var token = NewToken();

        Assert.NotEqual(Guid.Empty, token.Id);
        Assert.Equal("hash", token.TokenHash);
        Assert.Equal("warehouse", token.Label);
        Assert.Equal(Admin, token.CreatedByUserId);
        Assert.Equal(T0.AddHours(24), token.ExpiresAt);
        Assert.True(token.IsUsable(T0));
        Assert.True(token.IsUsable(T0.AddHours(24).AddSeconds(-1)));
        Assert.False(token.IsUsable(T0.AddHours(24)));
    }

    [Fact]
    public void Redeeming_marks_it_used_and_a_second_use_is_refused()
    {
        var token = NewToken();
        var agent = Guid.NewGuid();

        token.Redeem(agent, T0.AddMinutes(1));

        Assert.True(token.IsUsed);
        Assert.Equal(T0.AddMinutes(1), token.UsedAt);
        Assert.Equal(agent, token.AgentId);
        Assert.False(token.IsUsable(T0.AddMinutes(2)));
        Assert.Throws<InvalidOperationException>(() => token.Redeem(Guid.NewGuid(), T0.AddMinutes(2)));
    }

    [Fact]
    public void An_expired_token_cannot_be_redeemed()
    {
        var token = NewToken(TimeSpan.FromMinutes(10));

        Assert.Throws<InvalidOperationException>(() => token.Redeem(Guid.NewGuid(), T0.AddMinutes(10)));
        Assert.False(token.IsUsed);
    }

    [Theory]
    [InlineData(30)]
    [InlineData(0)]
    [InlineData(-5)]
    public void Lifetimes_below_one_minute_are_rejected(int seconds)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => NewToken(TimeSpan.FromSeconds(seconds)));
    }

    [Fact]
    public void Lifetimes_are_limited_to_seven_days_and_the_boundaries_are_allowed()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => NewToken(TimeSpan.FromDays(7) + TimeSpan.FromSeconds(1)));
        Assert.NotNull(NewToken(TimeSpan.FromDays(7)));
        Assert.NotNull(NewToken(TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void Labels_are_trimmed_blank_ones_become_null_and_long_ones_are_rejected()
    {
        Assert.Equal("north", NewToken(label: "  north ").Label);
        Assert.Null(NewToken(label: "   ").Label);
        Assert.Null(NewToken(label: null).Label);
        Assert.Throws<ArgumentException>(() => NewToken(label: new string('x', EnrollmentToken.MaxLabelLength + 1)));
    }

    [Fact]
    public void Issue_and_redeem_reject_bad_input()
    {
        Assert.Throws<ArgumentException>(() => EnrollmentToken.Issue(" ", null, Admin, T0, TimeSpan.FromHours(1)));
        Assert.Throws<ArgumentException>(() => EnrollmentToken.Issue("hash", null, Guid.Empty, T0, TimeSpan.FromHours(1)));
        Assert.Throws<ArgumentException>(() =>
            EnrollmentToken.Issue("hash", null, Admin, new DateTimeOffset(2026, 10, 4, 14, 0, 0, TimeSpan.FromHours(2)), TimeSpan.FromHours(1)));
        Assert.Throws<ArgumentException>(() => NewToken().Redeem(Guid.Empty, T0));
    }
}
