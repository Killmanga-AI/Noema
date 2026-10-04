namespace Noema.Domain.Tests;

public sealed class AuthorizedRangeTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid Admin = Guid.NewGuid();

    [Fact]
    public void Creates_a_private_range_with_a_trimmed_description()
    {
        var range = AuthorizedRange.Create(CidrRange.Parse("192.168.1.0/24"), "  Home lab  ", Admin, T0, allowPublic: false);

        Assert.NotEqual(Guid.Empty, range.Id);
        Assert.Equal(CidrRange.Parse("192.168.1.0/24"), range.Range);
        Assert.Equal("Home lab", range.Description);
        Assert.Equal(Admin, range.CreatedByUserId);
        Assert.Equal(T0, range.CreatedAt);
    }

    [Fact]
    public void Blank_descriptions_become_null()
    {
        Assert.Null(AuthorizedRange.Create(CidrRange.Parse("192.168.1.0/24"), "   ", Admin, T0, false).Description);
        Assert.Null(AuthorizedRange.Create(CidrRange.Parse("192.168.1.0/24"), null, Admin, T0, false).Description);
    }

    [Fact]
    public void Rejects_descriptions_over_the_limit()
    {
        Assert.Throws<ArgumentException>(() => AuthorizedRange.Create(
            CidrRange.Parse("192.168.1.0/24"), new string('x', AuthorizedRange.MaxDescriptionLength + 1), Admin, T0, false));
    }

    [Fact]
    public void Rejects_public_ranges_unless_allowed()
    {
        var publicRange = CidrRange.Parse("203.0.113.0/24");

        Assert.Throws<ArgumentException>(() => AuthorizedRange.Create(publicRange, null, Admin, T0, allowPublic: false));
        Assert.NotNull(AuthorizedRange.Create(publicRange, null, Admin, T0, allowPublic: true));
    }

    [Theory]
    [InlineData("127.0.0.0/8")]
    [InlineData("0.0.0.0/0")]
    [InlineData("224.0.0.0/4")]
    public void Rejects_reserved_ranges_even_when_public_is_allowed(string cidr)
    {
        Assert.Throws<ArgumentException>(() => AuthorizedRange.Create(CidrRange.Parse(cidr), null, Admin, T0, allowPublic: true));
    }

    [Fact]
    public void Rejects_null_range_and_non_utc_time()
    {
        Assert.Throws<ArgumentNullException>(() => AuthorizedRange.Create(null!, null, Admin, T0, false));
        Assert.Throws<ArgumentException>(() => AuthorizedRange.Create(
            CidrRange.Parse("192.168.1.0/24"), null, Admin, new DateTimeOffset(2026, 10, 4, 14, 0, 0, TimeSpan.FromHours(2)), false));
    }
}
