using System.Numerics;

namespace Noema.Domain.Tests;

public sealed class ScanAuthorizationPolicyTests
{
    private static readonly BigInteger Limit = 65_536;

    private static readonly CidrRange[] Authorized =
    [
        CidrRange.Parse("192.168.1.0/24"),
        CidrRange.Parse("10.20.0.0/16")
    ];

    private static ScanAuthorizationResult Evaluate(string target, params CidrRange[] ranges) =>
        ScanAuthorizationPolicy.Evaluate(CidrRange.Parse(target), ranges.Length == 0 ? Authorized : ranges, Limit);

    [Theory]
    [InlineData("192.168.1.0/24")]
    [InlineData("192.168.1.128/25")]
    [InlineData("192.168.1.7/32")]
    [InlineData("10.20.0.0/16")]
    [InlineData("10.20.5.0/24")]
    public void Targets_inside_an_authorized_range_are_allowed(string target)
    {
        var result = Evaluate(target);

        Assert.True(result.IsAllowed);
        Assert.Equal(ScanAuthorizationOutcome.Allowed, result.Outcome);
        Assert.Null(result.Reason);
    }

    [Theory]
    [InlineData("192.168.2.0/24")]
    [InlineData("192.168.0.0/16")]
    [InlineData("192.168.0.0/23")]
    [InlineData("10.0.0.0/8")]
    [InlineData("10.21.0.0/16")]
    [InlineData("8.8.8.0/24")]
    [InlineData("fd00::/64")]
    public void Targets_not_fully_inside_an_authorized_range_are_refused(string target)
    {
        var result = Evaluate(target);

        Assert.False(result.IsAllowed);
        Assert.Equal(ScanAuthorizationOutcome.NotAuthorized, result.Outcome);
        Assert.NotNull(result.Reason);
    }

    [Fact]
    public void A_target_that_straddles_two_authorized_ranges_is_refused()
    {
        var result = ScanAuthorizationPolicy.Evaluate(
            CidrRange.Parse("192.168.0.0/23"),
            [CidrRange.Parse("192.168.0.0/24"), CidrRange.Parse("192.168.1.0/24")],
            Limit);

        Assert.Equal(ScanAuthorizationOutcome.NotAuthorized, result.Outcome);
    }

    [Fact]
    public void Nothing_is_allowed_when_no_ranges_are_authorized()
    {
        var result = ScanAuthorizationPolicy.Evaluate(CidrRange.Parse("192.168.1.0/24"), [], Limit);

        Assert.Equal(ScanAuthorizationOutcome.NotAuthorized, result.Outcome);
    }

    [Theory]
    [InlineData("127.0.0.0/8")]
    [InlineData("0.0.0.0/0")]
    [InlineData("224.0.0.0/24")]
    public void Reserved_targets_are_forbidden_even_if_an_authorized_range_covers_them(string target)
    {
        var result = ScanAuthorizationPolicy.Evaluate(CidrRange.Parse(target), [CidrRange.Parse("0.0.0.0/0")], Limit);

        Assert.Equal(ScanAuthorizationOutcome.Forbidden, result.Outcome);
    }

    [Fact]
    public void Targets_over_the_size_limit_are_refused_even_when_authorized()
    {
        var result = ScanAuthorizationPolicy.Evaluate(
            CidrRange.Parse("10.0.0.0/8"),
            [CidrRange.Parse("10.0.0.0/8")],
            Limit);

        Assert.Equal(ScanAuthorizationOutcome.TooLarge, result.Outcome);
    }

    [Fact]
    public void A_target_exactly_at_the_limit_is_allowed()
    {
        var result = ScanAuthorizationPolicy.Evaluate(
            CidrRange.Parse("10.20.0.0/16"),
            [CidrRange.Parse("10.0.0.0/8")],
            Limit);

        Assert.True(result.IsAllowed);
    }

    [Fact]
    public void Large_ipv6_targets_hit_the_size_limit()
    {
        var result = ScanAuthorizationPolicy.Evaluate(
            CidrRange.Parse("fd00::/64"),
            [CidrRange.Parse("fd00::/8")],
            Limit);

        Assert.Equal(ScanAuthorizationOutcome.TooLarge, result.Outcome);
    }
}
