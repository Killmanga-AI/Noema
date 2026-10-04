namespace Noema.Domain.Tests;

public sealed class ScanTargetRulesTests
{
    [Theory]
    [InlineData("127.0.0.0/8")]
    [InlineData("127.0.0.1/32")]
    [InlineData("0.0.0.0/0")]
    [InlineData("0.0.0.0/8")]
    [InlineData("224.0.0.0/4")]
    [InlineData("239.1.1.0/24")]
    [InlineData("240.0.0.0/4")]
    [InlineData("255.255.255.255/32")]
    [InlineData("::1/128")]
    [InlineData("::/0")]
    [InlineData("ff02::/16")]
    [InlineData("128.0.0.0/1")]
    public void Reserved_space_is_never_scannable_even_when_only_partly_covered(string cidr)
    {
        Assert.True(ScanTargetRules.IsNeverScannable(CidrRange.Parse(cidr)));
    }

    [Theory]
    [InlineData("192.168.1.0/24")]
    [InlineData("10.0.0.0/8")]
    [InlineData("172.16.0.0/12")]
    [InlineData("100.64.0.0/10")]
    [InlineData("203.0.113.0/24")]
    [InlineData("fd00::/8")]
    [InlineData("fe80::/10")]
    public void Ordinary_ranges_are_not_blocked(string cidr)
    {
        Assert.False(ScanTargetRules.IsNeverScannable(CidrRange.Parse(cidr)));
    }

    [Theory]
    [InlineData("192.168.1.0/24", true)]
    [InlineData("192.168.0.0/16", true)]
    [InlineData("10.20.0.0/16", true)]
    [InlineData("172.16.0.0/12", true)]
    [InlineData("172.31.255.0/24", true)]
    [InlineData("100.64.1.0/24", true)]
    [InlineData("169.254.0.0/16", true)]
    [InlineData("fd12:3456::/32", true)]
    [InlineData("fe80::/64", true)]
    [InlineData("172.32.0.0/16", false)]
    [InlineData("172.0.0.0/8", false)]
    [InlineData("192.0.0.0/8", false)]
    [InlineData("203.0.113.0/24", false)]
    [InlineData("8.8.8.0/24", false)]
    [InlineData("0.0.0.0/0", false)]
    [InlineData("2001:db8::/32", false)]
    public void Private_means_entirely_inside_private_space(string cidr, bool expected)
    {
        Assert.Equal(expected, ScanTargetRules.IsPrivate(CidrRange.Parse(cidr)));
    }

    [Fact]
    public void Authorization_check_blocks_reserved_and_public_ranges_unless_public_is_allowed()
    {
        Assert.Null(ScanTargetRules.ValidateForAuthorization(CidrRange.Parse("192.168.1.0/24"), allowPublic: false));
        Assert.NotNull(ScanTargetRules.ValidateForAuthorization(CidrRange.Parse("203.0.113.0/24"), allowPublic: false));
        Assert.Null(ScanTargetRules.ValidateForAuthorization(CidrRange.Parse("203.0.113.0/24"), allowPublic: true));
        Assert.NotNull(ScanTargetRules.ValidateForAuthorization(CidrRange.Parse("127.0.0.0/8"), allowPublic: true));
        Assert.NotNull(ScanTargetRules.ValidateForAuthorization(CidrRange.Parse("0.0.0.0/0"), allowPublic: true));
    }

    [Fact]
    public void Max_addresses_uses_the_configured_value_or_the_default()
    {
        Assert.Equal(new System.Numerics.BigInteger(ScanTargetRules.DefaultMaxScanAddresses), ScanTargetRules.MaxAddressesOrDefault(null));
        Assert.Equal(new System.Numerics.BigInteger(ScanTargetRules.DefaultMaxScanAddresses), ScanTargetRules.MaxAddressesOrDefault(0));
        Assert.Equal(new System.Numerics.BigInteger(1024), ScanTargetRules.MaxAddressesOrDefault(1024));
    }
}
