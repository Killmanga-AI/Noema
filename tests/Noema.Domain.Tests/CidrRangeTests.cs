using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace Noema.Domain.Tests;

public sealed class CidrRangeTests
{
    [Theory]
    [InlineData("192.168.1.0/24", "192.168.1.0/24")]
    [InlineData("10.0.0.0/8", "10.0.0.0/8")]
    [InlineData("0.0.0.0/0", "0.0.0.0/0")]
    [InlineData("192.168.1.7/32", "192.168.1.7/32")]
    [InlineData("  172.16.0.0/12  ", "172.16.0.0/12")]
    [InlineData("fd00::/8", "fd00::/8")]
    [InlineData("2001:db8::/32", "2001:db8::/32")]
    public void Parses_valid_ranges(string input, string expected)
    {
        Assert.Equal(expected, CidrRange.Parse(input).ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("192.168.1.0")]
    [InlineData("192.168.1.0/")]
    [InlineData("/24")]
    [InlineData("192.168.1.0/24/8")]
    [InlineData("192.168.1.0/33")]
    [InlineData("192.168.1.0/-1")]
    [InlineData("192.168.1.0/2x")]
    [InlineData("192.168.1.0/0024")]
    [InlineData("192.168.1.5/24")]
    [InlineData("10.0.0.1/8")]
    [InlineData("10.1/16")]
    [InlineData("10/8")]
    [InlineData("010.0.0.0/8")]
    [InlineData("0x0a.0.0.0/8")]
    [InlineData("256.0.0.0/8")]
    [InlineData("10.0.0.0.0/8")]
    [InlineData("localhost/24")]
    [InlineData("fe80::1%eth0/64")]
    [InlineData("fd00::1/8")]
    [InlineData("fd00::/129")]
    [InlineData("::ffff:10.0.0.0/104")]
    public void Rejects_anything_ambiguous_or_malformed(string? input)
    {
        Assert.False(CidrRange.TryParse(input, out var result));
        Assert.Null(result);
        Assert.Throws<FormatException>(() => CidrRange.Parse(input!));
    }

    [Theory]
    [InlineData("192.168.1.0/24", "192.168.1.0", true)]
    [InlineData("192.168.1.0/24", "192.168.1.255", true)]
    [InlineData("192.168.1.0/24", "192.168.2.0", false)]
    [InlineData("192.168.1.0/24", "192.168.0.255", false)]
    [InlineData("10.0.0.0/8", "10.255.255.255", true)]
    [InlineData("10.0.0.0/8", "11.0.0.0", false)]
    [InlineData("192.168.1.64/26", "192.168.1.127", true)]
    [InlineData("192.168.1.64/26", "192.168.1.128", false)]
    [InlineData("192.168.1.7/32", "192.168.1.7", true)]
    [InlineData("192.168.1.7/32", "192.168.1.8", false)]
    [InlineData("0.0.0.0/0", "203.0.113.9", true)]
    [InlineData("fd00::/8", "fd12:3456::1", true)]
    [InlineData("fd00::/8", "fe80::1", false)]
    [InlineData("192.168.1.0/24", "fd00::1", false)]
    [InlineData("fd00::/8", "192.168.1.1", false)]
    public void Contains_checks_membership_across_prefix_boundaries(string range, string address, bool expected)
    {
        Assert.Equal(expected, CidrRange.Parse(range).Contains(IPAddress.Parse(address)));
    }

    [Fact]
    public void Contains_treats_ipv4_mapped_ipv6_as_ipv4()
    {
        var range = CidrRange.Parse("192.168.1.0/24");

        Assert.True(range.Contains(IPAddress.Parse("::ffff:192.168.1.10")));
        Assert.False(range.Contains(IPAddress.Parse("::ffff:192.168.2.10")));
    }

    [Theory]
    [InlineData("10.0.0.0/8", "10.1.0.0/16", true)]
    [InlineData("10.0.0.0/8", "10.0.0.0/8", true)]
    [InlineData("10.1.0.0/16", "10.0.0.0/8", false)]
    [InlineData("10.0.0.0/8", "11.0.0.0/16", false)]
    [InlineData("10.0.0.0/8", "fd00::/16", false)]
    public void Contains_range_requires_the_other_range_to_fit_inside(string outer, string inner, bool expected)
    {
        Assert.Equal(expected, CidrRange.Parse(outer).Contains(CidrRange.Parse(inner)));
    }

    [Fact]
    public void Reports_family_and_address_count()
    {
        Assert.Equal(AddressFamily.InterNetwork, CidrRange.Parse("10.0.0.0/8").Family);
        Assert.Equal(AddressFamily.InterNetworkV6, CidrRange.Parse("fd00::/8").Family);
        Assert.Equal(new BigInteger(256), CidrRange.Parse("192.168.1.0/24").AddressCount);
        Assert.Equal(BigInteger.One, CidrRange.Parse("192.168.1.7/32").AddressCount);
        Assert.Equal(new BigInteger(4_294_967_296), CidrRange.Parse("0.0.0.0/0").AddressCount);
        Assert.Equal(BigInteger.One << 64, CidrRange.Parse("2001:db8::/64").AddressCount);
    }

    [Fact]
    public void Equal_ranges_compare_equal()
    {
        Assert.Equal(CidrRange.Parse("192.168.1.0/24"), CidrRange.Parse(" 192.168.1.0/24 "));
        Assert.NotEqual(CidrRange.Parse("192.168.1.0/24"), CidrRange.Parse("192.168.1.0/25"));
    }

    [Fact]
    public void Ranges_sort_by_family_then_address_then_prefix()
    {
        var sorted = new[]
        {
            CidrRange.Parse("fd00::/8"),
            CidrRange.Parse("192.168.2.0/24"),
            CidrRange.Parse("10.0.0.0/16"),
            CidrRange.Parse("10.0.0.0/8"),
            CidrRange.Parse("192.168.1.0/24")
        }.OrderBy(r => r).Select(r => r.ToString()).ToArray();

        Assert.Equal("10.0.0.0/8", sorted[0]);
        Assert.Equal("10.0.0.0/16", sorted[1]);
        Assert.Equal("192.168.1.0/24", sorted[2]);
        Assert.Equal("192.168.2.0/24", sorted[3]);
        Assert.Equal("fd00::/8", sorted[4]);
    }

    [Fact]
    public void CompareTo_treats_null_as_smaller_and_equal_ranges_as_equal()
    {
        var range = CidrRange.Parse("10.0.0.0/8");

        Assert.Equal(1, range.CompareTo((CidrRange?)null));
        Assert.Equal(1, range.CompareTo((object?)null));
        Assert.Equal(0, range.CompareTo(CidrRange.Parse("10.0.0.0/8")));
        Assert.Throws<ArgumentException>(() => range.CompareTo("10.0.0.0/8"));
    }
}
