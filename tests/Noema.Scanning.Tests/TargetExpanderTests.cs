using System.Net;
using System.Numerics;
using Noema.Domain;

namespace Noema.Scanning.Tests;

public sealed class TargetExpanderTests
{
    private static List<string> Expand(string cidr, int max = 100_000) =>
        TargetExpander.Expand(CidrRange.Parse(cidr), max).Select(a => a.ToString()).ToList();

    [Fact]
    public void A_slash_24_skips_the_network_and_broadcast_addresses()
    {
        var addresses = Expand("192.168.1.0/24");

        Assert.Equal(254, addresses.Count);
        Assert.Equal("192.168.1.1", addresses[0]);
        Assert.Equal("192.168.1.254", addresses[^1]);
        Assert.DoesNotContain("192.168.1.0", addresses);
        Assert.DoesNotContain("192.168.1.255", addresses);
    }

    [Fact]
    public void A_slash_30_has_two_usable_hosts()
    {
        Assert.Equal(["10.0.0.5", "10.0.0.6"], Expand("10.0.0.4/30"));
    }

    [Fact]
    public void Slash_31_and_slash_32_keep_every_address()
    {
        Assert.Equal(["10.0.0.4", "10.0.0.5"], Expand("10.0.0.4/31"));
        Assert.Equal(["10.0.0.7"], Expand("10.0.0.7/32"));
    }

    [Theory]
    [InlineData("192.168.1.0/24", 254)]
    [InlineData("192.168.1.0/30", 2)]
    [InlineData("192.168.1.0/31", 2)]
    [InlineData("192.168.1.7/32", 1)]
    [InlineData("10.0.0.0/16", 65534)]
    [InlineData("10.0.0.0/8", 16777214)]
    public void Count_matches_what_expansion_would_produce(string cidr, long expected)
    {
        Assert.Equal(new BigInteger(expected), TargetExpander.Count(CidrRange.Parse(cidr)));
    }

    [Fact]
    public void Addresses_come_out_in_ascending_order_across_octet_boundaries()
    {
        var addresses = Expand("10.0.0.0/23", 1000);

        Assert.Equal("10.0.0.1", addresses[0]);
        Assert.Equal("10.0.0.255", addresses[254]);
        Assert.Equal("10.0.1.0", addresses[255]);
        Assert.Equal("10.0.1.254", addresses[^1]);
        Assert.Equal(addresses.Count, addresses.Distinct().Count());
    }

    [Fact]
    public void Ranges_larger_than_the_limit_are_refused_before_any_work()
    {
        Assert.Throws<ArgumentException>(() => TargetExpander.Expand(CidrRange.Parse("10.0.0.0/16"), 1000));
        Assert.Throws<ArgumentException>(() => TargetExpander.Expand(CidrRange.Parse("fd00::/64"), 65_536));
        Assert.Throws<ArgumentOutOfRangeException>(() => TargetExpander.Expand(CidrRange.Parse("10.0.0.0/24"), 0));
    }

    [Fact]
    public void A_range_exactly_at_the_limit_is_allowed()
    {
        Assert.Equal(254, TargetExpander.Expand(CidrRange.Parse("10.0.0.0/24"), 254).Count());
    }

    [Fact]
    public void Expansion_is_lazy_so_a_huge_range_costs_nothing_until_enumerated()
    {
        var first = TargetExpander.Expand(CidrRange.Parse("10.0.0.0/8"), int.MaxValue).Take(3).Select(a => a.ToString()).ToList();

        Assert.Equal(["10.0.0.1", "10.0.0.2", "10.0.0.3"], first);
    }

    [Fact]
    public void Ipv6_ranges_expand_without_dropping_the_ends()
    {
        var addresses = Expand("fd00::/126");

        Assert.Equal(["fd00::", "fd00::1", "fd00::2", "fd00::3"], addresses);
    }

    [Fact]
    public void Unusable_addresses_are_skipped_even_inside_an_allowed_looking_range()
    {
        Assert.Empty(Expand("127.0.0.0/30"));
        Assert.Equal(["0.0.0.1", "0.0.0.2"], Expand("0.0.0.0/30").Where(a => a != "0.0.0.0").ToList());
    }

    [Fact]
    public void Expansion_yields_real_ip_addresses_of_the_right_family()
    {
        Assert.All(TargetExpander.Expand(CidrRange.Parse("10.0.0.0/30"), 10), a => Assert.Equal(System.Net.Sockets.AddressFamily.InterNetwork, a.AddressFamily));
        Assert.All(TargetExpander.Expand(CidrRange.Parse("fd00::/126"), 10), a => Assert.Equal(System.Net.Sockets.AddressFamily.InterNetworkV6, a.AddressFamily));
    }
}
