using System.Net;

namespace Noema.Domain.Tests;

public sealed class IpAddressNormalizerTests
{
    [Fact]
    public void Maps_ipv4_in_ipv6_back_to_ipv4()
    {
        Assert.Equal(IPAddress.Parse("192.168.1.10"), IpAddressNormalizer.Normalize(IPAddress.Parse("::ffff:192.168.1.10")));
    }

    [Fact]
    public void Drops_ipv6_scope_ids()
    {
        var scoped = IPAddress.Parse("fe80::1%3");

        var normalized = IpAddressNormalizer.Normalize(scoped);

        Assert.Equal(0, normalized.ScopeId);
        Assert.Equal(IPAddress.Parse("fe80::1"), normalized);
    }

    [Theory]
    [InlineData("192.168.1.10", true)]
    [InlineData("10.0.0.1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("2001:db8::5", true)]
    [InlineData("0.0.0.0", false)]
    [InlineData("::", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("::1", false)]
    [InlineData("255.255.255.255", false)]
    [InlineData("224.0.0.251", false)]
    [InlineData("239.255.255.250", false)]
    [InlineData("ff02::fb", false)]
    public void Decides_which_addresses_can_identify_a_device(string address, bool expected)
    {
        Assert.Equal(expected, IpAddressNormalizer.IsAssignable(IPAddress.Parse(address)));
    }
}
