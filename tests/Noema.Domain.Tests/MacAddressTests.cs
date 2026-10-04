using System.Net.NetworkInformation;

namespace Noema.Domain.Tests;

public sealed class MacAddressTests
{
    [Theory]
    [InlineData("aa:bb:cc:dd:ee:01")]
    [InlineData("AA:BB:CC:DD:EE:01")]
    [InlineData("aa-bb-cc-dd-ee-01")]
    [InlineData("AABB.CCDD.EE01")]
    [InlineData("aabbccddee01")]
    [InlineData("  aa:bb:cc:dd:ee:01  ")]
    public void Parses_common_formats_to_one_canonical_form(string input)
    {
        Assert.Equal("aa:bb:cc:dd:ee:01", MacAddress.Parse(input).ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("aa:bb:cc:dd:ee")]
    [InlineData("aa:bb:cc:dd:ee:01:02")]
    [InlineData("aa:bb:cc:dd:ee:0g")]
    [InlineData("aa:bb-cc:dd-ee:01")]
    [InlineData("aabb.ccdd.ee")]
    [InlineData("aabbccddee0")]
    [InlineData("0xaabbccddee01")]
    public void Rejects_malformed_input(string? input)
    {
        Assert.False(MacAddress.TryParse(input, out var result));
        Assert.Null(result);
    }

    [Theory]
    [InlineData("00:00:00:00:00:00")]
    [InlineData("ff:ff:ff:ff:ff:ff")]
    [InlineData("01:00:5e:00:00:fb")]
    [InlineData("33:33:00:00:00:01")]
    public void Rejects_zero_broadcast_and_multicast(string input)
    {
        Assert.False(MacAddress.TryParse(input, out _));
        Assert.Throws<FormatException>(() => MacAddress.Parse(input));
    }

    [Fact]
    public void Equal_addresses_compare_equal_whatever_the_input_format()
    {
        Assert.Equal(MacAddress.Parse("AA-BB-CC-DD-EE-01"), MacAddress.Parse("aabb.ccdd.ee01"));
        Assert.NotEqual(MacAddress.Parse("aa:bb:cc:dd:ee:01"), MacAddress.Parse("aa:bb:cc:dd:ee:02"));
    }

    [Fact]
    public void Round_trips_through_physical_address_and_bytes()
    {
        var mac = MacAddress.Parse("aa:bb:cc:dd:ee:01");

        Assert.Equal(mac, MacAddress.FromPhysicalAddress(mac.ToPhysicalAddress()));
        Assert.Equal(mac, MacAddress.FromBytes(mac.ToPhysicalAddress().GetAddressBytes()));
    }

    [Fact]
    public void FromBytes_rejects_wrong_length_zero_and_multicast()
    {
        Assert.Throws<ArgumentException>(() => MacAddress.FromBytes(new byte[5]));
        Assert.Throws<ArgumentException>(() => MacAddress.FromBytes(new byte[6]));
        Assert.Throws<ArgumentException>(() => MacAddress.FromBytes(new byte[] { 0x01, 0, 0x5e, 0, 0, 0xfb }));
        Assert.Throws<ArgumentException>(() => MacAddress.FromPhysicalAddress(new PhysicalAddress(new byte[4])));
    }

    [Fact]
    public void Exposes_oui_and_locally_administered_bit()
    {
        var universal = MacAddress.Parse("00:1a:2b:3c:4d:5e");
        var local = MacAddress.Parse("02:1a:2b:3c:4d:5e");

        Assert.Equal("00:1a:2b", universal.Oui);
        Assert.False(universal.IsLocallyAdministered);
        Assert.True(local.IsLocallyAdministered);
    }
}
