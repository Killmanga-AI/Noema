using Noema.Api.Common;
using Noema.Domain;

namespace Noema.Api.Tests;

public sealed class EnumParsingTests
{
    [Theory]
    [InlineData("Admin", UserRole.Admin)]
    [InlineData("admin", UserRole.Admin)]
    [InlineData("  OPERATOR ", UserRole.Operator)]
    public void Parses_names_ignoring_case_and_padding(string input, UserRole expected)
    {
        Assert.True(EnumParsing.TryParseName<UserRole>(input, out var result));
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("1")]
    [InlineData("0")]
    [InlineData("99")]
    [InlineData("Admin,Operator")]
    [InlineData("Superuser")]
    [InlineData("-1")]
    public void Rejects_numbers_lists_and_unknown_names(string? input)
    {
        Assert.False(EnumParsing.TryParseName<UserRole>(input, out _));
    }

    [Fact]
    public void Probe_names_parse_individually_and_none_can_be_filtered_by_the_caller()
    {
        Assert.True(EnumParsing.TryParseName<ScanProbes>("Icmp", out var icmp));
        Assert.Equal(ScanProbes.Icmp, icmp);
        Assert.False(EnumParsing.TryParseName<ScanProbes>("Icmp,Arp", out _));
        Assert.False(EnumParsing.TryParseName<ScanProbes>("3", out _));
    }
}
