using Noema.Domain;

namespace Noema.Scanning.Tests;

public sealed class ScanScopeTests
{
    private static ScanScope Scope(int max = 1024, params string[] ranges) =>
        new(ranges.Select(CidrRange.Parse), max);

    [Fact]
    public void Allows_targets_inside_an_allowed_range()
    {
        var scope = Scope(1024, "192.168.1.0/24");

        Assert.True(scope.Authorize(CidrRange.Parse("192.168.1.0/24")).IsAllowed);
        Assert.True(scope.Authorize(CidrRange.Parse("192.168.1.64/26")).IsAllowed);
    }

    [Fact]
    public void Refuses_everything_when_no_ranges_are_configured()
    {
        Assert.Equal(ScanAuthorizationOutcome.NotAuthorized, Scope(1024).Authorize(CidrRange.Parse("192.168.1.0/24")).Outcome);
    }

    [Fact]
    public void Refuses_targets_outside_every_range_and_oversized_or_reserved_ones()
    {
        var scope = Scope(256, "10.0.0.0/8");

        Assert.Equal(ScanAuthorizationOutcome.NotAuthorized, scope.Authorize(CidrRange.Parse("192.168.1.0/24")).Outcome);
        Assert.Equal(ScanAuthorizationOutcome.TooLarge, scope.Authorize(CidrRange.Parse("10.0.0.0/16")).Outcome);
        Assert.Equal(ScanAuthorizationOutcome.Forbidden, scope.Authorize(CidrRange.Parse("127.0.0.0/24")).Outcome);
    }

    [Fact]
    public void Rejects_bad_construction()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ScanScope([], 0));
        Assert.Throws<ArgumentNullException>(() => new ScanScope(null!, 10));
    }

    [Fact]
    public void Exposes_what_it_was_configured_with()
    {
        var scope = Scope(77, "10.0.0.0/8", "192.168.0.0/16");

        Assert.Equal(77, scope.MaxAddresses);
        Assert.Equal(2, scope.AllowedRanges.Count);
    }
}

public sealed class ScanEngineOptionsTests
{
    [Fact]
    public void Defaults_are_valid()
    {
        Assert.Empty(new ScanEngineOptions().Validate());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1025)]
    public void Concurrency_must_be_in_range(int value)
    {
        Assert.NotEmpty(new ScanEngineOptions { MaxConcurrency = value }.Validate());
    }

    [Theory]
    [InlineData(50)]
    [InlineData(31_000)]
    public void Probe_timeout_must_be_in_range(int milliseconds)
    {
        Assert.NotEmpty(new ScanEngineOptions { ProbeTimeout = TimeSpan.FromMilliseconds(milliseconds) }.Validate());
    }

    [Theory]
    [InlineData(50)]
    [InlineData(11_000)]
    public void Grace_must_be_in_range(int milliseconds)
    {
        Assert.NotEmpty(new ScanEngineOptions { ProbeTimeoutGrace = TimeSpan.FromMilliseconds(milliseconds) }.Validate());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(10_001)]
    public void Abort_threshold_must_be_in_range(int value)
    {
        Assert.NotEmpty(new ScanEngineOptions { AbortAfterConsecutiveErrors = value }.Validate());
    }

    [Fact]
    public void Boundary_values_are_accepted()
    {
        Assert.Empty(new ScanEngineOptions
        {
            MaxConcurrency = 1,
            ProbeTimeout = TimeSpan.FromMilliseconds(100),
            ProbeTimeoutGrace = TimeSpan.FromSeconds(10),
            AbortAfterConsecutiveErrors = 10_000
        }.Validate());
    }
}
