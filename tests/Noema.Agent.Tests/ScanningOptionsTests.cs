using Noema.Domain;

namespace Noema.Agent.Tests;

public sealed class ScanningOptionsTests
{
    private static ScanningOptions Valid() => new() { AllowedRanges = ["192.168.1.0/24"] };

    [Fact]
    public void Defaults_are_valid_and_allow_nothing()
    {
        var options = new ScanningOptions();

        Assert.Empty(options.Validate());
        Assert.Empty(options.BuildScope().AllowedRanges);
    }

    [Fact]
    public void Configured_ranges_become_the_scope()
    {
        var scope = new ScanningOptions { AllowedRanges = ["192.168.1.0/24", "10.0.0.0/8"], MaxAddressesPerScan = 500 }.BuildScope();

        Assert.Equal(2, scope.AllowedRanges.Count);
        Assert.Equal(500, scope.MaxAddresses);
        Assert.True(scope.Authorize(CidrRange.Parse("192.168.1.0/25")).IsAllowed);
    }

    [Theory]
    [InlineData("not-a-range")]
    [InlineData("192.168.1.5/24")]
    [InlineData("10.1/16")]
    [InlineData("203.0.113.0/24")]
    [InlineData("0.0.0.0/0")]
    [InlineData("127.0.0.0/8")]
    public void Bad_or_unsafe_ranges_are_reported_by_name(string range)
    {
        var problems = new ScanningOptions { AllowedRanges = [range] }.Validate();

        Assert.Contains("Scanning:AllowedRanges", Assert.Single(problems));
    }

    [Fact]
    public void Public_ranges_need_the_explicit_switch_but_reserved_ones_never_pass()
    {
        Assert.Empty(new ScanningOptions { AllowedRanges = ["203.0.113.0/24"], AllowPublicRanges = true }.Validate());
        Assert.NotEmpty(new ScanningOptions { AllowedRanges = ["127.0.0.0/8"], AllowPublicRanges = true }.Validate());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16_777_217)]
    public void The_address_limit_must_be_in_range(int value)
    {
        var options = Valid();
        options.MaxAddressesPerScan = value;

        Assert.Contains("MaxAddressesPerScan", string.Join(" ", options.Validate()));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(10_001)]
    [InlineData(double.NaN)]
    public void The_packet_rate_must_be_positive_and_bounded(double value)
    {
        var options = Valid();
        options.PacketsPerSecond = value;

        Assert.Contains("PacketsPerSecond", string.Join(" ", options.Validate()));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(10_001)]
    public void The_burst_must_be_in_range(int value)
    {
        var options = Valid();
        options.Burst = value;

        Assert.Contains("Burst", string.Join(" ", options.Validate()));
    }

    [Fact]
    public void Engine_limits_are_validated_too()
    {
        var options = Valid();
        options.MaxConcurrency = 0;
        options.ProbeTimeoutMilliseconds = 5;

        var text = string.Join(" ", options.Validate());

        Assert.Contains("MaxConcurrency", text);
        Assert.Contains("ProbeTimeout", text);
    }

    [Fact]
    public void Engine_options_use_the_configured_values()
    {
        var engine = new ScanningOptions
        {
            MaxConcurrency = 12,
            ProbeTimeoutMilliseconds = 750,
            ProbeTimeoutGraceMilliseconds = 250,
            AbortAfterConsecutiveErrors = 9
        }.BuildEngineOptions();

        Assert.Equal(12, engine.MaxConcurrency);
        Assert.Equal(TimeSpan.FromMilliseconds(750), engine.ProbeTimeout);
        Assert.Equal(TimeSpan.FromMilliseconds(250), engine.ProbeTimeoutGrace);
        Assert.Equal(9, engine.AbortAfterConsecutiveErrors);
    }

    [Fact]
    public void The_options_validator_wraps_the_same_checks()
    {
        var validator = new ScanningOptionsValidator();

        Assert.True(validator.Validate(null, Valid()).Succeeded);
        Assert.True(validator.Validate(null, new ScanningOptions { AllowedRanges = ["nope"] }).Failed);
    }
}
