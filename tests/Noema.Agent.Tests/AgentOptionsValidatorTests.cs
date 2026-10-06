namespace Noema.Agent.Tests;

public sealed class AgentOptionsValidatorTests
{
    private readonly AgentOptionsValidator validator = new();

    private static AgentOptions Build(string? url, TimeSpan? interval = null) => new()
    {
        ControlPlaneUrl = url is null ? null : new Uri(url, UriKind.RelativeOrAbsolute),
        PollInterval = interval ?? TimeSpan.FromSeconds(30)
    };

    [Theory]
    [InlineData("https://noema.example.com")]
    [InlineData("https://10.0.0.5:8443")]
    [InlineData("http://localhost:8080")]
    [InlineData("http://127.0.0.1:8080")]
    public void Accepts_valid_control_plane_urls(string url)
    {
        Assert.True(validator.Validate(null, Build(url)).Succeeded);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("/relative/path")]
    [InlineData("http://noema.example.com")]
    [InlineData("http://10.0.0.5:8080")]
    [InlineData("ftp://noema.example.com")]
    public void Rejects_missing_relative_or_insecure_urls(string? url)
    {
        var result = validator.Validate(null, Build(url));

        Assert.True(result.Failed);
        Assert.Contains("ControlPlaneUrl", result.FailureMessage);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(500)]
    [InlineData(301_000)]
    public void Rejects_poll_intervals_outside_the_allowed_range(int milliseconds)
    {
        var result = validator.Validate(null, Build("https://noema.example.com", TimeSpan.FromMilliseconds(milliseconds)));

        Assert.True(result.Failed);
        Assert.Contains("PollInterval", result.FailureMessage);
    }

    [Theory]
    [InlineData(1_000)]
    [InlineData(300_000)]
    public void Accepts_poll_intervals_on_the_boundaries(int milliseconds)
    {
        Assert.True(validator.Validate(null, Build("https://noema.example.com", TimeSpan.FromMilliseconds(milliseconds))).Succeeded);
    }

    [Fact]
    public void Reports_every_problem_at_once()
    {
        var result = validator.Validate(null, Build(null, TimeSpan.Zero));

        Assert.Contains("ControlPlaneUrl", result.FailureMessage);
        Assert.Contains("PollInterval", result.FailureMessage);
    }
}

public sealed class AgentOptionsRuntimeValidatorTests
{
    private readonly AgentOptionsValidator validator = new();

    private static AgentOptions Valid() => new() { ControlPlaneUrl = new Uri("https://noema.example.com") };

    [Fact]
    public void The_new_defaults_are_valid()
    {
        Assert.True(validator.Validate(null, Valid()).Succeeded);
    }

    [Theory]
    [InlineData(500)]
    [InlineData(31_000)]
    public void The_report_interval_must_stay_well_under_the_lease(int milliseconds)
    {
        var options = Valid();
        options.ReportInterval = TimeSpan.FromMilliseconds(milliseconds);

        Assert.Contains("ReportInterval", validator.Validate(null, options).FailureMessage);
    }

    [Fact]
    public void The_report_interval_boundaries_are_accepted()
    {
        var options = Valid();
        options.ReportInterval = TimeSpan.FromSeconds(1);
        Assert.True(validator.Validate(null, options).Succeeded);

        options.ReportInterval = TimeSpan.FromSeconds(30);
        Assert.True(validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void The_backoff_cap_cannot_be_below_the_poll_interval_or_above_an_hour()
    {
        var below = Valid();
        below.PollInterval = TimeSpan.FromSeconds(60);
        below.MaxBackoff = TimeSpan.FromSeconds(30);
        Assert.Contains("MaxBackoff", validator.Validate(null, below).FailureMessage);

        var above = Valid();
        above.MaxBackoff = TimeSpan.FromHours(2);
        Assert.Contains("MaxBackoff", validator.Validate(null, above).FailureMessage);

        var edge = Valid();
        edge.MaxBackoff = TimeSpan.FromHours(1);
        Assert.True(validator.Validate(null, edge).Succeeded);
    }

    [Theory]
    [InlineData("https://noema.example.com", true)]
    [InlineData("http://localhost:8080", true)]
    [InlineData("http://127.0.0.1:8080", true)]
    [InlineData("http://noema.example.com", false)]
    [InlineData("ftp://noema.example.com", false)]
    public void The_shared_address_rule_is_https_or_loopback(string url, bool acceptable)
    {
        Assert.Equal(acceptable, ControlPlaneUrlRules.Check(new Uri(url)) is null);
    }

    [Fact]
    public void A_missing_or_relative_address_is_named_by_the_setting()
    {
        Assert.Contains("--server", ControlPlaneUrlRules.Check(null, "--server"));
        Assert.Contains("Agent:ControlPlaneUrl", ControlPlaneUrlRules.Check(new Uri("/relative", UriKind.Relative)));
    }
}

public sealed class AgentProfileTests
{
    [Fact]
    public void A_claim_describes_the_agent_with_its_probes_and_normalised_ranges()
    {
        var claim = AgentProfile.BuildClaim(new ScanningOptions { AllowedRanges = ["192.168.1.0/24", "10.0.0.0/8"] });

        Assert.Equal(["Icmp"], claim.Capabilities);
        Assert.Equal(["192.168.1.0/24", "10.0.0.0/8"], claim.ReportedRanges);
        Assert.False(string.IsNullOrWhiteSpace(claim.Version));
        Assert.False(string.IsNullOrWhiteSpace(claim.OperatingSystem));
    }

    [Fact]
    public void An_enrollment_carries_the_token_and_name()
    {
        var request = AgentProfile.BuildEnrollment("nmt_abc", "office", new ScanningOptions());

        Assert.Equal("nmt_abc", request.EnrollmentToken);
        Assert.Equal("office", request.AgentName);
        Assert.Empty(request.ReportedRanges);
    }

    [Fact]
    public void Probe_names_list_only_known_flags()
    {
        Assert.Equal(["Icmp", "Dns"], AgentProfile.ProbeNames(Noema.Domain.ScanProbes.Icmp | Noema.Domain.ScanProbes.Dns));
        Assert.Empty(AgentProfile.ProbeNames(Noema.Domain.ScanProbes.None));
    }
}
