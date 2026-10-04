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
