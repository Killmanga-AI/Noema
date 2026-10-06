using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Noema.Agent.Credentials;

namespace Noema.Agent.Tests;

public sealed class EnrollCommandParsingTests
{
    [Fact]
    public void Recognises_the_enroll_command()
    {
        Assert.True(EnrollCommand.IsEnrollCommand(["enroll"]));
        Assert.True(EnrollCommand.IsEnrollCommand(["ENROLL", "--server", "x"]));
        Assert.False(EnrollCommand.IsEnrollCommand(["scan"]));
        Assert.False(EnrollCommand.IsEnrollCommand([]));
    }

    [Fact]
    public void Parses_every_option()
    {
        var result = EnrollCommand.Parse(
            ["enroll", "--server", "https://noema.example.com", "--token", " nmt_abc ", "--name", "Office Agent", "--allow", "192.168.1.0/24", "--allow", "10.0.0.0/8", "--data-dir", "/tmp/agent", "--force"]);

        Assert.Null(result.Error);
        var arguments = result.Arguments!;
        Assert.Equal(new Uri("https://noema.example.com"), arguments.Server);
        Assert.Equal("nmt_abc", arguments.Token);
        Assert.Equal("Office Agent", arguments.Name);
        Assert.Equal(["192.168.1.0/24", "10.0.0.0/8"], arguments.Allow);
        Assert.Equal("/tmp/agent", arguments.DataDirectory);
        Assert.True(arguments.Force);
    }

    [Fact]
    public void Options_are_case_insensitive_and_repeated_ranges_are_deduplicated()
    {
        var result = EnrollCommand.Parse(["enroll", "--SERVER", "https://noema.example.com", "--Token", "t", "--allow", "192.168.1.0/24", "--allow", "192.168.1.0/24"]);

        Assert.Single(result.Arguments!.Allow);
    }

    [Fact]
    public void Loopback_http_is_allowed_for_trying_things_locally()
    {
        Assert.NotNull(EnrollCommand.Parse(["enroll", "--server", "http://localhost:8080", "--token", "t"]).Arguments);
    }

    [Theory]
    [InlineData("enroll")]
    [InlineData("enroll|--server|https://noema.example.com")]
    [InlineData("enroll|--token|abc")]
    [InlineData("enroll|--server|--token|abc")]
    [InlineData("enroll|--server|https://noema.example.com|--token")]
    [InlineData("enroll|--server|not a url|--token|abc")]
    [InlineData("enroll|--server|http://noema.example.com|--token|abc")]
    [InlineData("enroll|--server|ftp://noema.example.com|--token|abc")]
    [InlineData("enroll|--server|https://noema.example.com|--token|abc|--name|x")]
    [InlineData("enroll|--server|https://noema.example.com|--token|abc|--allow|192.168.1.5/24")]
    [InlineData("enroll|--server|https://noema.example.com|--token|abc|--allow|nonsense")]
    [InlineData("enroll|--server|https://noema.example.com|--token|abc|--frobnicate")]
    public void Bad_input_gives_an_error_and_no_arguments(string joined)
    {
        var result = EnrollCommand.Parse(joined.Split('|'));

        Assert.Null(result.Arguments);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
    }
}

public sealed class EnrollCommandRunTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "noema-tests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.ToDictionary(v => v.Key, v => (string?)v.Value)).Build();

    private string[] Args(params string[] extra) =>
        new[] { "enroll", "--server", "https://noema.example.com", "--token", "nmt_the-token", "--name", "office-agent", "--allow", "192.168.1.0/24", "--data-dir", directory }
            .Concat(extra).ToArray();

    private static StubHandler Success(Guid agentId) =>
        StubHandler.Json(HttpStatusCode.OK, new { agentId, agentSecret = "nma_brand-new", name = "office-agent" });

    private async Task<(int Code, string Out, string Err)> RunAsync(string[] args, StubHandler handler, IConfiguration? configuration = null)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var code = await EnrollCommand.RunAsync(args, output, error, configuration ?? Config(), CancellationToken.None, handler);
        return (code, output.ToString(), error.ToString());
    }

    [Fact]
    public async Task Enrolling_saves_the_credential_and_the_local_settings()
    {
        var agentId = Guid.NewGuid();
        var handler = Success(agentId);

        var (code, output, error) = await RunAsync(Args(), handler);

        Assert.Equal(0, code);
        Assert.Equal(string.Empty, error);
        Assert.Contains("Enrolled as 'office-agent'", output);
        Assert.DoesNotContain("nma_brand-new", output);

        var credentials = new FileCredentialStore(AgentPaths.CredentialsPath(directory)).Load();
        Assert.NotNull(credentials);
        Assert.Equal(agentId, credentials.AgentId);
        Assert.Equal("nma_brand-new", credentials.AgentSecret);
        Assert.Equal(new Uri("https://noema.example.com"), credentials.ControlPlaneUrl);

        var settings = File.ReadAllText(AgentPaths.SettingsPath(directory));
        Assert.Contains("https://noema.example.com", settings);
        Assert.Contains("192.168.1.0/24", settings);
    }

    [Fact]
    public async Task The_request_carries_the_token_name_probes_and_ranges_but_no_credential()
    {
        var handler = Success(Guid.NewGuid());

        await RunAsync(Args(), handler);

        var (request, body) = Assert.Single(handler.Seen);
        Assert.Equal("https://noema.example.com/api/v1/agent/enroll", request.RequestUri!.ToString());
        Assert.Null(request.Headers.Authorization);

        using var json = JsonDocument.Parse(body);
        Assert.Equal("nmt_the-token", json.RootElement.GetProperty("enrollmentToken").GetString());
        Assert.Equal("office-agent", json.RootElement.GetProperty("agentName").GetString());
        Assert.Equal("Icmp", json.RootElement.GetProperty("capabilities")[0].GetString());
        Assert.Equal("192.168.1.0/24", json.RootElement.GetProperty("reportedRanges")[0].GetString());
    }

    [Fact]
    public async Task A_refused_token_saves_nothing_and_says_what_to_do()
    {
        var (code, _, error) = await RunAsync(Args(), StubHandler.Json(HttpStatusCode.Unauthorized));

        Assert.Equal(1, code);
        Assert.Contains("new one", error);
        Assert.False(File.Exists(AgentPaths.CredentialsPath(directory)));
        Assert.False(File.Exists(AgentPaths.SettingsPath(directory)));
    }

    [Fact]
    public async Task An_unreachable_server_is_reported_without_saving_anything()
    {
        var (code, _, error) = await RunAsync(Args(), StubHandler.Throwing(new HttpRequestException("Name resolution failed")));

        Assert.Equal(1, code);
        Assert.Contains("Could not reach the control plane", error);
        Assert.False(File.Exists(AgentPaths.CredentialsPath(directory)));
    }

    [Fact]
    public async Task A_rejected_enrollment_shows_the_servers_reason()
    {
        var (code, _, error) = await RunAsync(Args(), StubHandler.Raw(HttpStatusCode.BadRequest, "{\"title\":\"One or more validation errors occurred.\"}"));

        Assert.Equal(1, code);
        Assert.Contains("validation errors", error);
    }

    [Fact]
    public async Task An_agent_that_is_already_enrolled_needs_force_to_enroll_again()
    {
        var first = await RunAsync(Args(), Success(Guid.NewGuid()));
        var secondHandler = Success(Guid.NewGuid());
        var second = await RunAsync(Args(), secondHandler);

        Assert.Equal(0, first.Code);
        Assert.Equal(2, second.Code);
        Assert.Contains("--force", second.Err);
        Assert.Empty(secondHandler.Seen);

        var replacement = Guid.NewGuid();
        var forced = await RunAsync(Args("--force"), Success(replacement));
        Assert.Equal(0, forced.Code);
        Assert.Equal(replacement, new FileCredentialStore(AgentPaths.CredentialsPath(directory)).Load()!.AgentId);
    }

    [Fact]
    public async Task Bad_arguments_exit_with_code_2_and_never_contact_the_server()
    {
        var handler = Success(Guid.NewGuid());

        var (code, _, error) = await RunAsync(["enroll", "--server", "http://insecure.example.com", "--token", "t"], handler);

        Assert.Equal(2, code);
        Assert.Contains("https", error);
        Assert.Empty(handler.Seen);
    }

    [Fact]
    public async Task Settings_that_would_allow_a_public_range_are_refused_before_contacting_the_server()
    {
        var handler = Success(Guid.NewGuid());

        var (code, _, error) = await RunAsync(
            ["enroll", "--server", "https://noema.example.com", "--token", "t", "--allow", "8.8.8.0/24", "--data-dir", directory], handler);

        Assert.Equal(2, code);
        Assert.Contains("Scanning:AllowedRanges", error);
        Assert.Empty(handler.Seen);
    }

    [Fact]
    public async Task Enrolling_without_any_allowed_range_works_but_warns_that_every_scan_will_be_refused()
    {
        var args = new[] { "enroll", "--server", "https://noema.example.com", "--token", "t", "--name", "office-agent", "--data-dir", directory };

        var (code, output, _) = await RunAsync(args, Success(Guid.NewGuid()));

        Assert.Equal(0, code);
        Assert.Contains("no ranges are allowed", output);
    }

    [Fact]
    public async Task Ranges_already_in_configuration_are_used_when_none_are_given_on_the_command_line()
    {
        var handler = Success(Guid.NewGuid());
        var args = new[] { "enroll", "--server", "https://noema.example.com", "--token", "t", "--name", "office-agent", "--data-dir", directory };

        var (code, _, _) = await RunAsync(args, handler, Config(("Scanning:AllowedRanges:0", "172.16.0.0/16")));

        Assert.Equal(0, code);
        Assert.Contains("172.16.0.0/16", Assert.Single(handler.Seen).Body);
    }

    [Fact]
    public void Each_kind_of_failure_has_a_helpful_description()
    {
        Assert.Contains("new one", EnrollCommand.Describe(new ControlPlane.ControlPlaneException(ControlPlane.ControlPlaneErrorKind.Unauthorized, "x")));
        Assert.Contains("Could not reach", EnrollCommand.Describe(new ControlPlane.ControlPlaneException(ControlPlane.ControlPlaneErrorKind.Transient, "x")));
        Assert.Contains("did not accept", EnrollCommand.Describe(new ControlPlane.ControlPlaneException(ControlPlane.ControlPlaneErrorKind.Rejected, "x")));
        Assert.Contains("failed", EnrollCommand.Describe(new ControlPlane.ControlPlaneException(ControlPlane.ControlPlaneErrorKind.Conflict, "x")));
    }
}
