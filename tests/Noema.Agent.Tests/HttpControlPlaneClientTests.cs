using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Noema.Agent.ControlPlane;
using Noema.Agent.Credentials;
using Noema.Contracts;

namespace Noema.Agent.Tests;

internal sealed class StubHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
{
    public List<(HttpRequestMessage Request, string Body)> Seen { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        Seen.Add((request, body));
        return await respond(request);
    }

    public static StubHandler Json(HttpStatusCode status, object? body = null) =>
        new(_ => Task.FromResult(new HttpResponseMessage(status)
        {
            Content = body is null ? null : JsonContent.Create(body)
        }));

    public static StubHandler Raw(HttpStatusCode status, string text, string contentType = "application/json") =>
        new(_ => Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(text, Encoding.UTF8, contentType) }));

    public static StubHandler Throwing(Exception exception) => new(_ => throw exception);
}

public sealed class HttpControlPlaneClientTests
{
    private static readonly Guid AgentId = Guid.Parse("6f1c6f0e-9d0a-4f4e-9d1e-1f0a8a6f6f11");
    private static readonly AgentCredentials Credentials = new(new Uri("https://noema.example.com:8443/"), AgentId, "nma_the-secret");
    private static readonly ClaimRequest Claim = new("1.0", "Linux", ["Icmp"], ["192.168.1.0/24"]);

    private static HttpControlPlaneClient Client(StubHandler handler, TimeSpan? timeout = null) =>
        HttpControlPlaneClient.Create(Credentials, handler, timeout);

    [Fact]
    public async Task Claiming_with_no_work_returns_nothing()
    {
        var client = Client(StubHandler.Json(HttpStatusCode.NoContent));

        Assert.Null(await client.ClaimAsync(Claim, CancellationToken.None));
    }

    [Fact]
    public async Task Claiming_with_work_returns_the_job()
    {
        var scanId = Guid.NewGuid();
        var lease = DateTimeOffset.UtcNow.AddMinutes(2);
        var client = Client(StubHandler.Json(HttpStatusCode.OK, new { scanId, target = "192.168.1.0/24", probes = new[] { "Icmp" }, leaseExpiresAt = lease }));

        var job = await client.ClaimAsync(Claim, CancellationToken.None);

        Assert.NotNull(job);
        Assert.Equal(scanId, job.ScanId);
        Assert.Equal("192.168.1.0/24", job.Target);
        Assert.Equal(["Icmp"], job.Probes);
    }

    [Fact]
    public async Task Every_request_carries_the_agent_credential_and_goes_to_the_right_path_with_the_right_body()
    {
        var handler = StubHandler.Json(HttpStatusCode.NoContent);
        var client = Client(handler);

        await client.ClaimAsync(Claim, CancellationToken.None);

        var (request, body) = Assert.Single(handler.Seen);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("https://noema.example.com:8443/api/v1/agent/claim", request.RequestUri!.ToString());
        Assert.Equal("Agent", request.Headers.Authorization!.Scheme);
        Assert.Equal($"{AgentId}:nma_the-secret", request.Headers.Authorization.Parameter);

        using var json = JsonDocument.Parse(body);
        Assert.Equal("1.0", json.RootElement.GetProperty("version").GetString());
        Assert.Equal("Icmp", json.RootElement.GetProperty("capabilities")[0].GetString());
        Assert.Equal("192.168.1.0/24", json.RootElement.GetProperty("reportedRanges")[0].GetString());
    }

    [Fact]
    public async Task Progress_observations_and_completion_use_their_own_paths()
    {
        var scanId = Guid.NewGuid();
        var handler = new StubHandler(request => Task.FromResult(request.RequestUri!.AbsolutePath.EndsWith("/progress", StringComparison.Ordinal)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(new { cancelRequested = true, leaseExpiresAt = DateTimeOffset.UtcNow }) }
            : request.RequestUri.AbsolutePath.EndsWith("/observations", StringComparison.Ordinal)
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(new { accepted = 2, duplicate = false, cancelRequested = false, leaseExpiresAt = DateTimeOffset.UtcNow }) }
                : new HttpResponseMessage(HttpStatusCode.NoContent)));
        var client = Client(handler);

        var progress = await client.ReportProgressAsync(scanId, new ProgressRequest(10, 5, 1), CancellationToken.None);
        var upload = await client.UploadObservationsAsync(scanId, new ObservationBatch(1, [new ObservationDto("IcmpEchoReply", "192.168.1.5", DateTimeOffset.UtcNow, null, null)]), CancellationToken.None);
        await client.CompleteAsync(scanId, new CompleteRequest("Completed", null, 10, 10, 1), CancellationToken.None);

        Assert.True(progress.CancelRequested);
        Assert.Equal(2, upload.Accepted);
        Assert.Equal(
            [$"/api/v1/agent/scans/{scanId}/progress", $"/api/v1/agent/scans/{scanId}/observations", $"/api/v1/agent/scans/{scanId}/complete"],
            handler.Seen.Select(s => s.Request.RequestUri!.AbsolutePath));
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, ControlPlaneErrorKind.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden, ControlPlaneErrorKind.Unauthorized)]
    [InlineData(HttpStatusCode.NotFound, ControlPlaneErrorKind.NotFound)]
    [InlineData(HttpStatusCode.Conflict, ControlPlaneErrorKind.Conflict)]
    [InlineData(HttpStatusCode.BadRequest, ControlPlaneErrorKind.Rejected)]
    [InlineData(HttpStatusCode.UnprocessableEntity, ControlPlaneErrorKind.Rejected)]
    [InlineData(HttpStatusCode.RequestEntityTooLarge, ControlPlaneErrorKind.Rejected)]
    [InlineData(HttpStatusCode.TooManyRequests, ControlPlaneErrorKind.Transient)]
    [InlineData(HttpStatusCode.RequestTimeout, ControlPlaneErrorKind.Transient)]
    [InlineData(HttpStatusCode.InternalServerError, ControlPlaneErrorKind.Transient)]
    [InlineData(HttpStatusCode.BadGateway, ControlPlaneErrorKind.Transient)]
    [InlineData(HttpStatusCode.ServiceUnavailable, ControlPlaneErrorKind.Transient)]
    public async Task Status_codes_become_the_right_kind_of_failure(HttpStatusCode status, ControlPlaneErrorKind expected)
    {
        var client = Client(StubHandler.Json(status));

        var thrown = await Assert.ThrowsAsync<ControlPlaneException>(() => client.ClaimAsync(Claim, CancellationToken.None));

        Assert.Equal(expected, thrown.Kind);
        Assert.Equal(expected, HttpControlPlaneClient.Classify(status));
    }

    [Fact]
    public async Task The_servers_problem_title_is_included_in_the_message()
    {
        var client = Client(StubHandler.Raw(HttpStatusCode.Conflict, "{\"title\":\"The scan is Cancelled, not running.\",\"status\":409}", "application/problem+json"));

        var thrown = await Assert.ThrowsAsync<ControlPlaneException>(() => client.ReportProgressAsync(Guid.NewGuid(), new ProgressRequest(1, 0, 0), CancellationToken.None));

        Assert.Contains("409", thrown.Message);
        Assert.Contains("The scan is Cancelled, not running.", thrown.Message);
    }

    [Theory]
    [InlineData("<html>Bad gateway</html>")]
    [InlineData("")]
    [InlineData("[1,2]")]
    public async Task Unexpected_error_bodies_do_not_break_error_handling(string body)
    {
        var client = Client(StubHandler.Raw(HttpStatusCode.BadGateway, body, "text/html"));

        var thrown = await Assert.ThrowsAsync<ControlPlaneException>(() => client.ClaimAsync(Claim, CancellationToken.None));

        Assert.Equal(ControlPlaneErrorKind.Transient, thrown.Kind);
        Assert.Contains("502", thrown.Message);
    }

    [Fact]
    public async Task A_network_failure_is_transient()
    {
        var client = Client(StubHandler.Throwing(new HttpRequestException("Connection refused")));

        var thrown = await Assert.ThrowsAsync<ControlPlaneException>(() => client.ClaimAsync(Claim, CancellationToken.None));

        Assert.Equal(ControlPlaneErrorKind.Transient, thrown.Kind);
        Assert.Contains("Connection refused", thrown.Message);
    }

    [Fact]
    public async Task A_request_that_times_out_is_transient_but_caller_cancellation_is_not_swallowed()
    {
        var timeout = Client(StubHandler.Throwing(new TaskCanceledException("timed out")));
        var thrown = await Assert.ThrowsAsync<ControlPlaneException>(() => timeout.ClaimAsync(Claim, CancellationToken.None));
        Assert.Equal(ControlPlaneErrorKind.Transient, thrown.Kind);

        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        var client = Client(new StubHandler(request => throw new TaskCanceledException("cancelled")));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ClaimAsync(Claim, cancelled.Token));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("null")]
    public async Task A_success_with_an_unusable_body_is_rejected(string body)
    {
        var client = Client(StubHandler.Raw(HttpStatusCode.OK, body));

        var thrown = await Assert.ThrowsAsync<ControlPlaneException>(() => client.ClaimAsync(Claim, CancellationToken.None));

        Assert.Equal(ControlPlaneErrorKind.Rejected, thrown.Kind);
    }

    [Fact]
    public async Task Enrolling_posts_without_a_credential_and_returns_the_new_identity()
    {
        var agentId = Guid.NewGuid();
        var handler = StubHandler.Json(HttpStatusCode.OK, new { agentId, agentSecret = "nma_new", name = "office" });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://noema.example.com/") };

        var response = await ControlPlaneEnrollment.EnrollAsync(
            http, new EnrollRequest("nmt_token", "office", "1.0", "Linux", ["Icmp"], ["192.168.1.0/24"]), CancellationToken.None);

        Assert.Equal(agentId, response.AgentId);
        Assert.Equal("nma_new", response.AgentSecret);
        var (request, body) = Assert.Single(handler.Seen);
        Assert.Equal("https://noema.example.com/api/v1/agent/enroll", request.RequestUri!.ToString());
        Assert.Null(request.Headers.Authorization);
        Assert.Contains("nmt_token", body);
    }

    [Fact]
    public async Task A_refused_enrollment_is_unauthorized()
    {
        using var http = new HttpClient(StubHandler.Json(HttpStatusCode.Unauthorized)) { BaseAddress = new Uri("https://noema.example.com/") };

        var thrown = await Assert.ThrowsAsync<ControlPlaneException>(() => ControlPlaneEnrollment.EnrollAsync(
            http, new EnrollRequest("nmt_bad", "office", null, null, ["Icmp"], []), CancellationToken.None));

        Assert.Equal(ControlPlaneErrorKind.Unauthorized, thrown.Kind);
    }

    [Fact]
    public void Creating_a_client_requires_credentials()
    {
        Assert.Throws<ArgumentNullException>(() => HttpControlPlaneClient.Create(null!));
    }
}
