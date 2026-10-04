using System.Net;
using Noema.Api.Middleware;

namespace Noema.Api.Tests;

public sealed class HealthEndpointsTests(UnreachableDatabaseFactory factory) : IClassFixture<UnreachableDatabaseFactory>
{
    [Fact]
    public async Task Live_returns_200_even_when_the_database_is_down()
    {
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/health/live");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Ready_returns_503_when_the_database_is_unreachable()
    {
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/health/ready");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task Responses_carry_a_generated_correlation_id()
    {
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/health/live");

        Assert.True(response.Headers.TryGetValues(CorrelationIdMiddleware.HeaderName, out var values));
        Assert.False(string.IsNullOrEmpty(values!.Single()));
    }

    [Fact]
    public async Task Responses_echo_a_valid_incoming_correlation_id()
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/health/live");
        request.Headers.Add(CorrelationIdMiddleware.HeaderName, "test-correlation-42");

        var response = await client.SendAsync(request);

        Assert.Equal("test-correlation-42", response.Headers.GetValues(CorrelationIdMiddleware.HeaderName).Single());
    }

    [Fact]
    public async Task Unknown_routes_return_404_and_still_carry_a_correlation_id()
    {
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/does-not-exist");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.True(response.Headers.Contains(CorrelationIdMiddleware.HeaderName));
    }
}
