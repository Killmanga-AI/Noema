using System.Net;

namespace Noema.Api.Tests;

[Trait("Category", "Docker")]
public sealed class ReadinessWithDatabaseTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{
    [Fact]
    public async Task Ready_returns_200_when_postgres_is_reachable()
    {
        await using var factory = new NoemaApiFactory(postgres.ConnectionString);
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/health/ready");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
