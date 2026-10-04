using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Noema.Infrastructure.Persistence;

namespace Noema.Api.Tests;

[Trait("Category", "Docker")]
public sealed class MigrationOnStartupTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{
    [Fact]
    public async Task Pending_migrations_are_applied_when_enabled()
    {
        await using var factory = new NoemaApiFactory(postgres.ConnectionString)
            .WithWebHostBuilder(builder => builder.UseSetting("Database:MigrateOnStartup", "true"));

        using var client = factory.CreateClient();
        var response = await client.GetAsync("/health/ready");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var scope = factory.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<NoemaDbContext>();
        Assert.NotEmpty(await context.Database.GetAppliedMigrationsAsync());
        Assert.Empty(await context.Database.GetPendingMigrationsAsync());
    }
}
