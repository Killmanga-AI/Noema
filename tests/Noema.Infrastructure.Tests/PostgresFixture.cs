using Microsoft.EntityFrameworkCore;
using Noema.Infrastructure.Persistence;
using Testcontainers.PostgreSql;

namespace Noema.Infrastructure.Tests;

/// <summary>One Postgres container for all database tests, migrated once through the real migrations.</summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer container = new PostgreSqlBuilder("postgres:17-alpine").Build();

    public string ConnectionString => container.GetConnectionString();

    public async Task InitializeAsync()
    {
        await container.StartAsync();

        await using var context = CreateContext();
        await context.Database.MigrateAsync();
    }

    public Task DisposeAsync() => container.DisposeAsync().AsTask();

    public NoemaDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<NoemaDbContext>()
            .UseNpgsql(ConnectionString)
            .Options;

        return new NoemaDbContext(options);
    }
}

[CollectionDefinition(Name)]
public sealed class PostgresCollection : ICollectionFixture<PostgresFixture>
{
    public const string Name = "postgres";
}
