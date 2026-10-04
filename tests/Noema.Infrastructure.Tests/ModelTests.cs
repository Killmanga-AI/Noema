using Microsoft.EntityFrameworkCore;
using Noema.Infrastructure.Persistence;

namespace Noema.Infrastructure.Tests;

public sealed class ModelTests
{
    [Fact]
    public void Model_matches_the_latest_migration()
    {
        // Needs no database. Fails when someone changes the model and forgets to add a migration.
        var options = new DbContextOptionsBuilder<NoemaDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
            .Options;
        using var context = new NoemaDbContext(options);

        Assert.False(context.Database.HasPendingModelChanges());
    }

    [Fact]
    public void At_least_one_migration_exists()
    {
        var options = new DbContextOptionsBuilder<NoemaDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
            .Options;
        using var context = new NoemaDbContext(options);

        Assert.NotEmpty(context.Database.GetMigrations());
    }
}
