using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Noema.Infrastructure.Persistence;

/// <summary>
/// Used only by the dotnet ef tools. Generating a migration never connects to the database,
/// so the default is harmless. Set NOEMA_DESIGN_CONNECTION to override it.
/// </summary>
public sealed class NoemaDbContextFactory : IDesignTimeDbContextFactory<NoemaDbContext>
{
    private const string FallbackConnection =
        "Host=localhost;Port=5432;Database=noema;Username=noema;Password=design-time-only";

    public NoemaDbContext CreateDbContext(string[] args)
    {
        var connection = Environment.GetEnvironmentVariable("NOEMA_DESIGN_CONNECTION") ?? FallbackConnection;

        var options = new DbContextOptionsBuilder<NoemaDbContext>()
            .UseNpgsql(connection)
            .Options;

        return new NoemaDbContext(options);
    }
}
