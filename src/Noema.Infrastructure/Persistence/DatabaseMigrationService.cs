using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Noema.Infrastructure.Persistence;

/// <summary>
/// Runs before the web server starts listening, so the API never serves requests against an old schema.
/// EF Core takes a database lock while migrating, so two instances starting together do not collide.
/// </summary>
internal sealed class DatabaseMigrationService(
    IServiceScopeFactory scopeFactory,
    IOptions<DatabaseOptions> options,
    ILogger<DatabaseMigrationService> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!options.Value.MigrateOnStartup)
        {
            return;
        }

        await using var scope = scopeFactory.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<NoemaDbContext>();

        var pending = (await context.Database.GetPendingMigrationsAsync(cancellationToken)).Count();
        logger.LogInformation("Applying {PendingCount} pending database migrations", pending);

        await context.Database.MigrateAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
