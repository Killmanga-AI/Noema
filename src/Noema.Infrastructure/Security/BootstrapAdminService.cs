using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Noema.Domain;
using Noema.Infrastructure.Persistence;

namespace Noema.Infrastructure.Security;

/// <summary>
/// Creates the first administrator from configuration when no users exist. Does nothing, and never touches
/// the database, unless a username and password are configured. Must run after migrations.
/// </summary>
internal sealed class BootstrapAdminService(
    IServiceScopeFactory scopeFactory,
    IOptions<BootstrapOptions> options,
    TimeProvider timeProvider,
    ILogger<BootstrapAdminService> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;

        if (string.IsNullOrWhiteSpace(settings.AdminUsername) || string.IsNullOrEmpty(settings.AdminPassword))
        {
            return;
        }

        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<NoemaDbContext>();

        if (await db.Users.AnyAsync(cancellationToken))
        {
            return;
        }

        var username = User.NormalizeUsername(settings.AdminUsername);
        if (!User.IsValidUsername(username))
        {
            throw new InvalidOperationException("Bootstrap:AdminUsername is not a valid username.");
        }

        var problems = PasswordPolicy.Check(settings.AdminPassword, username);
        if (problems.Count > 0)
        {
            throw new InvalidOperationException("Bootstrap:AdminPassword is not acceptable: " + string.Join(" ", problems));
        }

        var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
        var now = timeProvider.GetUtcNow();
        var admin = User.Create(username, hasher.Hash(settings.AdminPassword), UserRole.Admin, now);

        db.Users.Add(admin);
        db.AuditEntries.Add(AuditEntry.Create(
            "user.bootstrap_created",
            AuditOutcome.Success,
            now,
            admin.Id,
            admin.Username,
            "user",
            admin.Id.ToString(),
            JsonSerializer.Serialize(new { role = admin.Role.ToString() })));

        await db.SaveChangesAsync(cancellationToken);

        logger.LogWarning("Created the first administrator {Username}. Remove Bootstrap:AdminPassword from configuration now", admin.Username);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
