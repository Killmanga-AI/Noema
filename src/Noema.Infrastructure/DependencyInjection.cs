using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Noema.Infrastructure.Persistence;
using Noema.Infrastructure.Security;

namespace Noema.Infrastructure;

public static class DependencyInjection
{
    public const string ReadyTag = "ready";

    public static IServiceCollection AddNoemaInfrastructure(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);

        services.AddOptions<DatabaseOptions>()
            .BindConfiguration(DatabaseOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<SecurityOptions>()
            .BindConfiguration(SecurityOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<BootstrapOptions>()
            .BindConfiguration(BootstrapOptions.SectionName);

        // Options are read when the context is resolved, not at registration time,
        // so configuration overrides (tests, containers) are always respected.
        services.AddDbContext<NoemaDbContext>((serviceProvider, builder) =>
        {
            var database = serviceProvider.GetRequiredService<IOptions<DatabaseOptions>>().Value;
            builder.UseNpgsql(database.ConnectionString);
        });

        services.AddSingleton<IPasswordHasher>(serviceProvider =>
            new Pbkdf2PasswordHasher(serviceProvider.GetRequiredService<IOptions<SecurityOptions>>().Value.PasswordHashIterations));

        // Order matters: migrate first, then create the first administrator.
        services.AddHostedService<DatabaseMigrationService>();
        services.AddHostedService<BootstrapAdminService>();

        services.AddHealthChecks()
            .AddDbContextCheck<NoemaDbContext>(name: "postgres", tags: [ReadyTag]);

        return services;
    }
}
