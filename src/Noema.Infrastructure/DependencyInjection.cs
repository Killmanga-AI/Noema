using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Noema.Infrastructure.Persistence;

namespace Noema.Infrastructure;

public static class DependencyInjection
{
    public const string ReadyTag = "ready";

    public static IServiceCollection AddNoemaInfrastructure(this IServiceCollection services)
    {
        services.AddOptions<DatabaseOptions>()
            .BindConfiguration(DatabaseOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        // Options are read when the context is resolved, not at registration time,
        // so configuration overrides (tests, containers) are always respected.
        services.AddDbContext<NoemaDbContext>((serviceProvider, builder) =>
        {
            var database = serviceProvider.GetRequiredService<IOptions<DatabaseOptions>>().Value;
            builder.UseNpgsql(database.ConnectionString);
        });

        services.AddHealthChecks()
            .AddDbContextCheck<NoemaDbContext>(name: "postgres", tags: [ReadyTag]);

        return services;
    }
}
