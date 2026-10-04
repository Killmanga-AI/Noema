using Microsoft.Extensions.Options;
using Noema.Scanning;

namespace Noema.Agent;

public static class ScanningServiceCollectionExtensions
{
    public static IServiceCollection AddNoemaScanning(this IServiceCollection services)
    {
        services.AddSingleton<IValidateOptions<ScanningOptions>, ScanningOptionsValidator>();
        services.AddOptions<ScanningOptions>()
            .BindConfiguration(ScanningOptions.SectionName)
            .ValidateOnStart();

        // One engine, and so one shared packet budget, for everything this agent scans.
        services.AddSingleton<ScanEngine>(provider =>
            ScanEngineFactory.Create(
                provider.GetRequiredService<IOptions<ScanningOptions>>().Value,
                provider.GetRequiredService<TimeProvider>()));

        return services;
    }
}
