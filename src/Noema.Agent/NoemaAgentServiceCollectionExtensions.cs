using Noema.Agent.ControlPlane;
using Noema.Agent.Credentials;

namespace Noema.Agent;

public static class NoemaAgentServiceCollectionExtensions
{
    /// <summary>Registers everything the agent needs to run, except the host specific service wrappers.</summary>
    public static IServiceCollection AddNoemaAgent(this IServiceCollection services, string dataDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);

        services.AddNoemaScanning();
        services.AddSingleton<ICredentialStore>(new FileCredentialStore(AgentPaths.CredentialsPath(dataDirectory)));
        services.AddSingleton<IControlPlaneClientFactory, HttpControlPlaneClientFactory>();
        services.AddHostedService<AgentWorker>();

        return services;
    }
}
