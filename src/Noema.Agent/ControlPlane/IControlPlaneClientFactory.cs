using Noema.Agent.Credentials;

namespace Noema.Agent.ControlPlane;

public interface IControlPlaneClientFactory
{
    IControlPlaneClient Create(AgentCredentials credentials);
}

public sealed class HttpControlPlaneClientFactory : IControlPlaneClientFactory
{
    public IControlPlaneClient Create(AgentCredentials credentials) => HttpControlPlaneClient.Create(credentials);
}
