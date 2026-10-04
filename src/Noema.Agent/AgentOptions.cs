namespace Noema.Agent;

public sealed class AgentOptions
{
    public const string SectionName = "Agent";

    public Uri? ControlPlaneUrl { get; set; }

    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(30);
}
