namespace Noema.Agent;

public sealed class AgentOptions
{
    public const string SectionName = "Agent";

    public Uri? ControlPlaneUrl { get; set; }

    /// <summary>How often an idle agent asks the control plane for work. Each ask also counts as a heartbeat.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>How often a running scan sends its findings and progress, which also keeps its lease alive.</summary>
    public TimeSpan ReportInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>The longest wait between attempts while the control plane cannot be reached.</summary>
    public TimeSpan MaxBackoff { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Where credentials and local settings live. Defaults to a standard location for the operating system.</summary>
    public string? DataDirectory { get; set; }
}
