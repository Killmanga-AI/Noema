using System.Reflection;
using System.Runtime.InteropServices;
using Noema.Contracts;
using Noema.Domain;

namespace Noema.Agent;

/// <summary>What this agent tells the control plane about itself: its version, system, probes and the ranges it will scan.</summary>
public static class AgentProfile
{
    public static string Version =>
        typeof(AgentProfile).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";

    public static string OperatingSystemDescription => RuntimeInformation.OSDescription;

    public static ClaimRequest BuildClaim(ScanningOptions scanning) =>
        new(Version, OperatingSystemDescription, ProbeNames(ScanEngineFactory.SupportedProbes), Ranges(scanning));

    public static EnrollRequest BuildEnrollment(string token, string agentName, ScanningOptions scanning) =>
        new(token, agentName, Version, OperatingSystemDescription, ProbeNames(ScanEngineFactory.SupportedProbes), Ranges(scanning));

    public static string[] ProbeNames(ScanProbes probes) =>
        Enum.GetValues<ScanProbes>().Where(p => p != ScanProbes.None && probes.HasFlag(p)).Select(p => p.ToString()).ToArray();

    private static string[] Ranges(ScanningOptions scanning) =>
        (scanning.AllowedRanges ?? []).Select(text => CidrRange.Parse(text).ToString()).ToArray();
}
