namespace Noema.Scanning;

public enum ProbePhase
{
    /// <summary>Decides whether a host is there at all, for example a ping or an ARP lookup.</summary>
    Discovery,

    /// <summary>Learns more about a host that is there, for example reverse DNS or open ports.</summary>
    Enrichment
}
