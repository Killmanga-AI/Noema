using Noema.Domain;

namespace Noema.Api.Common;

public static class ScanProbeNames
{
    public static string[] ToNames(ScanProbes probes) =>
        Enum.GetValues<ScanProbes>().Where(p => p != ScanProbes.None && probes.HasFlag(p)).Select(p => p.ToString()).ToArray();

    /// <summary>Parses a list of probe names into flags. Returns null with a message when any name is unknown.</summary>
    public static ScanProbes? TryParse(IEnumerable<string>? names, int maxEntries, out string? problem)
    {
        problem = null;
        var combined = ScanProbes.None;
        var count = 0;

        foreach (var name in names ?? [])
        {
            if (++count > maxEntries)
            {
                problem = "Too many entries.";
                return null;
            }

            if (!EnumParsing.TryParseName<ScanProbes>(name, out var probe) || probe == ScanProbes.None)
            {
                problem = $"'{name}' is not a known probe. Use Icmp, Arp, Dns, Tcp or Snmp.";
                return null;
            }

            combined |= probe;
        }

        if (combined == ScanProbes.None)
        {
            problem = "Choose at least one probe: Icmp, Arp, Dns, Tcp or Snmp.";
            return null;
        }

        return combined;
    }
}
