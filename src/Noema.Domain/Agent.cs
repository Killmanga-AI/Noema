using System.Net;
using System.Text.RegularExpressions;

namespace Noema.Domain;

public enum AgentStatus
{
    Active,
    Revoked
}

/// <summary>
/// A scanner that has enrolled with this installation. It reports what it can probe and which ranges it covers,
/// and the control plane only offers it scans it can actually serve. Its secret is never stored, only a hash of it.
/// </summary>
public sealed class Agent
{
    public const int MaxReportedRanges = 64;
    public const int MaxVersionLength = 64;
    public const int MaxOperatingSystemLength = 128;

    private static readonly Regex NamePattern = new(
        "^[A-Za-z0-9][A-Za-z0-9._ -]{1,63}$",
        RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    private List<CidrRange> reportedRanges = [];

    private Agent()
    {
    }

    public Guid Id { get; private set; }

    public string Name { get; private set; } = null!;

    public string CredentialHash { get; private set; } = null!;

    public AgentStatus Status { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? LastSeenAt { get; private set; }

    public IPAddress? LastSeenAddress { get; private set; }

    public string? Version { get; private set; }

    public string? OperatingSystem { get; private set; }

    public ScanProbes Capabilities { get; private set; }

    /// <summary>The ranges the agent says it is willing and able to scan. Used only to route jobs to it.</summary>
    public IReadOnlyList<CidrRange> ReportedRanges
    {
        get => reportedRanges;
        private set => reportedRanges = value.ToList();
    }

    public DateTimeOffset? RevokedAt { get; private set; }

    public bool IsRevoked => Status == AgentStatus.Revoked;

    public static bool IsValidName(string? name) => name is not null && NamePattern.IsMatch(name.Trim());

    public static Agent Enroll(
        string name,
        string credentialHash,
        DateTimeOffset now,
        string? version,
        string? operatingSystem,
        ScanProbes capabilities,
        IEnumerable<CidrRange> ranges,
        IPAddress? address = null)
    {
        Guard.Utc(now, nameof(now));

        var trimmed = name?.Trim();
        if (!IsValidName(trimmed))
        {
            throw new ArgumentException(
                "An agent name is 2 to 64 characters: letters, digits, dot, dash, underscore or space, starting with a letter or digit.",
                nameof(name));
        }

        if (string.IsNullOrWhiteSpace(credentialHash))
        {
            throw new ArgumentException("A credential hash is required.", nameof(credentialHash));
        }

        var agent = new Agent
        {
            Id = Ids.New(now),
            Name = trimmed!,
            CredentialHash = credentialHash,
            Status = AgentStatus.Active,
            CreatedAt = now
        };

        agent.RecordContact(now, address, version, operatingSystem, capabilities, ranges);
        return agent;
    }

    /// <summary>Records that the agent checked in and refreshes what it says it can do.</summary>
    public void RecordContact(
        DateTimeOffset now,
        IPAddress? address,
        string? version,
        string? operatingSystem,
        ScanProbes capabilities,
        IEnumerable<CidrRange> ranges)
    {
        Guard.Utc(now, nameof(now));
        ArgumentNullException.ThrowIfNull(ranges);

        if (capabilities == ScanProbes.None || (capabilities & ~AllProbes) != 0)
        {
            throw new ArgumentException("Report at least one known probe.", nameof(capabilities));
        }

        var distinct = ranges.Distinct().ToList();
        if (distinct.Count > MaxReportedRanges)
        {
            throw new ArgumentException($"An agent can report at most {MaxReportedRanges} ranges.", nameof(ranges));
        }

        if (distinct.Any(ScanTargetRules.IsNeverScannable))
        {
            throw new ArgumentException("An agent cannot cover loopback, multicast or reserved ranges.", nameof(ranges));
        }

        LastSeenAt = now;
        LastSeenAddress = address is null ? null : IpAddressNormalizer.Normalize(address);
        Version = Limit(version, MaxVersionLength);
        OperatingSystem = Limit(operatingSystem, MaxOperatingSystemLength);
        Capabilities = capabilities;
        reportedRanges = distinct;
    }

    /// <summary>Revoking is permanent. A revoked agent can never authenticate again and must enroll anew.</summary>
    public void Revoke(DateTimeOffset now)
    {
        Guard.Utc(now, nameof(now));

        if (IsRevoked)
        {
            return;
        }

        Status = AgentStatus.Revoked;
        RevokedAt = now;
    }

    /// <summary>True when the agent is active, has every requested probe, and reports a range that contains the target.</summary>
    public bool CanServe(CidrRange target, ScanProbes probes)
    {
        ArgumentNullException.ThrowIfNull(target);

        return Status == AgentStatus.Active
            && probes != ScanProbes.None
            && (Capabilities & probes) == probes
            && reportedRanges.Any(range => range.Contains(target));
    }

    public bool IsOnline(DateTimeOffset now, TimeSpan window) =>
        Status == AgentStatus.Active && LastSeenAt is { } seen && now - seen <= window;

    private const ScanProbes AllProbes = ScanProbes.Icmp | ScanProbes.Arp | ScanProbes.Dns | ScanProbes.Tcp | ScanProbes.Snmp;

    private static string? Limit(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        return trimmed.Length > max ? trimmed[..max] : trimmed;
    }
}
