using System.Net;
using System.Text.Json;

namespace Noema.Domain;

public enum ObservationKind
{
    IcmpEchoReply,
    ArpEntry,
    ReverseDnsName,
    TcpPortOpen,
    SnmpSystemInfo
}

/// <summary>
/// One fact a probe saw at one moment. Observations are append only and are never edited,
/// they are the raw history that assets are later built from.
/// </summary>
public sealed class Observation
{
    public const int MaxDetailLength = 16 * 1024;

    private Observation()
    {
    }

    public Guid Id { get; private set; }

    public Guid ScanRunId { get; private set; }

    public ObservationKind Kind { get; private set; }

    public IPAddress Address { get; private set; } = null!;

    public MacAddress? MacAddress { get; private set; }

    public DateTimeOffset ObservedAt { get; private set; }

    /// <summary>Probe specific data as JSON, for example a port number or SNMP system fields.</summary>
    public string? DetailJson { get; private set; }

    public static Observation Create(
        Guid scanRunId,
        ObservationKind kind,
        IPAddress address,
        DateTimeOffset observedAt,
        MacAddress? macAddress = null,
        string? detailJson = null)
    {
        if (scanRunId == Guid.Empty)
        {
            throw new ArgumentException("An observation belongs to a scan run.", nameof(scanRunId));
        }

        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown observation kind.");
        }

        Guard.Utc(observedAt, nameof(observedAt));
        var normalized = Guard.DeviceAddress(address, nameof(address));

        if (kind == ObservationKind.ArpEntry && macAddress is null)
        {
            throw new ArgumentException("An ARP observation needs the MAC address it resolved to.", nameof(macAddress));
        }

        return new Observation
        {
            Id = Ids.New(observedAt),
            ScanRunId = scanRunId,
            Kind = kind,
            Address = normalized,
            MacAddress = macAddress,
            ObservedAt = observedAt,
            DetailJson = ValidateDetail(detailJson)
        };
    }

    private static string? ValidateDetail(string? detailJson)
    {
        if (string.IsNullOrWhiteSpace(detailJson))
        {
            return null;
        }

        if (detailJson.Length > MaxDetailLength)
        {
            throw new ArgumentException($"Detail can be at most {MaxDetailLength} characters.", nameof(detailJson));
        }

        try
        {
            using (JsonDocument.Parse(detailJson))
            {
            }
        }
        catch (JsonException)
        {
            throw new ArgumentException("Detail must be valid JSON.", nameof(detailJson));
        }

        return detailJson;
    }
}
