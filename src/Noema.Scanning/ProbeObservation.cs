using System.Net;
using Noema.Domain;

namespace Noema.Scanning;

/// <summary>
/// One fact a probe learned. The scan engine does not know which scan run it belongs to,
/// the caller attaches that when converting to a stored observation.
/// </summary>
public sealed record ProbeObservation(
    ObservationKind Kind,
    IPAddress Address,
    DateTimeOffset ObservedAt,
    MacAddress? MacAddress = null,
    string? DetailJson = null)
{
    public Observation ToDomain(Guid scanRunId) =>
        Observation.Create(scanRunId, Kind, Address, ObservedAt, MacAddress, DetailJson);
}
