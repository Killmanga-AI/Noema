using System.Net;

namespace Noema.Domain;

/// <summary>
/// One network interface of an asset. An interface without a MAC address stands for an address seen
/// only through routed discovery, and an asset can have at most one of those.
/// </summary>
public sealed class AssetInterface
{
    private readonly List<InterfaceAddress> addresses = [];

    private AssetInterface()
    {
    }

    internal AssetInterface(Guid id, Guid assetId, MacAddress? macAddress, DateTimeOffset seenAt)
    {
        Id = id;
        AssetId = assetId;
        MacAddress = macAddress;
        FirstSeenAt = seenAt;
        LastSeenAt = seenAt;
    }

    public Guid Id { get; private set; }

    public Guid AssetId { get; private set; }

    public MacAddress? MacAddress { get; private set; }

    public DateTimeOffset FirstSeenAt { get; private set; }

    public DateTimeOffset LastSeenAt { get; private set; }

    public IReadOnlyList<InterfaceAddress> Addresses => addresses;

    internal void RecordSighting(IPAddress? address, DateTimeOffset seenAt)
    {
        if (seenAt < FirstSeenAt)
        {
            FirstSeenAt = seenAt;
        }

        if (seenAt > LastSeenAt)
        {
            LastSeenAt = seenAt;
        }

        if (address is null)
        {
            return;
        }

        var existing = addresses.FirstOrDefault(a => a.Address.Equals(address));
        if (existing is null)
        {
            addresses.Add(new InterfaceAddress(Ids.New(seenAt), Id, address, seenAt));
        }
        else
        {
            existing.Touch(seenAt);
        }
    }
}
