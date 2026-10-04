using System.Net;

namespace Noema.Domain;

/// <summary>An IP address that has been seen on an interface, with when it was first and last seen there.</summary>
public sealed class InterfaceAddress
{
    private InterfaceAddress()
    {
    }

    internal InterfaceAddress(Guid id, Guid assetInterfaceId, IPAddress address, DateTimeOffset seenAt)
    {
        Id = id;
        AssetInterfaceId = assetInterfaceId;
        Address = address;
        FirstSeenAt = seenAt;
        LastSeenAt = seenAt;
    }

    public Guid Id { get; private set; }

    public Guid AssetInterfaceId { get; private set; }

    public IPAddress Address { get; private set; } = null!;

    public DateTimeOffset FirstSeenAt { get; private set; }

    public DateTimeOffset LastSeenAt { get; private set; }

    internal void Touch(DateTimeOffset seenAt)
    {
        if (seenAt < FirstSeenAt)
        {
            FirstSeenAt = seenAt;
        }

        if (seenAt > LastSeenAt)
        {
            LastSeenAt = seenAt;
        }
    }
}
