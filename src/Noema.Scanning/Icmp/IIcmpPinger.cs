using System.Net;

namespace Noema.Scanning.Icmp;

public enum IcmpStatus
{
    Success,
    TimedOut,

    /// <summary>A router or the host itself answered that the address cannot be reached.</summary>
    Unreachable,

    /// <summary>The ping could not be sent or came back with something unexpected.</summary>
    Error
}

public sealed record IcmpReply(IcmpStatus Status, TimeSpan RoundTrip = default, int? TimeToLive = null, string? Error = null);

public interface IIcmpPinger
{
    Task<IcmpReply> PingAsync(IPAddress target, TimeSpan timeout, CancellationToken cancellationToken);
}
