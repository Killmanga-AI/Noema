using System.Net;
using System.Net.NetworkInformation;

namespace Noema.Scanning.Icmp;

/// <summary>
/// Sends real ICMP echo requests through the operating system. Works on Windows, Linux and macOS without
/// special code. On Linux it needs permission to send ping, which the install steps cover.
/// </summary>
public sealed class SystemIcmpPinger : IIcmpPinger
{
    private static readonly byte[] Payload = new byte[32];

    public async Task<IcmpReply> PingAsync(IPAddress target, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(target, timeout, Payload, null, cancellationToken).ConfigureAwait(false);

            return new IcmpReply(
                Map(reply.Status),
                TimeSpan.FromMilliseconds(reply.RoundtripTime),
                reply.Options?.Ttl,
                reply.Status == IPStatus.Success ? null : $"ICMP status {reply.Status}.");
        }
        catch (PingException ex)
        {
            return new IcmpReply(IcmpStatus.Error, Error: ex.InnerException?.Message ?? ex.Message);
        }
    }

    public static IcmpStatus Map(IPStatus status) => status switch
    {
        IPStatus.Success => IcmpStatus.Success,
        IPStatus.TimedOut => IcmpStatus.TimedOut,
        IPStatus.DestinationNetworkUnreachable
            or IPStatus.DestinationHostUnreachable
            or IPStatus.DestinationProtocolUnreachable
            or IPStatus.DestinationPortUnreachable
            or IPStatus.DestinationProhibited
            or IPStatus.DestinationScopeMismatch
            or IPStatus.DestinationUnreachable
            or IPStatus.TtlExpired
            or IPStatus.TtlReassemblyTimeExceeded
            or IPStatus.TimeExceeded => IcmpStatus.Unreachable,
        _ => IcmpStatus.Error
    };
}
