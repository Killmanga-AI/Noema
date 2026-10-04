using System.Net;
using System.Net.Sockets;

namespace Noema.Domain;

public static class IpAddressNormalizer
{
    /// <summary>Maps IPv4 in IPv6 form back to IPv4 and drops IPv6 scope ids so equal addresses compare equal.</summary>
    public static IPAddress Normalize(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0)
        {
            return new IPAddress(address.GetAddressBytes());
        }

        return address;
    }

    /// <summary>True for addresses that can identify a real device on a network.</summary>
    public static bool IsAssignable(IPAddress address)
    {
        var normalized = Normalize(address);

        if (normalized.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            return false;
        }

        if (normalized.Equals(IPAddress.Any) || normalized.Equals(IPAddress.IPv6Any))
        {
            return false;
        }

        if (IPAddress.IsLoopback(normalized) || normalized.Equals(IPAddress.Broadcast))
        {
            return false;
        }

        if (normalized.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return !normalized.IsIPv6Multicast;
        }

        var first = normalized.GetAddressBytes()[0];
        return first is < 224 or > 239;
    }
}
