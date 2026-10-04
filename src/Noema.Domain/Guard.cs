using System.Net;

namespace Noema.Domain;

internal static class Guard
{
    public static void Utc(DateTimeOffset value, string paramName)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Timestamps must be UTC (offset zero).", paramName);
        }
    }

    public static IPAddress DeviceAddress(IPAddress address, string paramName)
    {
        ArgumentNullException.ThrowIfNull(address, paramName);

        var normalized = IpAddressNormalizer.Normalize(address);
        if (!IpAddressNormalizer.IsAssignable(normalized))
        {
            throw new ArgumentException($"{address} is not a usable device address.", paramName);
        }

        return normalized;
    }
}
