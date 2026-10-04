using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using Noema.Domain;

namespace Noema.Scanning;

/// <summary>Turns a range into the addresses worth probing, one at a time, without building a list.</summary>
public static class TargetExpander
{
    /// <summary>
    /// How many addresses a sweep of the range would try. IPv4 ranges of /30 or larger leave out the network
    /// and broadcast addresses, since no host can have them.
    /// </summary>
    public static BigInteger Count(CidrRange range)
    {
        ArgumentNullException.ThrowIfNull(range);

        var total = range.AddressCount;
        return ExcludesEnds(range) ? total - 2 : total;
    }

    public static IEnumerable<IPAddress> Expand(CidrRange range, int maxAddresses)
    {
        ArgumentNullException.ThrowIfNull(range);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxAddresses, 1);

        if (Count(range) > maxAddresses)
        {
            throw new ArgumentException($"{range} has more than {maxAddresses} addresses to scan.", nameof(range));
        }

        return ExpandCore(range);
    }

    private static IEnumerable<IPAddress> ExpandCore(CidrRange range)
    {
        var byteLength = range.Family == AddressFamily.InterNetwork ? 4 : 16;
        var first = ToValue(range.Network.GetAddressBytes());
        var last = first + (UInt128)(range.AddressCount - 1);

        if (ExcludesEnds(range))
        {
            first += 1;
            last -= 1;
        }

        for (var value = first; ; value++)
        {
            var address = ToAddress(value, byteLength);

            if (IpAddressNormalizer.IsAssignable(address))
            {
                yield return address;
            }

            if (value == last)
            {
                yield break;
            }
        }
    }

    private static bool ExcludesEnds(CidrRange range) =>
        range.Family == AddressFamily.InterNetwork && range.PrefixLength <= 30;

    private static UInt128 ToValue(byte[] bytes)
    {
        Span<byte> padded = stackalloc byte[16];
        bytes.CopyTo(padded[(16 - bytes.Length)..]);
        return BinaryPrimitives.ReadUInt128BigEndian(padded);
    }

    private static IPAddress ToAddress(UInt128 value, int byteLength)
    {
        Span<byte> buffer = stackalloc byte[16];
        BinaryPrimitives.WriteUInt128BigEndian(buffer, value);
        return new IPAddress(buffer[(16 - byteLength)..]);
    }
}
