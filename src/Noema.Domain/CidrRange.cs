using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text.RegularExpressions;

namespace Noema.Domain;

/// <summary>
/// A network range in CIDR notation. Parsing is deliberately strict because these values decide
/// what the scanner is allowed to touch: no host bits, no shorthand like 10.1, no leading zeros, no scope ids.
/// </summary>
public sealed record CidrRange
{
    private static readonly Regex StrictIpv4 = new(
        "^(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}$",
        RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    private CidrRange(IPAddress network, int prefixLength)
    {
        Network = network;
        PrefixLength = prefixLength;
    }

    public IPAddress Network { get; }

    public int PrefixLength { get; }

    public AddressFamily Family => Network.AddressFamily;

    public int TotalBits => Family == AddressFamily.InterNetwork ? 32 : 128;

    /// <summary>Number of addresses in the range, including network and broadcast addresses.</summary>
    public BigInteger AddressCount => BigInteger.One << (TotalBits - PrefixLength);

    public static bool TryParse(string? input, [NotNullWhen(true)] out CidrRange? result)
    {
        result = null;

        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var text = input.Trim();
        var slash = text.IndexOf('/');
        if (slash <= 0 || slash != text.LastIndexOf('/') || slash == text.Length - 1)
        {
            return false;
        }

        var prefixText = text[(slash + 1)..];
        if (prefixText.Length > 3 || !prefixText.All(char.IsAsciiDigit))
        {
            return false;
        }

        if (!TryParseAddress(text[..slash], out var address))
        {
            return false;
        }

        var prefix = int.Parse(prefixText, CultureInfo.InvariantCulture);
        var maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix > maxPrefix)
        {
            return false;
        }

        if (HasHostBits(address.GetAddressBytes(), prefix))
        {
            return false;
        }

        result = new CidrRange(address, prefix);
        return true;
    }

    public static CidrRange Parse(string input)
    {
        if (TryParse(input, out var result))
        {
            return result;
        }

        throw new FormatException(
            $"'{input}' is not a valid CIDR range. Use network notation such as 192.168.1.0/24 with no host bits set.");
    }

    public bool Contains(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        var normalized = IpAddressNormalizer.Normalize(address);
        return normalized.AddressFamily == Family
            && PrefixMatches(normalized.GetAddressBytes(), Network.GetAddressBytes(), PrefixLength);
    }

    public bool Contains(CidrRange other)
    {
        ArgumentNullException.ThrowIfNull(other);

        return other.Family == Family
            && other.PrefixLength >= PrefixLength
            && PrefixMatches(other.Network.GetAddressBytes(), Network.GetAddressBytes(), PrefixLength);
    }

    public override string ToString() => $"{Network}/{PrefixLength}";

    private static bool TryParseAddress(string text, [NotNullWhen(true)] out IPAddress? address)
    {
        address = null;

        if (text.Contains(':'))
        {
            if (text.Contains('%') || !IPAddress.TryParse(text, out var v6) || v6.IsIPv4MappedToIPv6)
            {
                return false;
            }

            address = v6;
            return true;
        }

        if (!StrictIpv4.IsMatch(text) || !IPAddress.TryParse(text, out var v4))
        {
            return false;
        }

        address = v4;
        return true;
    }

    private static int MaskFor(int prefixLength, int byteIndex)
    {
        var bits = Math.Clamp(prefixLength - (byteIndex * 8), 0, 8);
        return bits == 0 ? 0 : (0xFF << (8 - bits)) & 0xFF;
    }

    private static bool HasHostBits(byte[] bytes, int prefixLength)
    {
        for (var i = 0; i < bytes.Length; i++)
        {
            if ((bytes[i] & ~MaskFor(prefixLength, i) & 0xFF) != 0)
            {
                return true;
            }
        }

        return false;
    }

    private static bool PrefixMatches(byte[] candidate, byte[] network, int prefixLength)
    {
        for (var i = 0; i < network.Length; i++)
        {
            var mask = MaskFor(prefixLength, i);
            if ((candidate[i] & mask) != (network[i] & mask))
            {
                return false;
            }
        }

        return true;
    }
}
