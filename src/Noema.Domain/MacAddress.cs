using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;

namespace Noema.Domain;

/// <summary>
/// A unicast 48 bit hardware address. Zero and multicast (including broadcast) addresses are rejected
/// because they cannot identify a single interface.
/// </summary>
public sealed record MacAddress : IComparable<MacAddress>, IComparable
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);
    private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    private static readonly Regex Separated = new("^[0-9a-f]{2}([:-])[0-9a-f]{2}(?:\\1[0-9a-f]{2}){4}$", Options, RegexTimeout);
    private static readonly Regex Dotted = new("^[0-9a-f]{4}\\.[0-9a-f]{4}\\.[0-9a-f]{4}$", Options, RegexTimeout);
    private static readonly Regex Plain = new("^[0-9a-f]{12}$", Options, RegexTimeout);

    private readonly ulong value;

    private MacAddress(ulong value)
    {
        this.value = value;
    }

    public bool IsLocallyAdministered => ((value >> 40) & 0x02) != 0;

    /// <summary>The first three octets, which identify the manufacturer for globally administered addresses.</summary>
    public string Oui => ToString()[..8];

    public static bool TryParse(string? input, [NotNullWhen(true)] out MacAddress? result)
    {
        result = null;

        if (input is null)
        {
            return false;
        }

        var text = input.Trim();
        if (!Separated.IsMatch(text) && !Dotted.IsMatch(text) && !Plain.IsMatch(text))
        {
            return false;
        }

        var hex = new string(text.Where(Uri.IsHexDigit).ToArray());
        var parsed = ulong.Parse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

        if (!IsUsable(parsed))
        {
            return false;
        }

        result = new MacAddress(parsed);
        return true;
    }

    public static MacAddress Parse(string input)
    {
        if (TryParse(input, out var result))
        {
            return result;
        }

        throw new FormatException($"'{input}' is not a usable unicast MAC address.");
    }

    public static MacAddress FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 6)
        {
            throw new ArgumentException("A MAC address is exactly 6 bytes.", nameof(bytes));
        }

        ulong parsed = 0;
        foreach (var b in bytes)
        {
            parsed = (parsed << 8) | b;
        }

        if (!IsUsable(parsed))
        {
            throw new ArgumentException("The address is zero or multicast and cannot identify an interface.", nameof(bytes));
        }

        return new MacAddress(parsed);
    }

    public static MacAddress FromPhysicalAddress(PhysicalAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return FromBytes(address.GetAddressBytes());
    }

    public PhysicalAddress ToPhysicalAddress() => new(ToBytes());

    public int CompareTo(MacAddress? other) => other is null ? 1 : value.CompareTo(other.value);

    public int CompareTo(object? obj) =>
        obj switch
        {
            null => 1,
            MacAddress other => CompareTo(other),
            _ => throw new ArgumentException($"Object must be of type {nameof(MacAddress)}.", nameof(obj))
        };

    public override string ToString() =>
        string.Join(':', ToBytes().Select(b => b.ToString("x2", CultureInfo.InvariantCulture)));

    private static bool IsUsable(ulong candidate) => candidate != 0 && ((candidate >> 40) & 0x01) == 0;

    private byte[] ToBytes()
    {
        var bytes = new byte[6];
        for (var i = 0; i < 6; i++)
        {
            bytes[i] = (byte)(value >> (8 * (5 - i)));
        }

        return bytes;
    }
}
