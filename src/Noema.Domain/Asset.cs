using System.Net;

namespace Noema.Domain;

/// <summary>
/// A device on the network. An asset owns its interfaces, so a laptop on wifi and ethernet is one asset
/// with two interfaces. All changes go through this type so its rules hold everywhere.
/// </summary>
public sealed class Asset
{
    public const int MaxNameLength = 255;
    public const int MaxHostnameLength = 253;

    private readonly List<AssetInterface> interfaces = [];

    private Asset()
    {
    }

    private Asset(Guid id, DateTimeOffset firstSeenAt)
    {
        Id = id;
        FirstSeenAt = firstSeenAt;
        LastSeenAt = firstSeenAt;
    }

    public Guid Id { get; private set; }

    /// <summary>A label chosen by a person. Never overwritten by discovery.</summary>
    public string? Name { get; private set; }

    /// <summary>The most recent hostname seen on the network, lower case and without a trailing dot.</summary>
    public string? Hostname { get; private set; }

    public DateTimeOffset? HostnameObservedAt { get; private set; }

    public AssetKind Kind { get; private set; } = AssetKind.Unknown;

    public DateTimeOffset FirstSeenAt { get; private set; }

    public DateTimeOffset LastSeenAt { get; private set; }

    public DateTimeOffset? RetiredAt { get; private set; }

    public bool IsRetired => RetiredAt.HasValue;

    public IReadOnlyList<AssetInterface> Interfaces => interfaces;

    public static Asset Discover(DateTimeOffset seenAt)
    {
        Guard.Utc(seenAt, nameof(seenAt));
        return new Asset(Ids.New(seenAt), seenAt);
    }

    /// <summary>
    /// Records that this asset was seen with the given MAC and or IP address. Finds or creates the matching
    /// interface, records the address on it, and keeps first and last seen correct even when results arrive out of order.
    /// Retired assets keep their state, deciding whether a sighting revives one is a policy for the caller.
    /// </summary>
    public AssetInterface RecordSighting(MacAddress? mac, IPAddress? address, DateTimeOffset seenAt)
    {
        Guard.Utc(seenAt, nameof(seenAt));

        if (mac is null && address is null)
        {
            throw new ArgumentException("A sighting needs a MAC address, an IP address, or both.");
        }

        var normalized = address is null ? null : Guard.DeviceAddress(address, nameof(address));

        var networkInterface = interfaces.FirstOrDefault(i => Equals(i.MacAddress, mac));
        if (networkInterface is null)
        {
            networkInterface = new AssetInterface(Ids.New(seenAt), Id, mac, seenAt);
            interfaces.Add(networkInterface);
        }

        networkInterface.RecordSighting(normalized, seenAt);
        Touch(seenAt);
        return networkInterface;
    }

    public void ObserveHostname(string hostname, DateTimeOffset seenAt)
    {
        Guard.Utc(seenAt, nameof(seenAt));
        var normalized = NormalizeHostname(hostname);

        Touch(seenAt);

        // An older observation arriving late must not overwrite a newer one.
        if (HostnameObservedAt is { } current && seenAt < current)
        {
            return;
        }

        Hostname = normalized;
        HostnameObservedAt = seenAt;
    }

    public void Rename(string? name)
    {
        var trimmed = string.IsNullOrWhiteSpace(name) ? null : name.Trim();

        if (trimmed is { Length: > MaxNameLength })
        {
            throw new ArgumentException($"A name can be at most {MaxNameLength} characters.", nameof(name));
        }

        Name = trimmed;
    }

    public void ClassifyAs(AssetKind kind)
    {
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown asset kind.");
        }

        Kind = kind;
    }

    public void Retire(DateTimeOffset at)
    {
        Guard.Utc(at, nameof(at));
        RetiredAt ??= at;
    }

    public void Reactivate() => RetiredAt = null;

    private void Touch(DateTimeOffset seenAt)
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

    private static string NormalizeHostname(string? hostname)
    {
        if (string.IsNullOrWhiteSpace(hostname))
        {
            throw new ArgumentException("A hostname is required.", nameof(hostname));
        }

        var value = hostname.Trim().TrimEnd('.').ToLowerInvariant();

        if (value.Length == 0
            || value.Length > MaxHostnameLength
            || value.StartsWith('.')
            || value.Contains("..", StringComparison.Ordinal)
            || !value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_'))
        {
            throw new ArgumentException("The hostname is not valid.", nameof(hostname));
        }

        return value;
    }
}
