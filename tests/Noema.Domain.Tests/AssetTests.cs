using System.Net;

namespace Noema.Domain.Tests;

public sealed class AssetTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);

    private static readonly MacAddress Wifi = MacAddress.Parse("aa:bb:cc:00:00:01");
    private static readonly MacAddress Ethernet = MacAddress.Parse("aa:bb:cc:00:00:02");

    private static IPAddress Ip(string value) => IPAddress.Parse(value);

    [Fact]
    public void Discover_starts_with_matching_first_and_last_seen()
    {
        var asset = Asset.Discover(T0);

        Assert.NotEqual(Guid.Empty, asset.Id);
        Assert.Equal(T0, asset.FirstSeenAt);
        Assert.Equal(T0, asset.LastSeenAt);
        Assert.Equal(AssetKind.Unknown, asset.Kind);
        Assert.Empty(asset.Interfaces);
        Assert.False(asset.IsRetired);
    }

    [Fact]
    public void Discover_gives_each_asset_its_own_id()
    {
        Assert.NotEqual(Asset.Discover(T0).Id, Asset.Discover(T0).Id);
    }

    [Fact]
    public void Discover_rejects_non_utc_timestamps()
    {
        var local = new DateTimeOffset(2026, 10, 4, 14, 0, 0, TimeSpan.FromHours(2));

        Assert.Throws<ArgumentException>(() => Asset.Discover(local));
    }

    [Fact]
    public void A_laptop_on_wifi_and_ethernet_is_one_asset_with_two_interfaces()
    {
        var asset = Asset.Discover(T0);

        asset.RecordSighting(Wifi, Ip("192.168.1.20"), T0);
        asset.RecordSighting(Ethernet, Ip("192.168.1.21"), T0.AddMinutes(1));

        Assert.Equal(2, asset.Interfaces.Count);
        Assert.Contains(asset.Interfaces, i => i.MacAddress == Wifi);
        Assert.Contains(asset.Interfaces, i => i.MacAddress == Ethernet);
    }

    [Fact]
    public void Seeing_the_same_mac_again_reuses_the_interface()
    {
        var asset = Asset.Discover(T0);

        var first = asset.RecordSighting(Wifi, Ip("192.168.1.20"), T0);
        var second = asset.RecordSighting(Wifi, Ip("192.168.1.20"), T0.AddHours(1));

        Assert.Same(first, second);
        Assert.Single(asset.Interfaces);
        Assert.Single(first.Addresses);
        Assert.Equal(T0.AddHours(1), first.LastSeenAt);
        Assert.Equal(T0.AddHours(1), first.Addresses[0].LastSeenAt);
        Assert.Equal(T0, first.Addresses[0].FirstSeenAt);
    }

    [Fact]
    public void A_new_ip_on_the_same_interface_keeps_the_old_address_as_history()
    {
        var asset = Asset.Discover(T0);

        asset.RecordSighting(Wifi, Ip("192.168.1.20"), T0);
        var networkInterface = asset.RecordSighting(Wifi, Ip("192.168.1.99"), T0.AddDays(1));

        Assert.Equal(2, networkInterface.Addresses.Count);
        var old = networkInterface.Addresses.Single(a => a.Address.Equals(Ip("192.168.1.20")));
        var current = networkInterface.Addresses.Single(a => a.Address.Equals(Ip("192.168.1.99")));
        Assert.Equal(T0, old.LastSeenAt);
        Assert.Equal(T0.AddDays(1), current.FirstSeenAt);
    }

    [Fact]
    public void A_sighting_with_only_an_ip_uses_the_single_macless_interface()
    {
        var asset = Asset.Discover(T0);

        var first = asset.RecordSighting(null, Ip("10.20.0.5"), T0);
        var second = asset.RecordSighting(null, Ip("10.20.0.6"), T0.AddMinutes(5));

        Assert.Same(first, second);
        Assert.Null(first.MacAddress);
        Assert.Equal(2, first.Addresses.Count);
    }

    [Fact]
    public void A_sighting_with_only_a_mac_is_allowed()
    {
        var asset = Asset.Discover(T0);

        var networkInterface = asset.RecordSighting(Wifi, null, T0);

        Assert.Empty(networkInterface.Addresses);
        Assert.Equal(Wifi, networkInterface.MacAddress);
    }

    [Fact]
    public void A_sighting_needs_a_mac_or_an_ip()
    {
        Assert.Throws<ArgumentException>(() => Asset.Discover(T0).RecordSighting(null, null, T0));
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("127.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("224.0.0.251")]
    [InlineData("ff02::1")]
    public void Unusable_addresses_are_rejected(string address)
    {
        Assert.Throws<ArgumentException>(() => Asset.Discover(T0).RecordSighting(Wifi, Ip(address), T0));
    }

    [Fact]
    public void Addresses_are_normalized_so_mapped_and_plain_forms_are_one_address()
    {
        var asset = Asset.Discover(T0);

        asset.RecordSighting(Wifi, Ip("192.168.1.20"), T0);
        var networkInterface = asset.RecordSighting(Wifi, Ip("::ffff:192.168.1.20"), T0.AddMinutes(1));

        Assert.Single(networkInterface.Addresses);
    }

    [Fact]
    public void Late_arriving_results_move_first_seen_back_but_never_move_last_seen_back()
    {
        var asset = Asset.Discover(T0);

        asset.RecordSighting(Wifi, Ip("192.168.1.20"), T0.AddHours(2));
        var networkInterface = asset.RecordSighting(Wifi, Ip("192.168.1.20"), T0.AddHours(1));

        Assert.Equal(T0, asset.FirstSeenAt);
        Assert.Equal(T0.AddHours(2), asset.LastSeenAt);
        Assert.Equal(T0.AddHours(1), networkInterface.FirstSeenAt);
        Assert.Equal(T0.AddHours(2), networkInterface.LastSeenAt);
        Assert.Equal(T0.AddHours(1), networkInterface.Addresses[0].FirstSeenAt);
        Assert.Equal(T0.AddHours(2), networkInterface.Addresses[0].LastSeenAt);
    }

    [Fact]
    public void Sightings_with_non_utc_timestamps_are_rejected()
    {
        var local = new DateTimeOffset(2026, 10, 4, 14, 0, 0, TimeSpan.FromHours(2));

        Assert.Throws<ArgumentException>(() => Asset.Discover(T0).RecordSighting(Wifi, Ip("192.168.1.20"), local));
    }

    [Fact]
    public void Hostnames_are_normalized()
    {
        var asset = Asset.Discover(T0);

        asset.ObserveHostname("  Laptop-01.Home.Lan.  ", T0);

        Assert.Equal("laptop-01.home.lan", asset.Hostname);
        Assert.Equal(T0, asset.HostnameObservedAt);
    }

    [Fact]
    public void A_stale_hostname_does_not_overwrite_a_newer_one()
    {
        var asset = Asset.Discover(T0);

        asset.ObserveHostname("new-name", T0.AddHours(1));
        asset.ObserveHostname("old-name", T0);

        Assert.Equal("new-name", asset.Hostname);
        Assert.Equal(T0.AddHours(1), asset.HostnameObservedAt);
    }

    [Fact]
    public void A_newer_hostname_replaces_the_old_one()
    {
        var asset = Asset.Discover(T0);

        asset.ObserveHostname("old-name", T0);
        asset.ObserveHostname("new-name", T0.AddHours(1));

        Assert.Equal("new-name", asset.Hostname);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("bad host")]
    [InlineData("host!name")]
    [InlineData("a..b")]
    [InlineData(".leading")]
    [InlineData("caf\u00e9")]
    public void Invalid_hostnames_are_rejected(string? hostname)
    {
        Assert.Throws<ArgumentException>(() => Asset.Discover(T0).ObserveHostname(hostname!, T0));
    }

    [Fact]
    public void Hostnames_over_the_dns_limit_are_rejected()
    {
        var tooLong = new string('a', Asset.MaxHostnameLength + 1);

        Assert.Throws<ArgumentException>(() => Asset.Discover(T0).ObserveHostname(tooLong, T0));
    }

    [Fact]
    public void Rename_trims_and_clears_blank_names()
    {
        var asset = Asset.Discover(T0);

        asset.Rename("  Front desk printer  ");
        Assert.Equal("Front desk printer", asset.Name);

        asset.Rename("   ");
        Assert.Null(asset.Name);
    }

    [Fact]
    public void Rename_rejects_names_over_the_limit()
    {
        Assert.Throws<ArgumentException>(() => Asset.Discover(T0).Rename(new string('x', Asset.MaxNameLength + 1)));
    }

    [Fact]
    public void Discovery_never_overwrites_a_name_chosen_by_a_person()
    {
        var asset = Asset.Discover(T0);
        asset.Rename("Latif laptop");

        asset.ObserveHostname("desktop-ab12", T0);
        asset.RecordSighting(Wifi, Ip("192.168.1.20"), T0);

        Assert.Equal("Latif laptop", asset.Name);
    }

    [Fact]
    public void ClassifyAs_rejects_unknown_kinds()
    {
        var asset = Asset.Discover(T0);

        asset.ClassifyAs(AssetKind.Printer);
        Assert.Equal(AssetKind.Printer, asset.Kind);

        Assert.Throws<ArgumentOutOfRangeException>(() => asset.ClassifyAs((AssetKind)999));
    }

    [Fact]
    public void Retire_is_idempotent_and_reactivate_clears_it()
    {
        var asset = Asset.Discover(T0);

        asset.Retire(T0.AddDays(1));
        asset.Retire(T0.AddDays(2));

        Assert.True(asset.IsRetired);
        Assert.Equal(T0.AddDays(1), asset.RetiredAt);

        asset.Reactivate();
        Assert.False(asset.IsRetired);
        Assert.Null(asset.RetiredAt);
    }

    [Fact]
    public void A_sighting_does_not_change_the_retired_state()
    {
        var asset = Asset.Discover(T0);
        asset.Retire(T0);

        asset.RecordSighting(Wifi, Ip("192.168.1.20"), T0.AddDays(1));

        Assert.True(asset.IsRetired);
        Assert.Equal(T0.AddDays(1), asset.LastSeenAt);
    }
}
