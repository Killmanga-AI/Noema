using System.Net;
using Microsoft.EntityFrameworkCore;
using Noema.Domain;

namespace Noema.Infrastructure.Tests;

[Collection(PostgresCollection.Name)]
[Trait("Category", "Docker")]
public sealed class AssetPersistenceTests(PostgresFixture postgres)
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);

    private static MacAddress NewMac()
    {
        var bytes = Guid.NewGuid().ToByteArray()[..6];
        bytes[0] &= 0xFE; // clear the multicast bit
        if (bytes.All(b => b == 0))
        {
            bytes[5] = 1;
        }

        return MacAddress.FromBytes(bytes);
    }

    private static IPAddress NewIp()
    {
        var bytes = Guid.NewGuid().ToByteArray();
        return new IPAddress(new byte[] { 10, bytes[0], bytes[1], (byte)(bytes[2] | 1) });
    }

    [Fact]
    public async Task A_full_asset_graph_round_trips()
    {
        var wifi = NewMac();
        var ethernet = NewMac();
        var wifiIp = NewIp();
        var ethernetIp = NewIp();
        var v6 = IPAddress.Parse("fe80::abcd");

        var asset = Asset.Discover(T0);
        asset.Rename("Latif laptop");
        asset.ObserveHostname("Laptop.Lan.", T0);
        asset.ClassifyAs(AssetKind.Workstation);
        asset.RecordSighting(wifi, wifiIp, T0);
        asset.RecordSighting(ethernet, ethernetIp, T0.AddMinutes(1));
        asset.RecordSighting(ethernet, v6, T0.AddMinutes(2));

        await using (var write = postgres.CreateContext())
        {
            write.Assets.Add(asset);
            await write.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();
        var loaded = await read.Assets
            .Include(a => a.Interfaces)
            .ThenInclude(i => i.Addresses)
            .SingleAsync(a => a.Id == asset.Id);

        Assert.Equal("Latif laptop", loaded.Name);
        Assert.Equal("laptop.lan", loaded.Hostname);
        Assert.Equal(T0, loaded.HostnameObservedAt);
        Assert.Equal(AssetKind.Workstation, loaded.Kind);
        Assert.Equal(T0, loaded.FirstSeenAt);
        Assert.Equal(T0.AddMinutes(2), loaded.LastSeenAt);
        Assert.Null(loaded.RetiredAt);
        Assert.Equal(2, loaded.Interfaces.Count);

        var wifiInterface = loaded.Interfaces.Single(i => i.MacAddress == wifi);
        Assert.Equal(wifiIp, Assert.Single(wifiInterface.Addresses).Address);

        var ethernetInterface = loaded.Interfaces.Single(i => i.MacAddress == ethernet);
        Assert.Equal(2, ethernetInterface.Addresses.Count);
        Assert.Contains(ethernetInterface.Addresses, a => a.Address.Equals(ethernetIp));
        Assert.Contains(ethernetInterface.Addresses, a => a.Address.Equals(v6));
    }

    [Fact]
    public async Task Assets_can_be_found_by_mac_and_by_ip()
    {
        var mac = NewMac();
        var ip = NewIp();
        var asset = Asset.Discover(T0);
        asset.RecordSighting(mac, ip, T0);

        await using (var write = postgres.CreateContext())
        {
            write.Assets.Add(asset);
            await write.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();

        var byMac = await read.AssetInterfaces.Where(i => i.MacAddress == mac).Select(i => i.AssetId).ToListAsync();
        var byIp = await read.InterfaceAddresses.Where(a => a.Address == ip).Select(a => a.AssetInterfaceId).ToListAsync();

        Assert.Equal(asset.Id, Assert.Single(byMac));
        Assert.Equal(asset.Interfaces[0].Id, Assert.Single(byIp));
    }

    [Fact]
    public async Task Adding_a_sighting_to_a_loaded_asset_persists_the_new_interface()
    {
        var firstMac = NewMac();
        var secondMac = NewMac();
        var asset = Asset.Discover(T0);
        asset.RecordSighting(firstMac, NewIp(), T0);

        await using (var write = postgres.CreateContext())
        {
            write.Assets.Add(asset);
            await write.SaveChangesAsync();
        }

        await using (var update = postgres.CreateContext())
        {
            var loaded = await update.Assets
                .Include(a => a.Interfaces).ThenInclude(i => i.Addresses)
                .SingleAsync(a => a.Id == asset.Id);
            loaded.RecordSighting(secondMac, NewIp(), T0.AddHours(1));
            await update.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();
        var interfaces = await read.AssetInterfaces.Where(i => i.AssetId == asset.Id).ToListAsync();

        Assert.Equal(2, interfaces.Count);
    }

    [Fact]
    public async Task Concurrent_updates_to_the_same_asset_are_detected()
    {
        var asset = Asset.Discover(T0);
        await using (var write = postgres.CreateContext())
        {
            write.Assets.Add(asset);
            await write.SaveChangesAsync();
        }

        await using var first = postgres.CreateContext();
        await using var second = postgres.CreateContext();
        var firstCopy = await first.Assets.SingleAsync(a => a.Id == asset.Id);
        var secondCopy = await second.Assets.SingleAsync(a => a.Id == asset.Id);

        firstCopy.Rename("first writer");
        await first.SaveChangesAsync();

        secondCopy.Rename("second writer");
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => second.SaveChangesAsync());
    }

    [Fact]
    public async Task Deleting_an_asset_removes_its_interfaces_and_addresses()
    {
        var asset = Asset.Discover(T0);
        asset.RecordSighting(NewMac(), NewIp(), T0);
        var interfaceId = asset.Interfaces[0].Id;

        await using (var write = postgres.CreateContext())
        {
            write.Assets.Add(asset);
            await write.SaveChangesAsync();
        }

        await using (var delete = postgres.CreateContext())
        {
            var loaded = await delete.Assets.SingleAsync(a => a.Id == asset.Id);
            delete.Assets.Remove(loaded);
            await delete.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();
        Assert.False(await read.AssetInterfaces.AnyAsync(i => i.Id == interfaceId));
        Assert.False(await read.InterfaceAddresses.AnyAsync(a => a.AssetInterfaceId == interfaceId));
    }

    [Fact]
    public async Task The_database_refuses_a_second_macless_interface_on_one_asset()
    {
        var asset = Asset.Discover(T0);
        asset.RecordSighting(null, NewIp(), T0);

        await using var context = postgres.CreateContext();
        context.Assets.Add(asset);
        await context.SaveChangesAsync();

        var thrown = await Assert.ThrowsAnyAsync<Exception>(() => context.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO asset_interfaces (id, asset_id, mac_address, first_seen_at, last_seen_at) VALUES ({Guid.NewGuid()}, {asset.Id}, NULL, {T0}, {T0})"));

        var postgresError = PostgresErrors.Find(thrown);
        Assert.NotNull(postgresError);
        Assert.Equal("23505", postgresError.SqlState);
        Assert.Equal("ux_asset_interfaces_asset_id_no_mac", postgresError.ConstraintName);
    }

    [Fact]
    public async Task The_database_refuses_the_same_address_twice_on_one_interface()
    {
        var ip = NewIp();
        var asset = Asset.Discover(T0);
        asset.RecordSighting(NewMac(), ip, T0);

        await using var context = postgres.CreateContext();
        context.Assets.Add(asset);
        await context.SaveChangesAsync();

        var interfaceId = asset.Interfaces[0].Id;
        var thrown = await Assert.ThrowsAnyAsync<Exception>(() => context.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO interface_addresses (id, asset_interface_id, address, first_seen_at, last_seen_at) VALUES ({Guid.NewGuid()}, {interfaceId}, {ip}, {T0}, {T0})"));

        var postgresError = PostgresErrors.Find(thrown);
        Assert.NotNull(postgresError);
        Assert.Equal("23505", postgresError.SqlState);
    }

    [Fact]
    public async Task The_database_refuses_last_seen_before_first_seen()
    {
        await using var context = postgres.CreateContext();

        var thrown = await Assert.ThrowsAnyAsync<Exception>(() => context.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO assets (id, name, hostname, hostname_observed_at, kind, first_seen_at, last_seen_at, retired_at) VALUES ({Guid.NewGuid()}, NULL, NULL, NULL, 'Unknown', {T0.AddHours(1)}, {T0}, NULL)"));

        var postgresError = PostgresErrors.Find(thrown);
        Assert.NotNull(postgresError);
        Assert.Equal("23514", postgresError.SqlState);
    }
}
