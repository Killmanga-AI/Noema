using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Noema.Domain;

namespace Noema.Infrastructure.Tests;

[Collection(PostgresCollection.Name)]
[Trait("Category", "Docker")]
public sealed class ScanPersistenceTests(PostgresFixture postgres)
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private static readonly CidrRange Lan = CidrRange.Parse("192.168.50.0/24");

    [Fact]
    public async Task A_scan_run_round_trips_through_its_lifecycle()
    {
        var run = ScanRun.Request(Lan, ScanProbes.Icmp | ScanProbes.Arp | ScanProbes.Tcp, T0);

        await using (var write = postgres.CreateContext())
        {
            write.ScanRuns.Add(run);
            await write.SaveChangesAsync();
        }

        await using (var update = postgres.CreateContext())
        {
            var loaded = await update.ScanRuns.SingleAsync(s => s.Id == run.Id);
            Assert.Equal(ScanStatus.Queued, loaded.Status);
            Assert.Equal(Lan, loaded.Target);
            Assert.Equal(ScanProbes.Icmp | ScanProbes.Arp | ScanProbes.Tcp, loaded.Probes);

            loaded.Start(T0.AddSeconds(1));
            loaded.Fail("Agent went offline", T0.AddSeconds(30));
            await update.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();
        var final = await read.ScanRuns.SingleAsync(s => s.Id == run.Id);

        Assert.Equal(ScanStatus.Failed, final.Status);
        Assert.Equal(T0.AddSeconds(1), final.StartedAt);
        Assert.Equal(T0.AddSeconds(30), final.FinishedAt);
        Assert.Equal("Agent went offline", final.FailureReason);
    }

    [Fact]
    public async Task Observations_round_trip_with_mac_address_and_json_detail()
    {
        var run = ScanRun.Request(Lan, ScanProbes.Arp | ScanProbes.Tcp, T0);
        var mac = MacAddress.Parse("aa:bb:cc:12:34:56");
        var arp = Observation.Create(run.Id, ObservationKind.ArpEntry, IPAddress.Parse("192.168.50.7"), T0, mac);
        var port = Observation.Create(run.Id, ObservationKind.TcpPortOpen, IPAddress.Parse("192.168.50.7"), T0.AddSeconds(2), null, "{\"port\":443,\"banner\":null}");

        await using (var write = postgres.CreateContext())
        {
            write.ScanRuns.Add(run);
            write.Observations.AddRange(arp, port);
            await write.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();
        var observations = await read.Observations.Where(o => o.ScanRunId == run.Id).OrderBy(o => o.ObservedAt).ToListAsync();

        Assert.Equal(2, observations.Count);
        Assert.Equal(mac, observations[0].MacAddress);
        Assert.Equal(IPAddress.Parse("192.168.50.7"), observations[0].Address);
        Assert.Equal(ObservationKind.TcpPortOpen, observations[1].Kind);

        // jsonb normalizes whitespace, so compare meaning instead of text.
        using var detail = JsonDocument.Parse(observations[1].DetailJson!);
        Assert.Equal(443, detail.RootElement.GetProperty("port").GetInt32());
    }

    [Fact]
    public async Task Observations_can_be_queried_by_address_and_time()
    {
        var run = ScanRun.Request(Lan, ScanProbes.Icmp, T0);
        var target = IPAddress.Parse("192.168.50.99");
        var early = Observation.Create(run.Id, ObservationKind.IcmpEchoReply, target, T0);
        var late = Observation.Create(run.Id, ObservationKind.IcmpEchoReply, target, T0.AddHours(2));
        var other = Observation.Create(run.Id, ObservationKind.IcmpEchoReply, IPAddress.Parse("192.168.50.100"), T0.AddHours(2));

        await using (var write = postgres.CreateContext())
        {
            write.ScanRuns.Add(run);
            write.Observations.AddRange(early, late, other);
            await write.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();
        var since = T0.AddHours(1);
        var found = await read.Observations
            .Where(o => o.Address == target && o.ObservedAt >= since)
            .Select(o => o.Id)
            .ToListAsync();

        Assert.Equal(late.Id, Assert.Single(found));
    }

    [Fact]
    public async Task Deleting_a_scan_run_removes_its_observations()
    {
        var run = ScanRun.Request(Lan, ScanProbes.Icmp, T0);
        var observation = Observation.Create(run.Id, ObservationKind.IcmpEchoReply, IPAddress.Parse("192.168.50.5"), T0);

        await using (var write = postgres.CreateContext())
        {
            write.ScanRuns.Add(run);
            write.Observations.Add(observation);
            await write.SaveChangesAsync();
        }

        await using (var delete = postgres.CreateContext())
        {
            var loaded = await delete.ScanRuns.SingleAsync(s => s.Id == run.Id);
            delete.ScanRuns.Remove(loaded);
            await delete.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();
        Assert.False(await read.Observations.AnyAsync(o => o.Id == observation.Id));
    }

    [Fact]
    public async Task An_observation_needs_an_existing_scan_run()
    {
        var orphan = Observation.Create(Guid.NewGuid(), ObservationKind.IcmpEchoReply, IPAddress.Parse("192.168.50.5"), T0);

        await using var context = postgres.CreateContext();
        context.Observations.Add(orphan);

        var thrown = await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync());

        Assert.Equal("23503", PostgresErrors.Find(thrown)?.SqlState);
    }

    [Fact]
    public async Task The_database_refuses_a_running_scan_without_a_start_time()
    {
        await using var context = postgres.CreateContext();

        var thrown = await Assert.ThrowsAnyAsync<Exception>(() => context.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO scan_runs (id, target, probes, status, requested_at, started_at, finished_at, failure_reason) VALUES ({Guid.NewGuid()}, '10.0.0.0/24', 1, 'Running', {T0}, NULL, NULL, NULL)"));

        var postgresError = PostgresErrors.Find(thrown);
        Assert.NotNull(postgresError);
        Assert.Equal("23514", postgresError.SqlState);
        Assert.Equal("ck_scan_runs_status_timestamps", postgresError.ConstraintName);
    }

    [Fact]
    public async Task The_database_refuses_a_finished_scan_without_a_finish_time()
    {
        await using var context = postgres.CreateContext();

        var thrown = await Assert.ThrowsAnyAsync<Exception>(() => context.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO scan_runs (id, target, probes, status, requested_at, started_at, finished_at, failure_reason) VALUES ({Guid.NewGuid()}, '10.0.0.0/24', 1, 'Completed', {T0}, {T0}, NULL, NULL)"));

        Assert.Equal("23514", PostgresErrors.Find(thrown)?.SqlState);
    }
}
