using System.Net;
using Microsoft.EntityFrameworkCore;
using Noema.Domain;
using Noema.Infrastructure.Persistence.Converters;

namespace Noema.Infrastructure.Tests;

public sealed class CidrRangeListTests
{
    [Fact]
    public void Ranges_round_trip_through_the_text_form()
    {
        var ranges = new[] { CidrRange.Parse("192.168.1.0/24"), CidrRange.Parse("fd00::/8") };

        var text = CidrRangeList.Format(ranges);

        Assert.Equal("192.168.1.0/24,fd00::/8", text);
        Assert.Equal(ranges, CidrRangeList.Parse(text));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Blank_text_is_an_empty_list(string text)
    {
        Assert.Empty(CidrRangeList.Parse(text));
        Assert.Equal(string.Empty, CidrRangeList.Format([]));
    }

    [Fact]
    public void Stray_spaces_and_empty_entries_are_tolerated()
    {
        Assert.Equal(2, CidrRangeList.Parse(" 10.0.0.0/8 , ,192.168.0.0/16,").Count);
    }

    [Fact]
    public void Stored_text_that_is_not_a_range_fails_loudly_instead_of_widening_a_scope()
    {
        Assert.Throws<FormatException>(() => CidrRangeList.Parse("10.0.0.0/8,garbage"));
    }

    [Fact]
    public void The_comparer_treats_equal_lists_as_equal_and_snapshots_by_copy()
    {
        var comparer = new CidrRangeListComparer();
        var a = new List<CidrRange> { CidrRange.Parse("10.0.0.0/8") };
        var b = new List<CidrRange> { CidrRange.Parse("10.0.0.0/8") };

        Assert.True(comparer.Equals(a, b));
        Assert.Equal(comparer.GetHashCode(a), comparer.GetHashCode(b));
        Assert.False(comparer.Equals(a, new List<CidrRange>()));

        var snapshot = (IReadOnlyList<CidrRange>)comparer.Snapshot(a)!;
        a.Add(CidrRange.Parse("192.168.0.0/16"));
        Assert.Single(snapshot);
        Assert.False(comparer.Equals(a, snapshot));
    }
}

[Collection(PostgresCollection.Name)]
[Trait("Category", "Docker")]
public sealed class AgentPersistenceTests(PostgresFixture postgres)
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);

    private static string NewName() => "u" + Guid.NewGuid().ToString("N")[..12];

    private async Task<User> SaveAdminAsync()
    {
        var user = User.Create(NewName(), "hash", UserRole.Admin, T0);
        await using var context = postgres.CreateContext();
        context.Users.Add(user);
        await context.SaveChangesAsync();
        return user;
    }

    private async Task<Agent> SaveAgentAsync(params string[] ranges)
    {
        var agent = Agent.Enroll(
            "agent-" + Guid.NewGuid().ToString("N")[..8], "hash", T0, "1.0", "Linux",
            ScanProbes.Icmp | ScanProbes.Arp, (ranges.Length == 0 ? ["192.168.1.0/24"] : ranges).Select(CidrRange.Parse), IPAddress.Parse("192.168.1.9"));
        await using var context = postgres.CreateContext();
        context.Agents.Add(agent);
        await context.SaveChangesAsync();
        return agent;
    }

    [Fact]
    public async Task An_agent_round_trips_with_its_ranges_capabilities_and_address()
    {
        var agent = await SaveAgentAsync("192.168.1.0/24", "10.0.0.0/8", "fd00::/8");

        await using var read = postgres.CreateContext();
        var loaded = await read.Agents.SingleAsync(a => a.Id == agent.Id);

        Assert.Equal(agent.Name, loaded.Name);
        Assert.Equal(ScanProbes.Icmp | ScanProbes.Arp, loaded.Capabilities);
        Assert.Equal(3, loaded.ReportedRanges.Count);
        Assert.Contains(CidrRange.Parse("fd00::/8"), loaded.ReportedRanges);
        Assert.Equal(IPAddress.Parse("192.168.1.9"), loaded.LastSeenAddress);
        Assert.Equal(AgentStatus.Active, loaded.Status);
        Assert.True(loaded.CanServe(CidrRange.Parse("10.1.0.0/16"), ScanProbes.Icmp));
    }

    [Fact]
    public async Task Changing_the_reported_ranges_is_detected_and_saved()
    {
        var agent = await SaveAgentAsync("192.168.1.0/24");

        await using (var update = postgres.CreateContext())
        {
            var loaded = await update.Agents.SingleAsync(a => a.Id == agent.Id);
            loaded.RecordContact(T0.AddMinutes(1), null, "2.0", "Windows", ScanProbes.Icmp, [CidrRange.Parse("172.16.5.0/24")]);
            await update.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();
        var reloaded = await read.Agents.SingleAsync(a => a.Id == agent.Id);
        Assert.Equal([CidrRange.Parse("172.16.5.0/24")], reloaded.ReportedRanges);
        Assert.Equal(ScanProbes.Icmp, reloaded.Capabilities);
        Assert.Null(reloaded.LastSeenAddress);
    }

    [Fact]
    public async Task A_revoke_and_a_check_in_at_the_same_moment_are_detected()
    {
        var agent = await SaveAgentAsync();
        await using var first = postgres.CreateContext();
        await using var second = postgres.CreateContext();
        var admin = await first.Agents.SingleAsync(a => a.Id == agent.Id);
        var checkIn = await second.Agents.SingleAsync(a => a.Id == agent.Id);

        admin.Revoke(T0.AddMinutes(1));
        await first.SaveChangesAsync();

        checkIn.RecordContact(T0.AddMinutes(1), null, null, null, ScanProbes.Icmp, [CidrRange.Parse("192.168.1.0/24")]);
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => second.SaveChangesAsync());
    }

    [Fact]
    public async Task Enrollment_tokens_round_trip_are_unique_by_hash_and_single_use_under_concurrency()
    {
        var admin = await SaveAdminAsync();
        var hash = "hash-" + Guid.NewGuid().ToString("N");
        var token = EnrollmentToken.Issue(hash, "lab", admin.Id, T0, TimeSpan.FromHours(24));
        await using (var write = postgres.CreateContext())
        {
            write.EnrollmentTokens.Add(token);
            await write.SaveChangesAsync();
        }

        await using (var duplicate = postgres.CreateContext())
        {
            duplicate.EnrollmentTokens.Add(EnrollmentToken.Issue(hash, null, admin.Id, T0, TimeSpan.FromHours(1)));
            var thrown = await Assert.ThrowsAsync<DbUpdateException>(() => duplicate.SaveChangesAsync());
            Assert.Equal("ux_enrollment_tokens_token_hash", PostgresErrors.Find(thrown)?.ConstraintName);
        }

        var agentA = await SaveAgentAsync();
        var agentB = await SaveAgentAsync();
        await using var first = postgres.CreateContext();
        await using var second = postgres.CreateContext();
        var copyA = await first.EnrollmentTokens.SingleAsync(t => t.Id == token.Id);
        var copyB = await second.EnrollmentTokens.SingleAsync(t => t.Id == token.Id);

        copyA.Redeem(agentA.Id, T0.AddMinutes(1));
        await first.SaveChangesAsync();

        copyB.Redeem(agentB.Id, T0.AddMinutes(1));
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => second.SaveChangesAsync());

        await using var read = postgres.CreateContext();
        Assert.Equal(agentA.Id, (await read.EnrollmentTokens.SingleAsync(t => t.Id == token.Id)).AgentId);
    }

    [Fact]
    public async Task A_scan_run_keeps_its_claim_lease_progress_and_batch_state()
    {
        var agent = await SaveAgentAsync();
        var run = ScanRun.Request(CidrRange.Parse("192.168.1.0/24"), ScanProbes.Icmp, T0, null, agent.Id);
        run.Claim(agent.Id, T0.AddSeconds(5), TimeSpan.FromMinutes(2));
        run.ReportProgress(agent.Id, T0.AddSeconds(30), TimeSpan.FromMinutes(2), 254, 100, 7);
        run.AcceptBatch(agent.Id, 1, T0.AddSeconds(31), TimeSpan.FromMinutes(2));
        run.RequestCancel(T0.AddSeconds(40));

        await using (var write = postgres.CreateContext())
        {
            write.ScanRuns.Add(run);
            await write.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();
        var loaded = await read.ScanRuns.SingleAsync(s => s.Id == run.Id);

        Assert.Equal(agent.Id, loaded.RequestedAgentId);
        Assert.Equal(agent.Id, loaded.AssignedAgentId);
        Assert.Equal(T0.AddSeconds(31) + TimeSpan.FromMinutes(2), loaded.LeaseExpiresAt);
        Assert.Equal(254, loaded.TargetsPlanned);
        Assert.Equal(100, loaded.TargetsScanned);
        Assert.Equal(7, loaded.HostsResponded);
        Assert.Equal(1, loaded.LastBatchSequence);
        Assert.Equal(T0.AddSeconds(40), loaded.CancelRequestedAt);
        Assert.True(loaded.IsCancelRequested);
    }

    [Fact]
    public async Task Two_writers_claiming_the_same_scan_cannot_both_win()
    {
        var one = await SaveAgentAsync();
        var two = await SaveAgentAsync();
        var run = ScanRun.Request(CidrRange.Parse("192.168.1.0/24"), ScanProbes.Icmp, T0);
        await using (var write = postgres.CreateContext())
        {
            write.ScanRuns.Add(run);
            await write.SaveChangesAsync();
        }

        await using var first = postgres.CreateContext();
        await using var second = postgres.CreateContext();
        var copyOne = await first.ScanRuns.SingleAsync(s => s.Id == run.Id);
        var copyTwo = await second.ScanRuns.SingleAsync(s => s.Id == run.Id);

        copyOne.Claim(one.Id, T0.AddSeconds(1), TimeSpan.FromMinutes(2));
        await first.SaveChangesAsync();

        copyTwo.Claim(two.Id, T0.AddSeconds(1), TimeSpan.FromMinutes(2));
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => second.SaveChangesAsync());
    }

    [Fact]
    public async Task Old_style_scan_rows_without_the_new_columns_are_still_valid()
    {
        var id = Guid.NewGuid();
        await using (var context = postgres.CreateContext())
        {
            await context.Database.ExecuteSqlInterpolatedAsync(
                $"INSERT INTO scan_runs (id, target, probes, status, requested_at, started_at, finished_at, failure_reason) VALUES ({id}, '10.0.0.0/24', 1, 'Queued', {T0}, NULL, NULL, NULL)");
        }

        await using var read = postgres.CreateContext();
        var loaded = await read.ScanRuns.SingleAsync(s => s.Id == id);
        Assert.Equal(0, loaded.TargetsScanned);
        Assert.Equal(0, loaded.LastBatchSequence);
        Assert.Null(loaded.AssignedAgentId);
    }

    [Fact]
    public async Task Deleting_an_agent_clears_the_links_without_removing_its_scans()
    {
        var agent = await SaveAgentAsync();
        var run = ScanRun.Request(CidrRange.Parse("192.168.1.0/24"), ScanProbes.Icmp, T0, null, agent.Id);
        await using (var write = postgres.CreateContext())
        {
            write.ScanRuns.Add(run);
            await write.SaveChangesAsync();
        }

        await using (var delete = postgres.CreateContext())
        {
            delete.Agents.Remove(await delete.Agents.SingleAsync(a => a.Id == agent.Id));
            await delete.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();
        var survivor = await read.ScanRuns.SingleAsync(s => s.Id == run.Id);
        Assert.Null(survivor.RequestedAgentId);
    }
}
