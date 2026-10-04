using System.Net;
using Microsoft.EntityFrameworkCore;
using Noema.Domain;

namespace Noema.Infrastructure.Tests;

[Collection(PostgresCollection.Name)]
[Trait("Category", "Docker")]
public sealed class SecurityPersistenceTests(PostgresFixture postgres)
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);

    private static string NewName() => "u" + Guid.NewGuid().ToString("N")[..12];

    private static User NewUser(UserRole role = UserRole.Operator) => User.Create(NewName(), "hash-value", role, T0);

    private async Task<User> SaveUserAsync(UserRole role = UserRole.Operator)
    {
        var user = NewUser(role);
        await using var context = postgres.CreateContext();
        context.Users.Add(user);
        await context.SaveChangesAsync();
        return user;
    }

    [Fact]
    public async Task All_security_tables_exist_with_snake_case_columns()
    {
        await using var context = postgres.CreateContext();
        var tables = await context.Database
            .SqlQueryRaw<string>("SELECT table_name AS \"Value\" FROM information_schema.tables WHERE table_schema = 'public'")
            .ToListAsync();

        foreach (var expected in new[] { "users", "refresh_tokens", "authorized_ranges", "audit_entries" })
        {
            Assert.Contains(expected, tables);
        }

        var columns = await context.Database
            .SqlQueryRaw<string>("SELECT column_name AS \"Value\" FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users'")
            .ToListAsync();
        Assert.Contains("password_hash", columns);
        Assert.Contains("failed_login_count", columns);
        Assert.Contains("locked_until", columns);
    }

    [Fact]
    public async Task A_user_round_trips_with_lockout_state()
    {
        var user = NewUser(UserRole.Admin);
        for (var i = 0; i < User.MaxFailedLogins; i++)
        {
            user.RecordFailedLogin(T0);
        }

        await using (var write = postgres.CreateContext())
        {
            write.Users.Add(user);
            await write.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();
        var loaded = await read.Users.SingleAsync(u => u.Id == user.Id);

        Assert.Equal(user.Username, loaded.Username);
        Assert.Equal(UserRole.Admin, loaded.Role);
        Assert.Equal(T0 + User.LockoutDuration, loaded.LockedUntil);
        Assert.True(loaded.IsLockedOut(T0));
        Assert.Equal("hash-value", loaded.PasswordHash);
    }

    [Fact]
    public async Task The_database_refuses_a_duplicate_username()
    {
        var existing = await SaveUserAsync();

        await using var context = postgres.CreateContext();
        context.Users.Add(User.Create(existing.Username, "another-hash", UserRole.Operator, T0));

        var thrown = await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync());

        var error = PostgresErrors.Find(thrown);
        Assert.NotNull(error);
        Assert.Equal("23505", error.SqlState);
        Assert.Equal("ux_users_username", error.ConstraintName);
    }

    [Fact]
    public async Task Two_writers_changing_the_same_user_are_detected()
    {
        var user = await SaveUserAsync();

        await using var first = postgres.CreateContext();
        await using var second = postgres.CreateContext();
        var firstCopy = await first.Users.SingleAsync(u => u.Id == user.Id);
        var secondCopy = await second.Users.SingleAsync(u => u.Id == user.Id);

        firstCopy.RecordFailedLogin(T0);
        await first.SaveChangesAsync();

        secondCopy.RecordFailedLogin(T0);
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => second.SaveChangesAsync());
    }

    [Fact]
    public async Task Refresh_tokens_round_trip_and_hashes_are_unique()
    {
        var user = await SaveUserAsync();
        var token = RefreshToken.Issue(user.Id, "hash-" + Guid.NewGuid().ToString("N"), T0, TimeSpan.FromDays(7));

        await using (var write = postgres.CreateContext())
        {
            write.RefreshTokens.Add(token);
            await write.SaveChangesAsync();
        }

        await using (var read = postgres.CreateContext())
        {
            var loaded = await read.RefreshTokens.SingleAsync(t => t.Id == token.Id);
            Assert.Equal(token.TokenHash, loaded.TokenHash);
            Assert.Equal(T0.AddDays(7), loaded.ExpiresAt);
            Assert.True(loaded.IsActive(T0));
        }

        await using var duplicate = postgres.CreateContext();
        duplicate.RefreshTokens.Add(RefreshToken.Issue(user.Id, token.TokenHash, T0, TimeSpan.FromDays(7)));
        var thrown = await Assert.ThrowsAsync<DbUpdateException>(() => duplicate.SaveChangesAsync());
        Assert.Equal("23505", PostgresErrors.Find(thrown)?.SqlState);
    }

    [Fact]
    public async Task Revoking_a_refresh_token_persists_and_a_concurrent_use_is_detected()
    {
        var user = await SaveUserAsync();
        var token = RefreshToken.Issue(user.Id, "hash-" + Guid.NewGuid().ToString("N"), T0, TimeSpan.FromDays(7));
        await using (var write = postgres.CreateContext())
        {
            write.RefreshTokens.Add(token);
            await write.SaveChangesAsync();
        }

        await using var first = postgres.CreateContext();
        await using var second = postgres.CreateContext();
        var firstCopy = await first.RefreshTokens.SingleAsync(t => t.Id == token.Id);
        var secondCopy = await second.RefreshTokens.SingleAsync(t => t.Id == token.Id);

        firstCopy.Revoke(T0.AddMinutes(1), Guid.NewGuid());
        await first.SaveChangesAsync();

        secondCopy.Revoke(T0.AddMinutes(1), Guid.NewGuid());
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => second.SaveChangesAsync());
    }

    [Fact]
    public async Task Deleting_a_user_removes_their_refresh_tokens()
    {
        var user = await SaveUserAsync();
        var token = RefreshToken.Issue(user.Id, "hash-" + Guid.NewGuid().ToString("N"), T0, TimeSpan.FromDays(7));
        await using (var write = postgres.CreateContext())
        {
            write.RefreshTokens.Add(token);
            await write.SaveChangesAsync();
        }

        await using (var delete = postgres.CreateContext())
        {
            delete.Users.Remove(await delete.Users.SingleAsync(u => u.Id == user.Id));
            await delete.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();
        Assert.False(await read.RefreshTokens.AnyAsync(t => t.Id == token.Id));
    }

    [Fact]
    public async Task Authorized_ranges_round_trip_and_are_unique()
    {
        var admin = await SaveUserAsync(UserRole.Admin);
        var cidr = CidrRange.Parse($"172.{Random.Shared.Next(16, 32)}.{Random.Shared.Next(1, 250)}.0/24");
        var range = AuthorizedRange.Create(cidr, "lab", admin.Id, T0, allowPublic: false);

        await using (var write = postgres.CreateContext())
        {
            write.AuthorizedRanges.Add(range);
            await write.SaveChangesAsync();
        }

        await using (var read = postgres.CreateContext())
        {
            var loaded = await read.AuthorizedRanges.SingleAsync(r => r.Id == range.Id);
            Assert.Equal(cidr, loaded.Range);
            Assert.Equal("lab", loaded.Description);
            Assert.True(await read.AuthorizedRanges.AnyAsync(r => r.Range == cidr));
        }

        await using var duplicate = postgres.CreateContext();
        duplicate.AuthorizedRanges.Add(AuthorizedRange.Create(cidr, null, admin.Id, T0, false));
        var thrown = await Assert.ThrowsAsync<DbUpdateException>(() => duplicate.SaveChangesAsync());
        Assert.Equal("ux_authorized_ranges_range", PostgresErrors.Find(thrown)?.ConstraintName);
    }

    [Fact]
    public async Task A_user_who_authorized_ranges_cannot_be_deleted()
    {
        var admin = await SaveUserAsync(UserRole.Admin);
        var range = AuthorizedRange.Create(
            CidrRange.Parse($"172.{Random.Shared.Next(16, 32)}.{Random.Shared.Next(1, 250)}.0/24"), null, admin.Id, T0, false);
        await using (var write = postgres.CreateContext())
        {
            write.AuthorizedRanges.Add(range);
            await write.SaveChangesAsync();
        }

        await using var delete = postgres.CreateContext();
        delete.Users.Remove(await delete.Users.SingleAsync(u => u.Id == admin.Id));

        var thrown = await Assert.ThrowsAsync<DbUpdateException>(() => delete.SaveChangesAsync());
        Assert.Equal("23503", PostgresErrors.Find(thrown)?.SqlState);
    }

    [Fact]
    public async Task Audit_entries_round_trip_with_address_and_json_and_outlive_their_user()
    {
        var user = await SaveUserAsync();
        var entry = AuditEntry.Create(
            "auth.login.failed", AuditOutcome.Failure, T0, user.Id, user.Username, "user", user.Id.ToString(),
            "{\"reason\":\"bad_password\"}", IPAddress.Parse("192.168.1.50"), "corr-123");

        await using (var write = postgres.CreateContext())
        {
            write.AuditEntries.Add(entry);
            await write.SaveChangesAsync();
        }

        await using (var delete = postgres.CreateContext())
        {
            delete.Users.Remove(await delete.Users.SingleAsync(u => u.Id == user.Id));
            await delete.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();
        var loaded = await read.AuditEntries.SingleAsync(a => a.Id == entry.Id);

        Assert.Equal("auth.login.failed", loaded.Action);
        Assert.Equal(AuditOutcome.Failure, loaded.Outcome);
        Assert.Equal(IPAddress.Parse("192.168.1.50"), loaded.RemoteAddress);
        Assert.Equal(user.Id, loaded.ActorUserId);
        Assert.Equal(user.Username, loaded.ActorName);
        Assert.Contains("bad_password", loaded.DetailJson);
    }

    [Fact]
    public async Task Audit_columns_use_the_native_types()
    {
        await using var context = postgres.CreateContext();

        var types = await context.Database
            .SqlQueryRaw<string>(
                "SELECT column_name || ':' || udt_name AS \"Value\" FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'audit_entries'")
            .ToListAsync();

        Assert.Contains("remote_address:inet", types);
        Assert.Contains("detail_json:jsonb", types);
        Assert.Contains("occurred_at:timestamptz", types);
    }

    [Fact]
    public async Task Scan_runs_remember_who_requested_them()
    {
        var requester = await SaveUserAsync();
        var run = ScanRun.Request(CidrRange.Parse("192.168.60.0/24"), ScanProbes.Icmp, T0, requester.Id);

        await using (var write = postgres.CreateContext())
        {
            write.ScanRuns.Add(run);
            await write.SaveChangesAsync();
        }

        await using var read = postgres.CreateContext();
        Assert.Equal(requester.Id, (await read.ScanRuns.SingleAsync(s => s.Id == run.Id)).RequestedByUserId);
    }
}
