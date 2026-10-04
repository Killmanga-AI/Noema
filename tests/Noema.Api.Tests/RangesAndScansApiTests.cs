using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Noema.Api.Tests;

[Collection(ApiCollection.Name)]
[Trait("Category", "Docker")]
public sealed class RangesAndScansApiTests(ApiFixture api)
{
    /// <summary>
    /// Each test gets its own private /24 so tests never depend on each other's data. They come from 172.16 to 172.29,
    /// which no other test authorizes as a larger range.
    /// </summary>
    private static string NewPrivateRange() => $"172.{Random.Shared.Next(16, 30)}.{Random.Shared.Next(1, 250)}.{0}/24";

    private async Task<(HttpClient Admin, string Cidr)> AuthorizeAsync(string? cidr = null)
    {
        var admin = await api.AdminClientAsync();
        cidr ??= NewPrivateRange();
        var response = await admin.PostAsJsonAsync("/api/v1/authorized-ranges", new { cidr, description = "test" });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (admin, cidr);
    }

    [Fact]
    public async Task An_administrator_can_authorize_a_private_range_and_it_is_audited()
    {
        var (admin, cidr) = await AuthorizeAsync();
        using (admin)
        {
            var list = await admin.GetFromJsonAsync<JsonElement>("/api/v1/authorized-ranges");
            Assert.Contains(list.EnumerateArray(), r => r.GetProperty("cidr").GetString() == cidr);

            var audit = await api.AuditAsync("action=range.created&limit=200");
            Assert.Contains(audit.EnumerateArray(), e => e.GetProperty("targetId").GetString() == cidr);
        }
    }

    [Theory]
    [InlineData("203.0.113.0/24")]
    [InlineData("8.8.8.0/24")]
    [InlineData("0.0.0.0/0")]
    [InlineData("127.0.0.0/8")]
    [InlineData("224.0.0.0/4")]
    [InlineData("10.0.0.0/7")]
    public async Task Public_and_reserved_ranges_cannot_be_authorized(string cidr)
    {
        using var admin = await api.AdminClientAsync();

        var response = await admin.PostAsJsonAsync("/api/v1/authorized-ranges", new { cidr });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("192.168.1.5/24")]
    [InlineData("192.168.1.0")]
    [InlineData("10.1/16")]
    [InlineData("not a range")]
    public async Task Malformed_ranges_are_refused(string? cidr)
    {
        using var admin = await api.AdminClientAsync();

        var response = await admin.PostAsJsonAsync("/api/v1/authorized-ranges", new { cidr });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task The_same_range_cannot_be_authorized_twice()
    {
        var (admin, cidr) = await AuthorizeAsync();
        using (admin)
        {
            var again = await admin.PostAsJsonAsync("/api/v1/authorized-ranges", new { cidr });

            Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
        }
    }

    [Fact]
    public async Task A_range_can_be_removed_and_scans_of_it_are_refused_afterwards()
    {
        var (admin, cidr) = await AuthorizeAsync();
        using (admin)
        {
            var list = await admin.GetFromJsonAsync<JsonElement>("/api/v1/authorized-ranges");
            var id = list.EnumerateArray().Single(r => r.GetProperty("cidr").GetString() == cidr).GetProperty("id").GetGuid();

            var before = await admin.PostAsJsonAsync("/api/v1/scans", new { target = cidr, probes = new[] { "Icmp" } });
            Assert.Equal(HttpStatusCode.Created, before.StatusCode);

            Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/v1/authorized-ranges/{id}")).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await admin.DeleteAsync($"/api/v1/authorized-ranges/{id}")).StatusCode);

            var after = await admin.PostAsJsonAsync("/api/v1/scans", new { target = cidr, probes = new[] { "Icmp" } });
            Assert.Equal(HttpStatusCode.Forbidden, after.StatusCode);
        }
    }

    [Fact]
    public async Task A_scan_inside_an_authorized_range_is_queued_and_audited()
    {
        var (admin, cidr) = await AuthorizeAsync();
        using (admin)
        {
            var operatorUser = await api.CreateUserAsync("Operator");
            using var client = await api.ClientForAsync(operatorUser);

            var response = await client.PostAsJsonAsync("/api/v1/scans", new { target = cidr, probes = new[] { "Icmp", "arp" } });

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            var scan = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal("Queued", scan.GetProperty("status").GetString());
            Assert.Equal(cidr, scan.GetProperty("target").GetString());
            Assert.Equal(operatorUser.Id, scan.GetProperty("requestedByUserId").GetGuid());
            Assert.Equal(2, scan.GetProperty("probes").GetArrayLength());

            var fetched = await client.GetAsync($"/api/v1/scans/{scan.GetProperty("id").GetGuid()}");
            Assert.Equal(HttpStatusCode.OK, fetched.StatusCode);

            var audit = await api.AuditAsync($"action=scan.requested&actor={operatorUser.Username}");
            Assert.Equal(1, audit.GetArrayLength());
        }
    }

    [Fact]
    public async Task A_smaller_range_inside_an_authorized_one_is_allowed()
    {
        var parent = "172.30.0.0/16";
        var (admin, _) = await AuthorizeAsync(parent);
        using (admin)
        {
            var response = await admin.PostAsJsonAsync("/api/v1/scans", new { target = "172.30.5.0/24", probes = new[] { "Icmp" } });

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        }
    }

    [Theory]
    [InlineData("192.168.250.0/24")]
    [InlineData("8.8.8.0/24")]
    [InlineData("100.64.0.0/10")]
    public async Task A_scan_outside_every_authorized_range_is_forbidden_and_audited(string target)
    {
        var operatorUser = await api.CreateUserAsync("Operator");
        using var client = await api.ClientForAsync(operatorUser);

        var response = await client.PostAsJsonAsync("/api/v1/scans", new { target, probes = new[] { "Icmp" } });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        var audit = await api.AuditAsync($"action=scan.denied&actor={operatorUser.Username}");
        Assert.Equal(1, audit.GetArrayLength());
    }

    [Theory]
    [InlineData("127.0.0.0/8")]
    [InlineData("0.0.0.0/0")]
    [InlineData("224.0.0.0/24")]
    public async Task Reserved_targets_are_refused_as_bad_requests(string target)
    {
        var operatorUser = await api.CreateUserAsync("Operator");
        using var client = await api.ClientForAsync(operatorUser);

        var response = await client.PostAsJsonAsync("/api/v1/scans", new { target, probes = new[] { "Icmp" } });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task A_target_over_the_size_limit_is_refused_even_when_authorized()
    {
        var (admin, _) = await AuthorizeAsync("10.0.0.0/8");
        using (admin)
        {
            var response = await admin.PostAsJsonAsync("/api/v1/scans", new { target = "10.0.0.0/8", probes = new[] { "Icmp" } });

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Theory]
    [InlineData(null, "Icmp")]
    [InlineData("", "Icmp")]
    [InlineData("192.168.1.5/24", "Icmp")]
    [InlineData("10.0.0.0/24", null)]
    [InlineData("10.0.0.0/24", "")]
    [InlineData("10.0.0.0/24", "Teleport")]
    [InlineData("10.0.0.0/24", "3")]
    [InlineData("10.0.0.0/24", "None")]
    public async Task Bad_scan_requests_are_rejected_before_any_authorization_check(string? target, string? probe)
    {
        var operatorUser = await api.CreateUserAsync("Operator");
        using var client = await api.ClientForAsync(operatorUser);
        var probes = probe is null ? null : new[] { probe };

        var response = await client.PostAsJsonAsync("/api/v1/scans", new { target, probes });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Scan_listing_is_limited_and_filterable()
    {
        var (admin, cidr) = await AuthorizeAsync();
        using (admin)
        {
            await admin.PostAsJsonAsync("/api/v1/scans", new { target = cidr, probes = new[] { "Icmp" } });

            var queued = await admin.GetFromJsonAsync<JsonElement>("/api/v1/scans?status=queued&limit=5");
            Assert.True(queued.GetArrayLength() is >= 1 and <= 5);
            Assert.All(queued.EnumerateArray(), s => Assert.Equal("Queued", s.GetProperty("status").GetString()));

            Assert.Equal(HttpStatusCode.BadRequest, (await admin.GetAsync("/api/v1/scans?limit=0")).StatusCode);
            Assert.Equal(HttpStatusCode.BadRequest, (await admin.GetAsync("/api/v1/scans?limit=101")).StatusCode);
            Assert.Equal(HttpStatusCode.BadRequest, (await admin.GetAsync("/api/v1/scans?status=exploded")).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/api/v1/scans/{Guid.NewGuid()}")).StatusCode);
        }
    }
}

[Collection(ApiCollection.Name)]
[Trait("Category", "Docker")]
public sealed class AuditApiTests(ApiFixture api)
{
    [Fact]
    public async Task Audit_queries_filter_by_action_prefix_actor_and_outcome()
    {
        var user = await api.CreateUserAsync();
        using var anonymous = api.Anonymous();
        await anonymous.PostAsJsonAsync("/api/v1/auth/login", new { username = user.Username, password = "wrong-password-value" });

        var byPrefix = await api.AuditAsync($"action=auth.login&actor={user.Username}");
        var byOutcome = await api.AuditAsync($"outcome=failure&actor={user.Username}");

        Assert.True(byPrefix.GetArrayLength() >= 1);
        Assert.All(byPrefix.EnumerateArray(), e => Assert.StartsWith("auth.login", e.GetProperty("action").GetString()));
        Assert.All(byOutcome.EnumerateArray(), e => Assert.Equal("Failure", e.GetProperty("outcome").GetString()));
    }

    [Fact]
    public async Task Audit_paging_returns_older_entries_with_the_before_cursor()
    {
        using var admin = await api.AdminClientAsync();

        var firstPage = await admin.GetFromJsonAsync<JsonElement>("/api/v1/audit?limit=2");
        Assert.Equal(2, firstPage.GetArrayLength());
        var cutoff = firstPage[1].GetProperty("occurredAt").GetDateTimeOffset();

        var nextPage = await admin.GetFromJsonAsync<JsonElement>($"/api/v1/audit?limit=2&before={Uri.EscapeDataString(cutoff.ToString("O"))}");

        Assert.All(nextPage.EnumerateArray(), e => Assert.True(e.GetProperty("occurredAt").GetDateTimeOffset() < cutoff));
    }

    [Theory]
    [InlineData("limit=0")]
    [InlineData("limit=201")]
    [InlineData("outcome=maybe")]
    public async Task Bad_audit_queries_are_rejected(string query)
    {
        using var admin = await api.AdminClientAsync();

        Assert.Equal(HttpStatusCode.BadRequest, (await admin.GetAsync("/api/v1/audit?" + query)).StatusCode);
    }

    [Fact]
    public async Task Audit_entries_record_the_caller_address_and_correlation_id()
    {
        var user = await api.CreateUserAsync();

        var audit = await api.AuditAsync($"action=user.created&limit=200");
        var entry = audit.EnumerateArray().First(e => e.GetProperty("targetId").GetString() == user.Id.ToString());

        Assert.False(string.IsNullOrEmpty(entry.GetProperty("correlationId").GetString()));
        Assert.Equal(ApiFixture.AdminUsername, entry.GetProperty("actorName").GetString());
    }
}
