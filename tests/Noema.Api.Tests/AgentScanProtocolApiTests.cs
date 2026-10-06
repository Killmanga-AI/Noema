using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Noema.Api.Features.Agents;
using Noema.Domain;
using Noema.Infrastructure.Persistence;

namespace Noema.Api.Tests;

[Collection(ApiCollection.Name)]
[Trait("Category", "Docker")]
public sealed class AgentJobClaimApiTests(ApiFixture api)
{
    [Fact]
    public async Task An_agent_gets_the_scan_for_its_range_once_and_then_nothing()
    {
        var range = RangeSupport.NewRange();
        var agent = await api.EnrollAgentAsync([range]);
        await RangeSupport.AuthorizeAsync(api, range);
        var scanId = await RangeSupport.RequestScanAsync(api, range);
        using var client = api.ClientFor(agent);

        var first = await client.PostAsJsonAsync("/api/v1/agent/claim", RangeSupport.Claim(range));
        var second = await client.PostAsJsonAsync("/api/v1/agent/claim", RangeSupport.Claim(range));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var job = await first.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(scanId, job.GetProperty("scanId").GetGuid());
        Assert.Equal(range, job.GetProperty("target").GetString());
        Assert.Equal("Icmp", job.GetProperty("probes")[0].GetString());
        Assert.True(job.GetProperty("leaseExpiresAt").GetDateTimeOffset() > DateTimeOffset.UtcNow);

        // The second claim means the agent is idle again, so the first scan counts as lost.
        Assert.Equal(HttpStatusCode.NoContent, second.StatusCode);
        var scan = await RangeSupport.GetScanAsync(api, scanId);
        Assert.Equal("Failed", scan.GetProperty("status").GetString());
        Assert.Contains("restarted", scan.GetProperty("failureReason").GetString());
    }

    [Fact]
    public async Task A_claimed_scan_shows_as_running_and_assigned_with_the_claim_audited()
    {
        var range = RangeSupport.NewRange();
        var agent = await api.EnrollAgentAsync([range]);
        await RangeSupport.AuthorizeAsync(api, range);
        var scanId = await RangeSupport.RequestScanAsync(api, range);
        using var client = api.ClientFor(agent);

        await client.PostAsJsonAsync("/api/v1/agent/claim", RangeSupport.Claim(range));

        var scan = await RangeSupport.GetScanAsync(api, scanId);
        Assert.Equal("Running", scan.GetProperty("status").GetString());
        Assert.Equal(agent.Id, scan.GetProperty("assignedAgentId").GetGuid());

        var audit = await api.AuditAsync("action=scan.claimed&limit=200");
        Assert.Contains(audit.EnumerateArray(), e => e.GetProperty("targetId").GetString() == scanId.ToString()
            && e.GetProperty("actorName").GetString() == "agent:" + agent.Name);
    }

    [Fact]
    public async Task Checking_in_marks_the_agent_online_and_refreshes_what_it_reports()
    {
        var range = RangeSupport.NewRange();
        var agent = await api.EnrollAgentAsync(["192.168.1.0/24"]);
        using var client = api.ClientFor(agent);

        var response = await client.PostAsJsonAsync("/api/v1/agent/claim", new
        {
            version = "2.0.0",
            operatingSystem = "Windows 11",
            capabilities = new[] { "Icmp", "Dns" },
            reportedRanges = new[] { range }
        });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        using var admin = await api.AdminClientAsync();
        var agents = await admin.GetFromJsonAsync<JsonElement>("/api/v1/agents");
        var entry = agents.EnumerateArray().Single(a => a.GetProperty("id").GetGuid() == agent.Id);
        Assert.Equal("2.0.0", entry.GetProperty("version").GetString());
        Assert.Equal("Windows 11", entry.GetProperty("operatingSystem").GetString());
        Assert.Equal(range, entry.GetProperty("reportedRanges")[0].GetString());
        Assert.Equal(2, entry.GetProperty("capabilities").GetArrayLength());
        Assert.True(entry.GetProperty("online").GetBoolean());
    }

    [Fact]
    public async Task An_agent_is_not_offered_scans_outside_its_ranges_or_beyond_its_probes()
    {
        var served = RangeSupport.NewRange();
        var elsewhere = RangeSupport.NewRange();
        var agent = await api.EnrollAgentAsync([served]);
        await RangeSupport.AuthorizeAsync(api, elsewhere);
        await RangeSupport.AuthorizeAsync(api, served);
        var outsideScan = await RangeSupport.RequestScanAsync(api, elsewhere);
        var needsArp = await RangeSupport.RequestScanAsync(api, served, ["Icmp", "Arp"]);
        using var client = api.ClientFor(agent);

        var response = await client.PostAsJsonAsync("/api/v1/agent/claim", RangeSupport.Claim(served));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal("Queued", (await RangeSupport.GetScanAsync(api, outsideScan)).GetProperty("status").GetString());
        Assert.Equal("Queued", (await RangeSupport.GetScanAsync(api, needsArp)).GetProperty("status").GetString());
    }

    [Fact]
    public async Task The_oldest_matching_scan_goes_first()
    {
        var range = RangeSupport.NewRange();
        var agent = await api.EnrollAgentAsync([range]);
        await RangeSupport.AuthorizeAsync(api, range);
        var older = await RangeSupport.RequestScanAsync(api, range);
        await Task.Delay(20);
        var newer = await RangeSupport.RequestScanAsync(api, range);
        using var client = api.ClientFor(agent);

        var job = await (await client.PostAsJsonAsync("/api/v1/agent/claim", RangeSupport.Claim(range))).Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(older, job.GetProperty("scanId").GetGuid());
        Assert.Equal("Queued", (await RangeSupport.GetScanAsync(api, newer)).GetProperty("status").GetString());
    }

    [Fact]
    public async Task A_scan_pinned_to_one_agent_is_only_offered_to_that_agent()
    {
        var range = RangeSupport.NewRange();
        var chosen = await api.EnrollAgentAsync([range]);
        var other = await api.EnrollAgentAsync([range]);
        await RangeSupport.AuthorizeAsync(api, range);
        var scanId = await RangeSupport.RequestScanAsync(api, range, null, chosen.Id);
        using var otherClient = api.ClientFor(other);
        using var chosenClient = api.ClientFor(chosen);

        Assert.Equal(HttpStatusCode.NoContent, (await otherClient.PostAsJsonAsync("/api/v1/agent/claim", RangeSupport.Claim(range))).StatusCode);
        var claimed = await chosenClient.PostAsJsonAsync("/api/v1/agent/claim", RangeSupport.Claim(range));

        Assert.Equal(HttpStatusCode.OK, claimed.StatusCode);
        Assert.Equal(scanId, (await claimed.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("scanId").GetGuid());
    }

    [Fact]
    public async Task Pinning_a_scan_to_an_agent_that_cannot_serve_it_or_does_not_exist_is_refused()
    {
        var range = RangeSupport.NewRange();
        var agent = await api.EnrollAgentAsync(["192.168.1.0/24"]);
        await RangeSupport.AuthorizeAsync(api, range);
        using var admin = await api.AdminClientAsync();

        var wrongRange = await admin.PostAsJsonAsync("/api/v1/scans", new { target = range, probes = new[] { "Icmp" }, agentId = agent.Id });
        var missing = await admin.PostAsJsonAsync("/api/v1/scans", new { target = range, probes = new[] { "Icmp" }, agentId = Guid.NewGuid() });

        Assert.Equal(HttpStatusCode.BadRequest, wrongRange.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
    }

    [Fact]
    public async Task Two_agents_asking_at_the_same_moment_never_get_the_same_scan()
    {
        var range = RangeSupport.NewRange();
        var first = await api.EnrollAgentAsync([range]);
        var second = await api.EnrollAgentAsync([range]);
        await RangeSupport.AuthorizeAsync(api, range);
        await RangeSupport.RequestScanAsync(api, range);
        using var firstClient = api.ClientFor(first);
        using var secondClient = api.ClientFor(second);

        var statuses = await Task.WhenAll(
            firstClient.PostAsJsonAsync("/api/v1/agent/claim", RangeSupport.Claim(range)),
            secondClient.PostAsJsonAsync("/api/v1/agent/claim", RangeSupport.Claim(range)));

        Assert.Equal(1, statuses.Count(r => r.StatusCode == HttpStatusCode.OK));
        Assert.Equal(1, statuses.Count(r => r.StatusCode == HttpStatusCode.NoContent));
    }

    [Fact]
    public async Task A_queued_scan_can_be_cancelled_and_is_then_never_offered()
    {
        var range = RangeSupport.NewRange();
        var agent = await api.EnrollAgentAsync([range]);
        await RangeSupport.AuthorizeAsync(api, range);
        var scanId = await RangeSupport.RequestScanAsync(api, range);
        using var admin = await api.AdminClientAsync();

        var cancel = await admin.PostAsync($"/api/v1/scans/{scanId}/cancel", null);
        using var client = api.ClientFor(agent);

        Assert.Equal(HttpStatusCode.OK, cancel.StatusCode);
        Assert.Equal("Cancelled", (await cancel.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("status").GetString());
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsJsonAsync("/api/v1/agent/claim", RangeSupport.Claim(range))).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsync($"/api/v1/scans/{scanId}/cancel", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PostAsync($"/api/v1/scans/{Guid.NewGuid()}/cancel", null)).StatusCode);
    }

    [Fact]
    public async Task Revoking_an_agent_cancels_scans_pinned_to_it_that_have_not_started()
    {
        var range = RangeSupport.NewRange();
        var agent = await api.EnrollAgentAsync([range]);
        await RangeSupport.AuthorizeAsync(api, range);
        var scanId = await RangeSupport.RequestScanAsync(api, range, null, agent.Id);
        using var admin = await api.AdminClientAsync();

        await admin.PostAsync($"/api/v1/agents/{agent.Id}/revoke", null);

        Assert.Equal("Cancelled", (await RangeSupport.GetScanAsync(api, scanId)).GetProperty("status").GetString());
    }
}

[Collection(ApiCollection.Name)]
[Trait("Category", "Docker")]
public sealed class AgentScanProgressApiTests(ApiFixture api)
{
    private sealed record Running(TestAgent Agent, string Range, Guid ScanId, HttpClient Client);

    private async Task<Running> StartScanAsync()
    {
        var range = RangeSupport.NewRange();
        var agent = await api.EnrollAgentAsync([range]);
        await RangeSupport.AuthorizeAsync(api, range);
        var scanId = await RangeSupport.RequestScanAsync(api, range);
        var client = api.ClientFor(agent);
        var claim = await client.PostAsJsonAsync("/api/v1/agent/claim", RangeSupport.Claim(range));
        Assert.Equal(HttpStatusCode.OK, claim.StatusCode);
        return new Running(agent, range, scanId, client);
    }

    private static string Ip(string range, int host) => range.Replace(".0/24", "." + host);

    private static object Obs(string range, int host, string kind = "IcmpEchoReply", DateTimeOffset? at = null, string? detail = null, string? mac = null) =>
        new { kind, address = Ip(range, host), observedAt = at ?? DateTimeOffset.UtcNow, macAddress = mac, detailJson = detail };

    [Fact]
    public async Task Progress_updates_the_counters_and_pushes_the_lease_out()
    {
        var run = await StartScanAsync();
        using var client = run.Client;
        var before = (await RangeSupport.GetScanAsync(api, run.ScanId));

        var response = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/progress", new { targetsPlanned = 254, targetsScanned = 100, hostsResponded = 7 });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(body.GetProperty("cancelRequested").GetBoolean());
        Assert.True(body.GetProperty("leaseExpiresAt").GetDateTimeOffset() > DateTimeOffset.UtcNow);

        var scan = await RangeSupport.GetScanAsync(api, run.ScanId);
        Assert.Equal(254, scan.GetProperty("targetsPlanned").GetInt64());
        Assert.Equal(100, scan.GetProperty("targetsScanned").GetInt64());
        Assert.Equal(7, scan.GetProperty("hostsResponded").GetInt64());
        Assert.Equal(0, before.GetProperty("targetsScanned").GetInt64());
    }

    [Theory]
    [InlineData(10, 20, 0)]
    [InlineData(10, 5, 6)]
    [InlineData(-1, 0, 0)]
    public async Task Progress_that_does_not_add_up_is_refused(long planned, long scanned, long responded)
    {
        var run = await StartScanAsync();
        using var client = run.Client;

        var response = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/progress", new { targetsPlanned = planned, targetsScanned = scanned, hostsResponded = responded });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task A_cancel_request_reaches_the_agent_on_its_next_report_and_it_can_finish_as_cancelled()
    {
        var run = await StartScanAsync();
        using var client = run.Client;
        using var admin = await api.AdminClientAsync();

        var cancel = await admin.PostAsync($"/api/v1/scans/{run.ScanId}/cancel", null);
        Assert.Equal(HttpStatusCode.OK, cancel.StatusCode);
        Assert.True((await cancel.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("cancelRequested").GetBoolean());

        var progress = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/progress", new { targetsPlanned = 254, targetsScanned = 3, hostsResponded = 0 });
        Assert.True((await progress.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("cancelRequested").GetBoolean());

        var complete = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/complete", new { outcome = "Cancelled", targetsPlanned = 254, targetsScanned = 3, hostsResponded = 0 });
        Assert.Equal(HttpStatusCode.NoContent, complete.StatusCode);
        Assert.Equal("Cancelled", (await RangeSupport.GetScanAsync(api, run.ScanId)).GetProperty("status").GetString());
    }

    [Fact]
    public async Task An_agent_cannot_touch_a_scan_that_belongs_to_another_agent()
    {
        var run = await StartScanAsync();
        using var owner = run.Client;
        var intruder = await api.EnrollAgentAsync([run.Range]);
        using var intruderClient = api.ClientFor(intruder);

        Assert.Equal(HttpStatusCode.NotFound, (await intruderClient.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/progress", new { targetsPlanned = 1, targetsScanned = 0, hostsResponded = 0 })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await intruderClient.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", new { sequence = 1, observations = new[] { Obs(run.Range, 5) } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await intruderClient.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/complete", new { outcome = "Completed" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await intruderClient.PostAsJsonAsync($"/api/v1/agent/scans/{Guid.NewGuid()}/progress", new { targetsPlanned = 1, targetsScanned = 0, hostsResponded = 0 })).StatusCode);
    }

    [Fact]
    public async Task Uploaded_observations_are_stored_and_listed_in_order_and_a_repeat_is_not_stored_twice()
    {
        var run = await StartScanAsync();
        using var client = run.Client;
        var now = DateTimeOffset.UtcNow;
        var batch = new
        {
            sequence = 1,
            observations = new[]
            {
                Obs(run.Range, 5, at: now.AddSeconds(-3), detail: "{\"rttMs\":1.2}"),
                Obs(run.Range, 9, "ArpEntry", at: now.AddSeconds(-2), mac: "aa:bb:cc:00:00:09")
            }
        };

        var first = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", batch);
        var repeat = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", batch);

        var firstBody = await first.Content.ReadFromJsonAsync<JsonElement>();
        var repeatBody = await repeat.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(2, firstBody.GetProperty("accepted").GetInt32());
        Assert.False(firstBody.GetProperty("duplicate").GetBoolean());
        Assert.True(repeatBody.GetProperty("duplicate").GetBoolean());
        Assert.Equal(0, repeatBody.GetProperty("accepted").GetInt32());

        var second = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", new { sequence = 2, observations = new[] { Obs(run.Range, 20, at: now.AddSeconds(-1)) } });
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);

        using var admin = await api.AdminClientAsync();
        var listed = await admin.GetFromJsonAsync<JsonElement>($"/api/v1/scans/{run.ScanId}/observations");
        Assert.Equal(3, listed.GetArrayLength());
        Assert.Equal(Ip(run.Range, 5), listed[0].GetProperty("address").GetString());
        Assert.Equal("aa:bb:cc:00:00:09", listed[1].GetProperty("macAddress").GetString());

        var page = await admin.GetFromJsonAsync<JsonElement>($"/api/v1/scans/{run.ScanId}/observations?limit=2");
        Assert.Equal(2, page.GetArrayLength());
        var rest = await admin.GetFromJsonAsync<JsonElement>($"/api/v1/scans/{run.ScanId}/observations?limit=2&after={page[1].GetProperty("id").GetGuid()}");
        Assert.Equal(1, rest.GetArrayLength());
        Assert.Equal(Ip(run.Range, 20), rest[0].GetProperty("address").GetString());
    }

    [Fact]
    public async Task A_skipped_batch_number_is_refused_and_does_not_lose_data_silently()
    {
        var run = await StartScanAsync();
        using var client = run.Client;

        var gap = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", new { sequence = 2, observations = new[] { Obs(run.Range, 5) } });
        Assert.Equal(HttpStatusCode.Conflict, gap.StatusCode);

        var inOrder = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", new { sequence = 1, observations = new[] { Obs(run.Range, 5) } });
        Assert.Equal(HttpStatusCode.OK, inOrder.StatusCode);
    }

    [Fact]
    public async Task An_invalid_observation_rejects_the_whole_batch_and_does_not_advance_the_sequence()
    {
        var run = await StartScanAsync();
        using var client = run.Client;
        var outside = new { kind = "IcmpEchoReply", address = "10.99.99.99", observedAt = DateTimeOffset.UtcNow, macAddress = (string?)null, detailJson = (string?)null };

        var rejected = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", new { sequence = 1, observations = new[] { Obs(run.Range, 5), outside } });

        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        using var admin = await api.AdminClientAsync();
        Assert.Equal(0, (await admin.GetFromJsonAsync<JsonElement>($"/api/v1/scans/{run.ScanId}/observations")).GetArrayLength());

        var corrected = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", new { sequence = 1, observations = new[] { Obs(run.Range, 5) } });
        Assert.Equal(HttpStatusCode.OK, corrected.StatusCode);
    }

    [Theory]
    [InlineData("Teleport", 5, null, null)]
    [InlineData("IcmpEchoReply", 0, null, null)]
    [InlineData("IcmpEchoReply", 5, "not json", null)]
    [InlineData("IcmpEchoReply", 5, null, "zz:zz")]
    [InlineData("ArpEntry", 5, null, null)]
    public async Task Malformed_observations_are_rejected(string kind, int host, string? detail, string? mac)
    {
        var run = await StartScanAsync();
        using var client = run.Client;
        var observation = host == 0
            ? (object)new { kind, address = "not-an-ip", observedAt = DateTimeOffset.UtcNow }
            : Obs(run.Range, host, kind, detail: detail, mac: mac);

        var response = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", new { sequence = 1, observations = new[] { observation } });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Observations_with_times_far_from_now_are_rejected_because_the_agent_clock_is_wrong()
    {
        var run = await StartScanAsync();
        using var client = run.Client;

        var future = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", new { sequence = 1, observations = new[] { Obs(run.Range, 5, at: DateTimeOffset.UtcNow.AddHours(2)) } });
        var past = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", new { sequence = 1, observations = new[] { Obs(run.Range, 5, at: DateTimeOffset.UtcNow.AddDays(-3)) } });

        Assert.Equal(HttpStatusCode.BadRequest, future.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, past.StatusCode);
    }

    [Fact]
    public async Task Batch_size_is_limited_and_empty_batches_are_refused()
    {
        var run = await StartScanAsync();
        using var client = run.Client;
        var tooMany = Enumerable.Range(1, 101).Select(i => Obs(run.Range, (i % 250) + 1)).ToArray();

        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", new { sequence = 1, observations = tooMany })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", new { sequence = 1, observations = Array.Empty<object>() })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", new { sequence = 0, observations = new[] { Obs(run.Range, 5) } })).StatusCode);
    }

    [Fact]
    public async Task Completing_ends_the_scan_with_the_final_counts_and_a_repeat_is_harmless()
    {
        var run = await StartScanAsync();
        using var client = run.Client;
        var body = new { outcome = "Completed", targetsPlanned = 254, targetsScanned = 254, hostsResponded = 12 };

        var first = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/complete", body);
        var repeat = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/complete", body);
        var different = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/complete", new { outcome = "Failed", reason = "late" });

        Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, repeat.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, different.StatusCode);

        var scan = await RangeSupport.GetScanAsync(api, run.ScanId);
        Assert.Equal("Completed", scan.GetProperty("status").GetString());
        Assert.Equal(12, scan.GetProperty("hostsResponded").GetInt64());
        Assert.Equal(254, scan.GetProperty("targetsScanned").GetInt64());
    }

    [Fact]
    public async Task A_failed_scan_keeps_the_reason_the_agent_gave_and_needs_one()
    {
        var run = await StartScanAsync();
        using var client = run.Client;

        var noReason = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/complete", new { outcome = "Failed" });
        var badOutcome = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/complete", new { outcome = "Exploded" });
        var failed = await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/complete", new { outcome = "Failed", reason = "Operation not permitted", targetsPlanned = 254, targetsScanned = 5, hostsResponded = 0 });

        Assert.Equal(HttpStatusCode.BadRequest, noReason.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, badOutcome.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, failed.StatusCode);
        var scan = await RangeSupport.GetScanAsync(api, run.ScanId);
        Assert.Equal("Failed", scan.GetProperty("status").GetString());
        Assert.Equal("Operation not permitted", scan.GetProperty("failureReason").GetString());
    }

    [Fact]
    public async Task Nothing_more_can_be_reported_once_the_scan_has_ended()
    {
        var run = await StartScanAsync();
        using var client = run.Client;
        await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/complete", new { outcome = "Completed", targetsPlanned = 1, targetsScanned = 1, hostsResponded = 0 });

        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/progress", new { targetsPlanned = 1, targetsScanned = 1, hostsResponded = 0 })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/observations", new { sequence = 1, observations = new[] { Obs(run.Range, 5) } })).StatusCode);
    }

    [Fact]
    public async Task Completion_is_audited_under_the_agent_name()
    {
        var run = await StartScanAsync();
        using var client = run.Client;
        await client.PostAsJsonAsync($"/api/v1/agent/scans/{run.ScanId}/complete", new { outcome = "Completed", targetsPlanned = 1, targetsScanned = 1, hostsResponded = 0 });

        var audit = await api.AuditAsync("action=scan.completed&limit=200");

        Assert.Contains(audit.EnumerateArray(), e => e.GetProperty("targetId").GetString() == run.ScanId.ToString()
            && e.GetProperty("actorName").GetString() == "agent:" + run.Agent.Name);
    }
}

[Collection(ApiCollection.Name)]
[Trait("Category", "Docker")]
public sealed class LeaseReaperApiTests(ApiFixture api)
{
    private async Task<T> WithDbAsync<T>(Func<NoemaDbContext, Task<T>> action)
    {
        using var scope = api.Factory.Services.CreateScope();
        return await action(scope.ServiceProvider.GetRequiredService<NoemaDbContext>());
    }

    private async Task<int> ReapAsync(DateTimeOffset now) =>
        await api.Factory.Services.GetRequiredService<LeaseReaper>().ReapOnceAsync(now, CancellationToken.None);

    [Fact]
    public async Task A_running_scan_whose_agent_went_silent_is_failed()
    {
        var range = RangeSupport.NewRange();
        var agent = await api.EnrollAgentAsync([range]);
        var now = DateTimeOffset.UtcNow;
        var scan = ScanRun.Request(CidrRange.Parse(range), ScanProbes.Icmp, now.AddHours(-1));
        scan.Claim(agent.Id, now.AddMinutes(-30), TimeSpan.FromMinutes(2));
        await WithDbAsync(async db =>
        {
            db.ScanRuns.Add(scan);
            await db.SaveChangesAsync();
            return 0;
        });

        var reaped = await ReapAsync(now);

        Assert.True(reaped >= 1);
        var loaded = await RangeSupport.GetScanAsync(api, scan.Id);
        Assert.Equal("Failed", loaded.GetProperty("status").GetString());
        Assert.Contains("stopped reporting", loaded.GetProperty("failureReason").GetString());
    }

    [Fact]
    public async Task A_running_scan_with_a_live_lease_is_left_alone()
    {
        var range = RangeSupport.NewRange();
        var agent = await api.EnrollAgentAsync([range]);
        await RangeSupport.AuthorizeAsync(api, range);
        var scanId = await RangeSupport.RequestScanAsync(api, range);
        using var client = api.ClientFor(agent);
        await client.PostAsJsonAsync("/api/v1/agent/claim", RangeSupport.Claim(range));

        await ReapAsync(DateTimeOffset.UtcNow);

        Assert.Equal("Running", (await RangeSupport.GetScanAsync(api, scanId)).GetProperty("status").GetString());
    }

    [Fact]
    public async Task A_queued_scan_nobody_claimed_for_a_day_is_failed_instead_of_waiting_forever()
    {
        var range = RangeSupport.NewRange();
        var now = DateTimeOffset.UtcNow;
        var stale = ScanRun.Request(CidrRange.Parse(range), ScanProbes.Icmp, now.AddDays(-2));
        await WithDbAsync(async db =>
        {
            db.ScanRuns.Add(stale);
            await db.SaveChangesAsync();
            return 0;
        });

        await ReapAsync(now);

        var loaded = await RangeSupport.GetScanAsync(api, stale.Id);
        Assert.Equal("Failed", loaded.GetProperty("status").GetString());
        Assert.Contains("No agent picked up", loaded.GetProperty("failureReason").GetString());
    }

    [Fact]
    public async Task A_recent_queued_scan_is_not_expired()
    {
        var range = RangeSupport.NewRange();
        await RangeSupport.AuthorizeAsync(api, range);
        var scanId = await RangeSupport.RequestScanAsync(api, range);

        await ReapAsync(DateTimeOffset.UtcNow);

        Assert.Equal("Queued", (await RangeSupport.GetScanAsync(api, scanId)).GetProperty("status").GetString());
    }
}
