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
public sealed class AgentEnrollmentApiTests(ApiFixture api)
{
    private static async Task<JsonElement> JsonAsync(HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<JsonElement>();

    private object EnrollBody(string token, string name = "office-agent", string[]? capabilities = null, string[]? ranges = null) => new
    {
        enrollmentToken = token,
        agentName = name,
        version = "1.0.0",
        operatingSystem = "Linux",
        capabilities = capabilities ?? new[] { "Icmp" },
        reportedRanges = ranges ?? new[] { "192.168.1.0/24" }
    };

    [Fact]
    public async Task An_administrator_can_create_a_token_that_is_shown_once_and_listed_without_its_secret()
    {
        using var admin = await api.AdminClientAsync();

        var created = await admin.PostAsJsonAsync("/api/v1/agents/enrollment-tokens", new { label = "warehouse", expiresInHours = 2 });

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var body = await JsonAsync(created);
        var raw = body.GetProperty("token").GetString()!;
        Assert.StartsWith("nmt_", raw);

        var list = await admin.GetFromJsonAsync<JsonElement>("/api/v1/agents/enrollment-tokens");
        var entry = list.EnumerateArray().Single(t => t.GetProperty("id").GetGuid() == body.GetProperty("id").GetGuid());
        Assert.Equal("Pending", entry.GetProperty("status").GetString());
        Assert.Equal("warehouse", entry.GetProperty("label").GetString());
        Assert.DoesNotContain(raw, list.GetRawText());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(169)]
    [InlineData(-1)]
    public async Task Token_lifetimes_outside_one_hour_to_a_week_are_refused(int hours)
    {
        using var admin = await api.AdminClientAsync();

        var response = await admin.PostAsJsonAsync("/api/v1/agents/enrollment-tokens", new { expiresInHours = hours });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Operators_and_anonymous_callers_cannot_manage_tokens()
    {
        var operatorUser = await api.CreateUserAsync("Operator");
        using var operatorClient = await api.ClientForAsync(operatorUser);
        using var anonymous = api.Anonymous();

        Assert.Equal(HttpStatusCode.Forbidden, (await operatorClient.PostAsJsonAsync("/api/v1/agents/enrollment-tokens", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await operatorClient.GetAsync("/api/v1/agents/enrollment-tokens")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync("/api/v1/agents/enrollment-tokens", new { })).StatusCode);
    }

    [Fact]
    public async Task An_unused_token_can_be_deleted_but_a_used_one_cannot()
    {
        using var admin = await api.AdminClientAsync();
        var tokenResponse = await JsonAsync(await admin.PostAsJsonAsync("/api/v1/agents/enrollment-tokens", new { label = "to delete" }));
        var id = tokenResponse.GetProperty("id").GetGuid();

        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/v1/agents/enrollment-tokens/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.DeleteAsync($"/api/v1/agents/enrollment-tokens/{id}")).StatusCode);

        var used = await JsonAsync(await admin.PostAsJsonAsync("/api/v1/agents/enrollment-tokens", new { }));
        using var anonymous = api.Anonymous();
        await anonymous.PostAsJsonAsync("/api/v1/agent/enroll", EnrollBody(used.GetProperty("token").GetString()!));
        Assert.Equal(HttpStatusCode.Conflict, (await admin.DeleteAsync($"/api/v1/agents/enrollment-tokens/{used.GetProperty("id").GetGuid()}")).StatusCode);
    }

    [Fact]
    public async Task Enrolling_returns_a_credential_marks_the_token_used_and_lists_the_agent()
    {
        var token = await api.CreateEnrollmentTokenAsync("lab");
        using var anonymous = api.Anonymous();

        var response = await anonymous.PostAsJsonAsync("/api/v1/agent/enroll", EnrollBody(token, "lab-agent", ["Icmp", "arp"], ["192.168.5.0/24", "10.5.0.0/16"]));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await JsonAsync(response);
        var agentId = body.GetProperty("agentId").GetGuid();
        Assert.StartsWith("nma_", body.GetProperty("agentSecret").GetString());

        using var admin = await api.AdminClientAsync();
        var agents = await admin.GetFromJsonAsync<JsonElement>("/api/v1/agents");
        var agent = agents.EnumerateArray().Single(a => a.GetProperty("id").GetGuid() == agentId);
        Assert.Equal("lab-agent", agent.GetProperty("name").GetString());
        Assert.Equal("Active", agent.GetProperty("status").GetString());
        Assert.True(agent.GetProperty("online").GetBoolean());
        Assert.Equal(2, agent.GetProperty("capabilities").GetArrayLength());
        Assert.Equal(2, agent.GetProperty("reportedRanges").GetArrayLength());
        Assert.DoesNotContain("credentialHash", agents.GetRawText(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(body.GetProperty("agentSecret").GetString()!, agents.GetRawText());

        var tokens = await admin.GetFromJsonAsync<JsonElement>("/api/v1/agents/enrollment-tokens");
        Assert.Contains(tokens.EnumerateArray(), t => t.GetProperty("agentId").ValueKind != JsonValueKind.Null
            && t.GetProperty("agentId").GetGuid() == agentId && t.GetProperty("status").GetString() == "Used");
    }

    [Fact]
    public async Task A_token_works_only_once()
    {
        var token = await api.CreateEnrollmentTokenAsync();
        using var anonymous = api.Anonymous();

        var first = await anonymous.PostAsJsonAsync("/api/v1/agent/enroll", EnrollBody(token));
        var second = await anonymous.PostAsJsonAsync("/api/v1/agent/enroll", EnrollBody(token, "second-agent"));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);
    }

    [Fact]
    public async Task Two_agents_racing_for_one_token_cannot_both_win()
    {
        var token = await api.CreateEnrollmentTokenAsync();

        var responses = await Task.WhenAll(Enumerable.Range(0, 4).Select(async i =>
        {
            using var client = api.Anonymous();
            return (await client.PostAsJsonAsync("/api/v1/agent/enroll", EnrollBody(token, "racer-" + i))).StatusCode;
        }));

        Assert.Equal(1, responses.Count(s => s == HttpStatusCode.OK));
        Assert.Equal(3, responses.Count(s => s == HttpStatusCode.Unauthorized));
    }

    [Fact]
    public async Task Unknown_and_garbage_tokens_get_the_same_answer_as_used_ones_and_are_audited()
    {
        var used = await api.CreateEnrollmentTokenAsync();
        using var anonymous = api.Anonymous();
        await anonymous.PostAsJsonAsync("/api/v1/agent/enroll", EnrollBody(used));

        var usedAgain = await anonymous.PostAsJsonAsync("/api/v1/agent/enroll", EnrollBody(used, "again"));
        var unknown = await anonymous.PostAsJsonAsync("/api/v1/agent/enroll", EnrollBody("nmt_" + Guid.NewGuid().ToString("N")));

        Assert.Equal(HttpStatusCode.Unauthorized, usedAgain.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(
            (await JsonAsync(usedAgain)).GetProperty("title").GetString(),
            (await JsonAsync(unknown)).GetProperty("title").GetString());

        var audit = await api.AuditAsync("action=agent.enroll_failed&limit=200");
        Assert.True(audit.GetArrayLength() >= 2);
    }

    [Fact]
    public async Task Bad_enrollment_input_is_rejected_without_using_the_token()
    {
        var token = await api.CreateEnrollmentTokenAsync();
        using var anonymous = api.Anonymous();

        var badName = await anonymous.PostAsJsonAsync("/api/v1/agent/enroll", EnrollBody(token, "x"));
        var badProbe = await anonymous.PostAsJsonAsync("/api/v1/agent/enroll", EnrollBody(token, "good-name", ["Teleport"]));
        var noProbes = await anonymous.PostAsJsonAsync("/api/v1/agent/enroll", EnrollBody(token, "good-name", []));
        var badRange = await anonymous.PostAsJsonAsync("/api/v1/agent/enroll", EnrollBody(token, "good-name", null, ["not-a-range"]));
        var reserved = await anonymous.PostAsJsonAsync("/api/v1/agent/enroll", EnrollBody(token, "good-name", null, ["127.0.0.0/8"]));

        foreach (var response in new[] { badName, badProbe, noProbes, badRange, reserved })
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        // None of the rejected attempts used the token up.
        var fresh = await anonymous.PostAsJsonAsync("/api/v1/agent/enroll", EnrollBody(token, "really-good"));
        Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
    }

    [Fact]
    public async Task Enrollment_is_recorded_in_the_audit_trail_without_the_secret()
    {
        var agent = await api.EnrollAgentAsync(["192.168.6.0/24"]);

        var audit = await api.AuditAsync("action=agent.enrolled&limit=200");

        var entry = audit.EnumerateArray().First(e => e.GetProperty("targetId").GetString() == agent.Id.ToString());
        Assert.Equal("agent:" + agent.Name, entry.GetProperty("actorName").GetString());
        Assert.DoesNotContain(agent.Secret, audit.GetRawText());
    }
}

[Collection(ApiCollection.Name)]
[Trait("Category", "Docker")]
public sealed class AgentAuthenticationApiTests(ApiFixture api)
{
    private static readonly object EmptyClaim = new { capabilities = new[] { "Icmp" }, reportedRanges = new[] { "192.168.1.0/24" } };

    [Fact]
    public async Task Agent_endpoints_refuse_requests_without_credentials()
    {
        using var anonymous = api.Anonymous();

        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync("/api/v1/agent/claim", EmptyClaim)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync($"/api/v1/agent/scans/{Guid.NewGuid()}/progress", new { })).StatusCode);
    }

    [Fact]
    public async Task A_wrong_secret_an_unknown_agent_and_a_malformed_header_are_all_refused()
    {
        var agent = await api.EnrollAgentAsync(["192.168.1.0/24"]);

        using var wrongSecret = api.ClientWithAgentHeader(agent.Id, "nma_wrong");
        using var unknownAgent = api.ClientWithAgentHeader(Guid.NewGuid(), agent.Secret);
        using var malformed = api.Anonymous();
        malformed.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Agent not-a-credential");

        Assert.Equal(HttpStatusCode.Unauthorized, (await wrongSecret.PostAsJsonAsync("/api/v1/agent/claim", EmptyClaim)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await unknownAgent.PostAsJsonAsync("/api/v1/agent/claim", EmptyClaim)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await malformed.PostAsJsonAsync("/api/v1/agent/claim", EmptyClaim)).StatusCode);
    }

    [Fact]
    public async Task User_tokens_cannot_call_agent_endpoints_and_agent_credentials_cannot_call_user_endpoints()
    {
        var agent = await api.EnrollAgentAsync(["192.168.1.0/24"]);
        using var admin = await api.AdminClientAsync();
        using var agentClient = api.ClientFor(agent);

        Assert.Equal(HttpStatusCode.Unauthorized, (await admin.PostAsJsonAsync("/api/v1/agent/claim", EmptyClaim)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await agentClient.GetAsync("/api/v1/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await agentClient.GetAsync("/api/v1/scans")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await agentClient.GetAsync("/api/v1/agents")).StatusCode);
    }

    [Fact]
    public async Task A_revoked_agent_is_locked_out_and_its_running_scan_is_ended()
    {
        var range = RangeSupport.NewRange();
        var agent = await api.EnrollAgentAsync([range]);
        await RangeSupport.AuthorizeAsync(api, range);
        var scanId = await RangeSupport.RequestScanAsync(api, range);
        using var agentClient = api.ClientFor(agent);
        Assert.Equal(HttpStatusCode.OK, (await agentClient.PostAsJsonAsync("/api/v1/agent/claim", new { capabilities = new[] { "Icmp" }, reportedRanges = new[] { range } })).StatusCode);

        using var admin = await api.AdminClientAsync();
        var revoke = await admin.PostAsync($"/api/v1/agents/{agent.Id}/revoke", null);
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        Assert.Equal("Revoked", (await revoke.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("status").GetString());

        Assert.Equal(HttpStatusCode.Unauthorized, (await agentClient.PostAsJsonAsync("/api/v1/agent/claim", EmptyClaim)).StatusCode);

        var scan = await admin.GetFromJsonAsync<JsonElement>($"/api/v1/scans/{scanId}");
        Assert.Equal("Failed", scan.GetProperty("status").GetString());
        Assert.Contains("revoked", scan.GetProperty("failureReason").GetString());
    }

    [Fact]
    public async Task Revoking_is_repeatable_and_needs_an_administrator_and_a_real_agent()
    {
        var agent = await api.EnrollAgentAsync(["192.168.1.0/24"]);
        var operatorUser = await api.CreateUserAsync("Operator");
        using var operatorClient = await api.ClientForAsync(operatorUser);
        using var admin = await api.AdminClientAsync();

        Assert.Equal(HttpStatusCode.Forbidden, (await operatorClient.PostAsync($"/api/v1/agents/{agent.Id}/revoke", null)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsync($"/api/v1/agents/{agent.Id}/revoke", null)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsync($"/api/v1/agents/{agent.Id}/revoke", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PostAsync($"/api/v1/agents/{Guid.NewGuid()}/revoke", null)).StatusCode);
    }

    [Fact]
    public async Task Operators_can_see_the_agent_list()
    {
        var operatorUser = await api.CreateUserAsync("Operator");
        using var client = await api.ClientForAsync(operatorUser);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/agents")).StatusCode);
    }

    [Fact]
    public async Task Reporting_a_reserved_range_when_checking_in_is_refused()
    {
        var agent = await api.EnrollAgentAsync(["192.168.1.0/24"]);
        using var client = api.ClientFor(agent);

        var response = await client.PostAsJsonAsync("/api/v1/agent/claim", new { capabilities = new[] { "Icmp" }, reportedRanges = new[] { "127.0.0.0/8" } });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}

internal static class RangeSupport
{
    private static int next = 10;

    /// <summary>A private /24 no other test uses, so tests never see each other's scans.</summary>
    public static string NewRange() => $"192.168.{Interlocked.Increment(ref next)}.0/24";

    public static async Task AuthorizeAsync(ApiFixture api, string range)
    {
        using var admin = await api.AdminClientAsync();
        var response = await admin.PostAsJsonAsync("/api/v1/authorized-ranges", new { cidr = range, description = "agent test" });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    public static async Task<Guid> RequestScanAsync(ApiFixture api, string range, string[]? probes = null, Guid? agentId = null)
    {
        using var admin = await api.AdminClientAsync();
        var response = await admin.PostAsJsonAsync("/api/v1/scans", new { target = range, probes = probes ?? ["Icmp"], agentId });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    public static async Task<JsonElement> GetScanAsync(ApiFixture api, Guid id)
    {
        using var admin = await api.AdminClientAsync();
        return await admin.GetFromJsonAsync<JsonElement>($"/api/v1/scans/{id}");
    }

    public static object Claim(string range, params string[] capabilities) =>
        new { capabilities = capabilities.Length == 0 ? new[] { "Icmp" } : capabilities, reportedRanges = new[] { range } };
}
