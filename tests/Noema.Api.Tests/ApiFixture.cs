using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Testcontainers.PostgreSql;

namespace Noema.Api.Tests;

public sealed class BootstrappedApiFactory(string connectionString) : NoemaApiFactory(connectionString)
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        builder.UseSetting("Database:MigrateOnStartup", "true");
        builder.UseSetting("Bootstrap:AdminUsername", ApiFixture.AdminUsername);
        builder.UseSetting("Bootstrap:AdminPassword", ApiFixture.AdminPassword);
    }
}

/// <summary>One Postgres and one running API for all the end to end tests, with the first administrator created.</summary>
public sealed class ApiFixture : IAsyncLifetime
{
    public const string AdminUsername = "test-admin";
    public const string AdminPassword = "section-three-passphrase-1";

    private readonly PostgreSqlContainer container = new PostgreSqlBuilder("postgres:17-alpine").Build();

    public BootstrappedApiFactory Factory { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await container.StartAsync();
        Factory = new BootstrappedApiFactory(container.GetConnectionString());
    }

    public async Task DisposeAsync()
    {
        await Factory.DisposeAsync();
        await container.DisposeAsync();
    }

    public HttpClient Anonymous() => Factory.CreateClient();

    public async Task<JsonElement> LoginOkAsync(string username, string password)
    {
        using var client = Anonymous();
        var response = await client.PostAsJsonAsync("/api/v1/auth/login", new { username, password });
        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    public HttpClient WithToken(string accessToken)
    {
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client;
    }

    public async Task<HttpClient> AdminClientAsync()
    {
        var login = await LoginOkAsync(AdminUsername, AdminPassword);
        return WithToken(login.GetProperty("accessToken").GetString()!);
    }

    /// <summary>Creates a user through the API and returns its credentials.</summary>
    public async Task<TestUser> CreateUserAsync(string role = "Operator")
    {
        var username = "u" + Guid.NewGuid().ToString("N")[..12];
        var password = "Passphrase-" + Guid.NewGuid().ToString("N");

        using var admin = await AdminClientAsync();
        var response = await admin.PostAsJsonAsync("/api/v1/users", new { username, password, role });
        Assert.Equal(System.Net.HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return new TestUser(body.GetProperty("id").GetGuid(), username, password);
    }

    public async Task<HttpClient> ClientForAsync(TestUser user)
    {
        var login = await LoginOkAsync(user.Username, user.Password);
        return WithToken(login.GetProperty("accessToken").GetString()!);
    }

    /// <summary>Creates an enrollment token as the administrator and returns the raw token.</summary>
    public async Task<string> CreateEnrollmentTokenAsync(string? label = "test", int? expiresInHours = null)
    {
        using var admin = await AdminClientAsync();
        var response = await admin.PostAsJsonAsync("/api/v1/agents/enrollment-tokens", new { label, expiresInHours });
        Assert.Equal(System.Net.HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!;
    }

    /// <summary>Enrolls a new agent through the real protocol.</summary>
    public async Task<TestAgent> EnrollAgentAsync(string[] ranges, string[]? capabilities = null, string? name = null)
    {
        var token = await CreateEnrollmentTokenAsync();
        var agentName = name ?? "agent-" + Guid.NewGuid().ToString("N")[..8];

        using var client = Anonymous();
        var response = await client.PostAsJsonAsync("/api/v1/agent/enroll", new
        {
            enrollmentToken = token,
            agentName,
            version = "1.0.0-test",
            operatingSystem = "TestOS",
            capabilities = capabilities ?? ["Icmp"],
            reportedRanges = ranges
        });
        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return new TestAgent(body.GetProperty("agentId").GetGuid(), agentName, body.GetProperty("agentSecret").GetString()!);
    }

    public HttpClient ClientFor(TestAgent agent) => ClientWithAgentHeader(agent.Id, agent.Secret);

    public HttpClient ClientWithAgentHeader(Guid id, string secret)
    {
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Agent", $"{id}:{secret}");
        return client;
    }

    public async Task<JsonElement> AuditAsync(string query)
    {
        using var admin = await AdminClientAsync();
        var response = await admin.GetAsync("/api/v1/audit?" + query);
        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }
}

public sealed record TestUser(Guid Id, string Username, string Password);

public sealed record TestAgent(Guid Id, string Name, string Secret);

[CollectionDefinition(Name)]
public sealed class ApiCollection : ICollectionFixture<ApiFixture>
{
    public const string Name = "api";
}
