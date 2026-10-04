using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Noema.Api.Tests;

[Collection(ApiCollection.Name)]
[Trait("Category", "Docker")]
public sealed class UsersAndRolesApiTests(ApiFixture api)
{
    [Theory]
    [InlineData("GET", "/api/v1/users")]
    [InlineData("GET", "/api/v1/audit")]
    public async Task Operators_cannot_use_admin_only_endpoints(string method, string path)
    {
        var operatorUser = await api.CreateUserAsync("Operator");
        using var client = await api.ClientForAsync(operatorUser);

        var response = await client.SendAsync(new HttpRequestMessage(new HttpMethod(method), path));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Operators_cannot_create_users_change_users_or_manage_ranges()
    {
        var operatorUser = await api.CreateUserAsync("Operator");
        var target = await api.CreateUserAsync("Operator");
        using var client = await api.ClientForAsync(operatorUser);

        var create = await client.PostAsJsonAsync("/api/v1/users", new { username = "sneaky-user", password = "A-long-enough-passphrase", role = "Admin" });
        var update = await client.PatchAsJsonAsync($"/api/v1/users/{target.Id}", new { role = "Admin" });
        var reset = await client.PostAsJsonAsync($"/api/v1/users/{target.Id}/reset-password", new { newPassword = "A-long-enough-passphrase" });
        var addRange = await client.PostAsJsonAsync("/api/v1/authorized-ranges", new { cidr = "192.168.77.0/24" });
        var deleteRange = await client.DeleteAsync($"/api/v1/authorized-ranges/{Guid.NewGuid()}");

        foreach (var response in new[] { create, update, reset, addRange, deleteRange })
        {
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
    }

    [Fact]
    public async Task Operators_can_read_ranges_and_scans()
    {
        var operatorUser = await api.CreateUserAsync("Operator");
        using var client = await api.ClientForAsync(operatorUser);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/authorized-ranges")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/scans")).StatusCode);
    }

    [Fact]
    public async Task An_administrator_can_create_and_list_users()
    {
        var created = await api.CreateUserAsync("Operator");
        using var admin = await api.AdminClientAsync();

        var list = await admin.GetFromJsonAsync<JsonElement>("/api/v1/users");

        Assert.Contains(list.EnumerateArray(), u => u.GetProperty("username").GetString() == created.Username);
        Assert.DoesNotContain("passwordHash", list.GetRawText(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("pbkdf2", list.GetRawText(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Creating_a_user_rejects_bad_input_with_field_errors()
    {
        using var admin = await api.AdminClientAsync();

        var response = await admin.PostAsJsonAsync("/api/v1/users", new { username = "x", password = "short", role = "Superuser" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var errors = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("errors");
        Assert.True(errors.TryGetProperty("username", out _));
        Assert.True(errors.TryGetProperty("password", out _));
        Assert.True(errors.TryGetProperty("role", out _));
    }

    [Fact]
    public async Task A_password_containing_the_username_is_refused()
    {
        using var admin = await api.AdminClientAsync();

        var response = await admin.PostAsJsonAsync("/api/v1/users", new { username = "latif-test", password = "my-latif-test-password", role = "Operator" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Usernames_are_unique_regardless_of_case()
    {
        var existing = await api.CreateUserAsync();
        using var admin = await api.AdminClientAsync();

        var response = await admin.PostAsJsonAsync("/api/v1/users", new { username = existing.Username.ToUpperInvariant(), password = "Another-long-passphrase-1", role = "Operator" });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task The_last_active_administrator_cannot_be_disabled_or_demoted()
    {
        using var admin = await api.AdminClientAsync();
        var users = await admin.GetFromJsonAsync<JsonElement>("/api/v1/users");
        var admins = users.EnumerateArray().Where(u => u.GetProperty("role").GetString() == "Admin" && !u.GetProperty("isDisabled").GetBoolean()).ToList();

        // Make sure the bootstrap administrator is the only active one by disabling any extra administrators first.
        var bootstrapId = users.EnumerateArray().Single(u => u.GetProperty("username").GetString() == ApiFixture.AdminUsername).GetProperty("id").GetGuid();
        foreach (var extra in admins.Where(a => a.GetProperty("id").GetGuid() != bootstrapId))
        {
            var disabled = await admin.PatchAsJsonAsync($"/api/v1/users/{extra.GetProperty("id").GetGuid()}", new { isDisabled = true });
            Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);
        }

        var disable = await admin.PatchAsJsonAsync($"/api/v1/users/{bootstrapId}", new { isDisabled = true });
        var demote = await admin.PatchAsJsonAsync($"/api/v1/users/{bootstrapId}", new { role = "Operator" });

        Assert.Equal(HttpStatusCode.Conflict, disable.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, demote.StatusCode);
    }

    [Fact]
    public async Task An_administrator_can_reset_a_password_and_sessions_are_ended()
    {
        var user = await api.CreateUserAsync();
        var login = await api.LoginOkAsync(user.Username, user.Password);
        using var admin = await api.AdminClientAsync();
        var newPassword = "Reset-passphrase-" + Guid.NewGuid().ToString("N");

        var reset = await admin.PostAsJsonAsync($"/api/v1/users/{user.Id}/reset-password", new { newPassword });
        Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);

        using var anonymous = api.Anonymous();
        var oldRefresh = await anonymous.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = login.GetProperty("refreshToken").GetString() });
        Assert.Equal(HttpStatusCode.Unauthorized, oldRefresh.StatusCode);
        await api.LoginOkAsync(user.Username, newPassword);
    }

    [Fact]
    public async Task Updating_needs_a_change_and_a_real_user()
    {
        var user = await api.CreateUserAsync();
        using var admin = await api.AdminClientAsync();

        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PatchAsJsonAsync($"/api/v1/users/{user.Id}", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PatchAsJsonAsync($"/api/v1/users/{user.Id}", new { role = "Root" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PatchAsJsonAsync($"/api/v1/users/{Guid.NewGuid()}", new { role = "Admin" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PostAsync($"/api/v1/users/{Guid.NewGuid()}/unlock", null)).StatusCode);
    }

    [Fact]
    public async Task User_changes_are_audited_with_the_actor()
    {
        var user = await api.CreateUserAsync();

        var audit = await api.AuditAsync($"action=user.created&actor={ApiFixture.AdminUsername}&limit=200");

        Assert.Contains(audit.EnumerateArray(), e => e.GetProperty("targetId").GetString() == user.Id.ToString());
    }
}
