using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Noema.Api.Tests;

[Collection(ApiCollection.Name)]
[Trait("Category", "Docker")]
public sealed class AuthApiTests(ApiFixture api)
{
    private static async Task<JsonElement> JsonAsync(HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<JsonElement>();

    [Fact]
    public async Task The_bootstrap_administrator_can_sign_in_and_is_recorded_in_the_audit_trail()
    {
        var login = await api.LoginOkAsync(ApiFixture.AdminUsername, ApiFixture.AdminPassword);

        Assert.Equal("Admin", login.GetProperty("user").GetProperty("role").GetString());

        var audit = await api.AuditAsync("action=user.bootstrap_created");
        Assert.True(audit.GetArrayLength() >= 1);
    }

    [Fact]
    public async Task Signing_in_returns_working_tokens_and_the_user()
    {
        var user = await api.CreateUserAsync();

        var login = await api.LoginOkAsync(user.Username, user.Password);
        using var client = api.WithToken(login.GetProperty("accessToken").GetString()!);
        var me = await client.GetAsync("/api/v1/auth/me");

        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var body = await JsonAsync(me);
        Assert.Equal(user.Username, body.GetProperty("username").GetString());
        Assert.Equal("Operator", body.GetProperty("role").GetString());
        Assert.False(string.IsNullOrEmpty(login.GetProperty("refreshToken").GetString()));
    }

    [Fact]
    public async Task Sign_in_ignores_username_case_and_padding()
    {
        var user = await api.CreateUserAsync();

        var login = await api.LoginOkAsync("  " + user.Username.ToUpperInvariant() + " ", user.Password);

        Assert.Equal(user.Username, login.GetProperty("user").GetProperty("username").GetString());
    }

    [Fact]
    public async Task A_wrong_password_and_an_unknown_user_get_the_same_answer()
    {
        var user = await api.CreateUserAsync();
        using var client = api.Anonymous();

        var wrongPassword = await client.PostAsJsonAsync("/api/v1/auth/login", new { username = user.Username, password = "not-the-password-1" });
        var unknownUser = await client.PostAsJsonAsync("/api/v1/auth/login", new { username = "nobody-" + Guid.NewGuid().ToString("N")[..8], password = "not-the-password-1" });

        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknownUser.StatusCode);
        var wrongTitle = (await JsonAsync(wrongPassword)).GetProperty("title").GetString();
        var unknownTitle = (await JsonAsync(unknownUser)).GetProperty("title").GetString();
        Assert.Equal(wrongTitle, unknownTitle);
    }

    [Theory]
    [InlineData(null, "something-long-enough")]
    [InlineData("someone", null)]
    [InlineData("", "")]
    public async Task Sign_in_requires_a_username_and_password(string? username, string? password)
    {
        using var client = api.Anonymous();

        var response = await client.PostAsJsonAsync("/api/v1/auth/login", new { username, password });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task An_oversized_password_is_rejected_before_any_hashing()
    {
        using var client = api.Anonymous();

        var response = await client.PostAsJsonAsync("/api/v1/auth/login", new { username = "someone", password = new string('a', 1000) });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Five_wrong_passwords_lock_the_account_even_against_the_right_password()
    {
        var user = await api.CreateUserAsync();
        using var client = api.Anonymous();

        for (var i = 0; i < 5; i++)
        {
            var failed = await client.PostAsJsonAsync("/api/v1/auth/login", new { username = user.Username, password = "wrong-password-" + i });
            Assert.Equal(HttpStatusCode.Unauthorized, failed.StatusCode);
        }

        var withCorrect = await client.PostAsJsonAsync("/api/v1/auth/login", new { username = user.Username, password = user.Password });
        Assert.Equal(HttpStatusCode.Unauthorized, withCorrect.StatusCode);

        var audit = await api.AuditAsync($"action=auth.account.locked&actor={user.Username}");
        Assert.Equal(1, audit.GetArrayLength());
    }

    [Fact]
    public async Task An_administrator_can_unlock_a_locked_account()
    {
        var user = await api.CreateUserAsync();
        using var client = api.Anonymous();
        for (var i = 0; i < 5; i++)
        {
            await client.PostAsJsonAsync("/api/v1/auth/login", new { username = user.Username, password = "wrong-password-" + i });
        }

        using var admin = await api.AdminClientAsync();
        var unlock = await admin.PostAsync($"/api/v1/users/{user.Id}/unlock", null);

        Assert.Equal(HttpStatusCode.OK, unlock.StatusCode);
        await api.LoginOkAsync(user.Username, user.Password);
    }

    [Fact]
    public async Task A_disabled_account_cannot_sign_in_and_its_existing_token_stops_working_at_once()
    {
        var user = await api.CreateUserAsync();
        using var userClient = await api.ClientForAsync(user);
        Assert.Equal(HttpStatusCode.OK, (await userClient.GetAsync("/api/v1/auth/me")).StatusCode);

        using var admin = await api.AdminClientAsync();
        var disable = await admin.PatchAsJsonAsync($"/api/v1/users/{user.Id}", new { isDisabled = true });
        Assert.Equal(HttpStatusCode.OK, disable.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await userClient.GetAsync("/api/v1/auth/me")).StatusCode);

        using var anonymous = api.Anonymous();
        var login = await anonymous.PostAsJsonAsync("/api/v1/auth/login", new { username = user.Username, password = user.Password });
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
    }

    [Fact]
    public async Task A_role_change_takes_effect_on_the_next_request()
    {
        var user = await api.CreateUserAsync("Admin");
        using var userClient = await api.ClientForAsync(user);
        Assert.Equal(HttpStatusCode.OK, (await userClient.GetAsync("/api/v1/users")).StatusCode);

        using var admin = await api.AdminClientAsync();
        var demote = await admin.PatchAsJsonAsync($"/api/v1/users/{user.Id}", new { role = "Operator" });
        Assert.Equal(HttpStatusCode.OK, demote.StatusCode);

        // The old token still says Admin, but the account is checked on every request.
        Assert.Equal(HttpStatusCode.Unauthorized, (await userClient.GetAsync("/api/v1/users")).StatusCode);
    }

    [Fact]
    public async Task Refreshing_gives_new_tokens_and_the_old_refresh_token_stops_working()
    {
        var user = await api.CreateUserAsync();
        var login = await api.LoginOkAsync(user.Username, user.Password);
        var first = login.GetProperty("refreshToken").GetString();
        using var client = api.Anonymous();

        var refreshed = await client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = first });
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        var second = (await JsonAsync(refreshed)).GetProperty("refreshToken").GetString();
        Assert.NotEqual(first, second);

        var replay = await client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = first });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task Replaying_a_used_refresh_token_ends_every_session_for_that_user()
    {
        var user = await api.CreateUserAsync();
        var login = await api.LoginOkAsync(user.Username, user.Password);
        var stolen = login.GetProperty("refreshToken").GetString();
        using var client = api.Anonymous();

        var legitimate = await client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = stolen });
        var current = (await JsonAsync(legitimate)).GetProperty("refreshToken").GetString();

        var attacker = await client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = stolen });
        Assert.Equal(HttpStatusCode.Unauthorized, attacker.StatusCode);

        var victimNext = await client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = current });
        Assert.Equal(HttpStatusCode.Unauthorized, victimNext.StatusCode);

        var audit = await api.AuditAsync($"action=auth.refresh.reuse_detected&actor={user.Username}");
        Assert.True(audit.GetArrayLength() >= 1);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Refresh_requires_a_token(string? token)
    {
        using var client = api.Anonymous();

        var response = await client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = token });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task An_unknown_refresh_token_is_refused()
    {
        using var client = api.Anonymous();

        var response = await client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = "not-a-real-token" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Signing_out_revokes_the_refresh_token()
    {
        var user = await api.CreateUserAsync();
        var login = await api.LoginOkAsync(user.Username, user.Password);
        var refresh = login.GetProperty("refreshToken").GetString();
        using var authed = api.WithToken(login.GetProperty("accessToken").GetString()!);

        var logout = await authed.PostAsJsonAsync("/api/v1/auth/logout", new { refreshToken = refresh });
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        using var anonymous = api.Anonymous();
        var after = await anonymous.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = refresh });
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    [Fact]
    public async Task Signing_out_with_someone_elses_token_changes_nothing()
    {
        var owner = await api.CreateUserAsync();
        var other = await api.CreateUserAsync();
        var ownerLogin = await api.LoginOkAsync(owner.Username, owner.Password);
        using var otherClient = await api.ClientForAsync(other);

        var logout = await otherClient.PostAsJsonAsync("/api/v1/auth/logout", new { refreshToken = ownerLogin.GetProperty("refreshToken").GetString() });
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        using var anonymous = api.Anonymous();
        var stillWorks = await anonymous.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = ownerLogin.GetProperty("refreshToken").GetString() });
        Assert.Equal(HttpStatusCode.OK, stillWorks.StatusCode);
    }

    [Fact]
    public async Task Changing_the_password_ends_old_sessions_and_the_old_password_stops_working()
    {
        var user = await api.CreateUserAsync();
        var login = await api.LoginOkAsync(user.Username, user.Password);
        using var client = api.WithToken(login.GetProperty("accessToken").GetString()!);
        var newPassword = "Brand-new-passphrase-" + Guid.NewGuid().ToString("N");

        var change = await client.PostAsJsonAsync("/api/v1/auth/change-password", new { currentPassword = user.Password, newPassword });
        Assert.Equal(HttpStatusCode.NoContent, change.StatusCode);

        using var anonymous = api.Anonymous();
        var oldRefresh = await anonymous.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = login.GetProperty("refreshToken").GetString() });
        Assert.Equal(HttpStatusCode.Unauthorized, oldRefresh.StatusCode);

        var oldPassword = await anonymous.PostAsJsonAsync("/api/v1/auth/login", new { username = user.Username, password = user.Password });
        Assert.Equal(HttpStatusCode.Unauthorized, oldPassword.StatusCode);

        await api.LoginOkAsync(user.Username, newPassword);
    }

    [Fact]
    public async Task Changing_the_password_needs_the_right_current_password_and_a_good_new_one()
    {
        var user = await api.CreateUserAsync();
        using var client = await api.ClientForAsync(user);

        var wrongCurrent = await client.PostAsJsonAsync("/api/v1/auth/change-password", new { currentPassword = "definitely-wrong-1", newPassword = "A-perfectly-fine-new-passphrase" });
        Assert.Equal(HttpStatusCode.BadRequest, wrongCurrent.StatusCode);

        var weak = await client.PostAsJsonAsync("/api/v1/auth/change-password", new { currentPassword = user.Password, newPassword = "short" });
        Assert.Equal(HttpStatusCode.BadRequest, weak.StatusCode);

        var same = await client.PostAsJsonAsync("/api/v1/auth/change-password", new { currentPassword = user.Password, newPassword = user.Password });
        Assert.Equal(HttpStatusCode.BadRequest, same.StatusCode);
    }

    [Fact]
    public async Task Passwords_never_appear_in_the_audit_trail()
    {
        var user = await api.CreateUserAsync();
        using var anonymous = api.Anonymous();
        await anonymous.PostAsJsonAsync("/api/v1/auth/login", new { username = user.Username, password = "an-incorrect-passphrase-xyz" });

        var audit = await api.AuditAsync($"actor={user.Username}&limit=200");

        Assert.DoesNotContain("an-incorrect-passphrase-xyz", audit.GetRawText());
        Assert.DoesNotContain(user.Password, audit.GetRawText());
    }
}
