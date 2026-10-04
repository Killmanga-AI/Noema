using System.Net;
using System.Net.Http.Json;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Noema.Api.Tests;

/// <summary>These run without Docker. Bad tokens are refused before the database is ever touched.</summary>
public sealed class TokenSecurityTests(UnreachableDatabaseFactory factory) : IClassFixture<UnreachableDatabaseFactory>
{
    private static string MakeToken(
        string key = TestSecrets.SigningKey,
        string issuer = "noema",
        string audience = "noema-api",
        DateTime? expires = null,
        string algorithm = SecurityAlgorithms.HmacSha256)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("sub", Guid.NewGuid().ToString()),
                new Claim("name", "intruder"),
                new Claim("role", "Admin")
            }),
            NotBefore = DateTime.UtcNow.AddMinutes(-30),
            Expires = expires ?? DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Convert.FromBase64String(key)), algorithm)
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private async Task<HttpStatusCode> StatusWithTokenAsync(string? token, string path = "/api/v1/users")
    {
        using var client = factory.CreateClient();
        if (token is not null)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return (await client.GetAsync(path)).StatusCode;
    }

    [Theory]
    [InlineData("/api/v1/users")]
    [InlineData("/api/v1/authorized-ranges")]
    [InlineData("/api/v1/scans")]
    [InlineData("/api/v1/audit")]
    [InlineData("/api/v1/auth/me")]
    public async Task Protected_endpoints_refuse_requests_without_a_token(string path)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, await StatusWithTokenAsync(null, path));
    }

    [Fact]
    public async Task A_token_signed_with_the_wrong_key_is_refused()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, await StatusWithTokenAsync(MakeToken(key: TestSecrets.OtherSigningKey)));
    }

    [Fact]
    public async Task An_expired_token_is_refused()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, await StatusWithTokenAsync(MakeToken(expires: DateTime.UtcNow.AddMinutes(-5))));
    }

    [Fact]
    public async Task A_token_for_another_issuer_or_audience_is_refused()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, await StatusWithTokenAsync(MakeToken(issuer: "someone-else")));
        Assert.Equal(HttpStatusCode.Unauthorized, await StatusWithTokenAsync(MakeToken(audience: "another-api")));
    }

    [Fact]
    public async Task A_token_using_a_different_algorithm_is_refused()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, await StatusWithTokenAsync(MakeToken(algorithm: SecurityAlgorithms.HmacSha512)));
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("a.b.c")]
    [InlineData("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwicm9sZSI6IkFkbWluIn0.")]
    public async Task Malformed_and_unsigned_tokens_are_refused(string token)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, await StatusWithTokenAsync(token));
    }

    [Fact]
    public async Task Health_endpoints_stay_open_to_probes()
    {
        Assert.Equal(HttpStatusCode.OK, await StatusWithTokenAsync(null, "/health/live"));
    }
}

public sealed class RateLimitTests(TightRateLimitFactory factory) : IClassFixture<TightRateLimitFactory>
{
    [Fact]
    public async Task Repeated_sign_in_attempts_from_one_address_are_limited()
    {
        using var client = factory.CreateClient();
        var statuses = new List<HttpStatusCode>();

        for (var i = 0; i < 5; i++)
        {
            var response = await client.PostAsJsonAsync("/api/v1/auth/login", new { username = "someone", password = "wrong-password-here" });
            statuses.Add(response.StatusCode);
        }

        Assert.DoesNotContain(HttpStatusCode.TooManyRequests, statuses.Take(3));
        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[3]);
        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[4]);
    }

    [Fact]
    public async Task The_limit_does_not_apply_to_other_endpoints()
    {
        using var client = factory.CreateClient();

        for (var i = 0; i < 6; i++)
        {
            var response = await client.GetAsync("/health/live");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }
}
