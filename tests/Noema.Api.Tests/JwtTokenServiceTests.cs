using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Noema.Api.Security;
using Noema.Domain;

namespace Noema.Api.Tests;

public sealed class JwtTokenServiceTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    private static JwtTokenService NewService(string key = TestSecrets.SigningKey) =>
        new(Options.Create(new JwtOptions { SigningKey = key }));

    private static User NewUser(UserRole role) => User.Create("latif", "hash", role, Now);

    private static TokenValidationParameters ParametersFor(string key) => new()
    {
        ValidIssuer = "noema",
        ValidAudience = "noema-api",
        IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String(key)),
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256]
    };

    [Fact]
    public async Task Access_tokens_carry_the_user_id_name_and_role_and_expire_when_configured()
    {
        var user = NewUser(UserRole.Admin);

        var issued = NewService().IssueAccessToken(user, Now);
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(issued.Token, ParametersFor(TestSecrets.SigningKey));

        Assert.True(result.IsValid);
        Assert.Equal(user.Id.ToString(), result.Claims["sub"]);
        Assert.Equal("latif", result.Claims["name"]);
        Assert.Equal("Admin", result.Claims["role"]);
        Assert.Equal(Now.AddMinutes(15).ToUnixTimeSeconds(), issued.ExpiresAt.ToUnixTimeSeconds());
    }

    [Fact]
    public async Task A_token_signed_with_another_key_is_rejected()
    {
        var issued = NewService(TestSecrets.OtherSigningKey).IssueAccessToken(NewUser(UserRole.Operator), Now);

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(issued.Token, ParametersFor(TestSecrets.SigningKey));

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task An_expired_token_is_rejected()
    {
        var issued = NewService().IssueAccessToken(NewUser(UserRole.Operator), Now.AddHours(-2));

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(issued.Token, ParametersFor(TestSecrets.SigningKey));

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Each_access_token_is_unique()
    {
        var service = NewService();
        var user = NewUser(UserRole.Operator);

        Assert.NotEqual(service.IssueAccessToken(user, Now).Token, service.IssueAccessToken(user, Now).Token);
    }

    [Fact]
    public void Refresh_tokens_are_long_random_and_url_safe()
    {
        var service = NewService();

        var first = service.NewRefreshToken();
        var second = service.NewRefreshToken();

        Assert.NotEqual(first, second);
        Assert.True(first.Length >= 43);
        Assert.True(first.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'));
    }

    [Fact]
    public void Refresh_token_hashes_are_stable_and_do_not_reveal_the_token()
    {
        var service = NewService();
        var token = service.NewRefreshToken();

        var hash = service.HashRefreshToken(token);

        Assert.Equal(hash, service.HashRefreshToken(token));
        Assert.NotEqual(hash, service.HashRefreshToken(token + "x"));
        Assert.DoesNotContain(token, hash);
        Assert.True(hash.Length <= 64);
    }

    [Fact]
    public void The_refresh_lifetime_comes_from_configuration()
    {
        var service = new JwtTokenService(Options.Create(new JwtOptions { SigningKey = TestSecrets.SigningKey, RefreshTokenDays = 3 }));

        Assert.Equal(TimeSpan.FromDays(3), service.RefreshTokenLifetime);
    }
}
