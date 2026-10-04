using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Noema.Domain;

namespace Noema.Api.Security;

public sealed record AccessToken(string Token, DateTimeOffset ExpiresAt);

public interface ITokenService
{
    TimeSpan RefreshTokenLifetime { get; }

    AccessToken IssueAccessToken(User user, DateTimeOffset now);

    /// <summary>A new random refresh token. Only its hash is ever stored.</summary>
    string NewRefreshToken();

    string HashRefreshToken(string token);
}

internal sealed class JwtTokenService(IOptions<JwtOptions> options) : ITokenService
{
    private readonly JsonWebTokenHandler handler = new();

    public TimeSpan RefreshTokenLifetime => TimeSpan.FromDays(options.Value.RefreshTokenDays);

    public AccessToken IssueAccessToken(User user, DateTimeOffset now)
    {
        var settings = options.Value;
        var expires = now.AddMinutes(settings.AccessTokenMinutes);
        var key = new SymmetricSecurityKey(Convert.FromBase64String(settings.SigningKey));

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = settings.Issuer,
            Audience = settings.Audience,
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("sub", user.Id.ToString()),
                new Claim("name", user.Username),
                new Claim("role", user.Role.ToString()),
                new Claim("jti", Guid.NewGuid().ToString("N"))
            }),
            NotBefore = now.UtcDateTime,
            IssuedAt = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        };

        return new AccessToken(handler.CreateToken(descriptor), expires);
    }

    public string NewRefreshToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    public string HashRefreshToken(string token) =>
        Convert.ToBase64String(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)));
}
