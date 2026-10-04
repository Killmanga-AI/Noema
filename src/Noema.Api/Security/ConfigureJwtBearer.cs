using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Noema.Infrastructure.Persistence;

namespace Noema.Api.Security;

/// <summary>
/// Reads the signing settings when the first request arrives, not at startup, so configuration overrides apply.
/// Also checks the account on every request, so disabling a user or changing a role takes effect at once
/// instead of waiting for the access token to expire.
/// </summary>
internal sealed class ConfigureJwtBearer(IOptions<JwtOptions> jwtOptions) : IConfigureNamedOptions<JwtBearerOptions>
{
    public void Configure(JwtBearerOptions options) => Configure(JwtBearerDefaults.AuthenticationScheme, options);

    public void Configure(string? name, JwtBearerOptions options)
    {
        if (name != JwtBearerDefaults.AuthenticationScheme)
        {
            return;
        }

        var settings = jwtOptions.Value;

        options.MapInboundClaims = false;
        options.SaveToken = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = settings.Issuer,
            ValidateAudience = true,
            ValidAudience = settings.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String(settings.SigningKey)),
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = "name",
            RoleClaimType = "role"
        };

        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = EnsureAccountStillAllowedAsync
        };
    }

    private static async Task EnsureAccountStillAllowedAsync(TokenValidatedContext context)
    {
        var subject = context.Principal?.FindFirst("sub")?.Value;
        var role = context.Principal?.FindFirst("role")?.Value;

        if (!Guid.TryParse(subject, out var userId))
        {
            context.Fail("The token has no valid subject.");
            return;
        }

        var db = context.HttpContext.RequestServices.GetRequiredService<NoemaDbContext>();
        var current = await db.Users
            .AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => new { u.IsDisabled, u.Role })
            .SingleOrDefaultAsync(context.HttpContext.RequestAborted);

        if (current is null || current.IsDisabled || current.Role.ToString() != role)
        {
            context.Fail("The account is disabled, removed, or has a different role now.");
        }
    }
}
