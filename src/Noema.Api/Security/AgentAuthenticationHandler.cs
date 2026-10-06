using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Noema.Contracts;
using Noema.Infrastructure.Persistence;
using Noema.Infrastructure.Security;

namespace Noema.Api.Security;

/// <summary>
/// Signs agents in from "Authorization: Agent {agentId}:{secret}". Revoked agents and wrong secrets get the
/// same answer, and an unknown agent id still does the same hashing work so timing reveals nothing.
/// Headers using any other scheme are ignored, which keeps this out of the way of user tokens.
/// </summary>
internal sealed class AgentAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    NoemaDbContext db) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    private static readonly string DecoyHash = SecretTokens.Hash("decoy-agent-secret");

    public const string AgentIdClaim = "agent_id";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(HeaderNames.Authorization, out var header))
        {
            return AuthenticateResult.NoResult();
        }

        var value = header.ToString();
        var prefix = AgentProtocol.AuthenticationScheme + " ";
        if (!value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        var credential = value[prefix.Length..].Trim();
        var separator = credential.IndexOf(':');
        if (separator <= 0 || credential.Length > 200 || !Guid.TryParse(credential[..separator], out var agentId))
        {
            return AuthenticateResult.Fail("Malformed agent credentials.");
        }

        var secret = credential[(separator + 1)..];
        var agent = await db.Agents.AsNoTracking().SingleOrDefaultAsync(a => a.Id == agentId, Context.RequestAborted);

        var secretMatches = SecretTokens.Matches(secret, agent?.CredentialHash ?? DecoyHash);
        if (agent is null || !secretMatches || agent.IsRevoked)
        {
            return AuthenticateResult.Fail("Invalid agent credentials.");
        }

        var identity = new ClaimsIdentity(
            new[]
            {
                new Claim(AgentIdClaim, agent.Id.ToString()),
                new Claim("name", agent.Name),
                new Claim("role", "Agent")
            },
            Scheme.Name,
            "name",
            "role");

        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
    }
}

public sealed record CurrentAgent(Guid Id, string Name);

public static class AgentPrincipalExtensions
{
    public static CurrentAgent? GetCurrentAgent(this ClaimsPrincipal principal)
    {
        var id = principal.FindFirst(AgentAuthenticationHandler.AgentIdClaim)?.Value;
        var name = principal.FindFirst("name")?.Value;

        return Guid.TryParse(id, out var agentId) && name is not null ? new CurrentAgent(agentId, name) : null;
    }
}
