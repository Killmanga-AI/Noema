using Noema.Api.Common;
using Noema.Api.Security;

namespace Noema.Api.Features.Agents;

internal static class AgentAdminEndpoints
{
    public static IEndpointRouteBuilder MapAgentAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/agents").WithTags("Agents");

        group.MapGet("/", async (AgentAdminService agents, CancellationToken ct) =>
                Results.Ok(await agents.ListAgentsAsync(ct)))
            .RequireAuthorization(Policies.Operator);

        group.MapPost("/{id:guid}/revoke", async (Guid id, System.Security.Claims.ClaimsPrincipal principal, AgentAdminService agents, CancellationToken ct) =>
            {
                var actor = principal.GetCurrentUser();
                if (actor is null)
                {
                    return Results.Unauthorized();
                }

                var result = await agents.RevokeAsync(actor, id, ct);
                return result.ToHttp(value => Results.Ok(value));
            })
            .RequireAuthorization(Policies.Admin);

        var tokens = group.MapGroup("/enrollment-tokens").RequireAuthorization(Policies.Admin);

        tokens.MapGet("/", async (AgentAdminService agents, CancellationToken ct) =>
            Results.Ok(await agents.ListTokensAsync(ct)));

        tokens.MapPost("/", async (CreateEnrollmentTokenRequest request, System.Security.Claims.ClaimsPrincipal principal, AgentAdminService agents, CancellationToken ct) =>
        {
            var actor = principal.GetCurrentUser();
            if (actor is null)
            {
                return Results.Unauthorized();
            }

            var result = await agents.CreateTokenAsync(actor, request, ct);
            return result.ToHttp(value => Results.Created($"/api/v1/agents/enrollment-tokens/{value.Id}", value));
        });

        tokens.MapDelete("/{id:guid}", async (Guid id, System.Security.Claims.ClaimsPrincipal principal, AgentAdminService agents, CancellationToken ct) =>
        {
            var actor = principal.GetCurrentUser();
            if (actor is null)
            {
                return Results.Unauthorized();
            }

            var result = await agents.DeleteTokenAsync(actor, id, ct);
            return result.ToHttp(_ => Results.NoContent());
        });

        return app;
    }
}
