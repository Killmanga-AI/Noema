using Noema.Api.Common;
using Noema.Api.Security;
using Noema.Contracts;

namespace Noema.Api.Features.Agents;

internal static class AgentProtocolEndpoints
{
    public static IEndpointRouteBuilder MapAgentProtocolEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/agent").WithTags("Agent protocol");

        group.MapPost("/enroll", async (EnrollRequest body, AgentProtocolService agents, CancellationToken ct) =>
            {
                var result = await agents.EnrollAsync(body, ct);
                return result.ToHttp(value => Results.Ok(value));
            })
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitPolicies.Auth);

        var authed = group.MapGroup(string.Empty).RequireAuthorization(Policies.Agent);

        authed.MapPost("/claim", async (ClaimRequest body, System.Security.Claims.ClaimsPrincipal principal, AgentProtocolService agents, CancellationToken ct) =>
        {
            var current = principal.GetCurrentAgent();
            if (current is null)
            {
                return Results.Unauthorized();
            }

            var result = await agents.ClaimAsync(current, body, ct);
            return result.ToHttp(job => job is null ? Results.NoContent() : Results.Ok(job));
        });

        authed.MapPost("/scans/{scanId:guid}/progress", async (Guid scanId, ProgressRequest body, System.Security.Claims.ClaimsPrincipal principal, AgentProtocolService agents, CancellationToken ct) =>
        {
            var current = principal.GetCurrentAgent();
            if (current is null)
            {
                return Results.Unauthorized();
            }

            var result = await agents.ReportProgressAsync(current, scanId, body, ct);
            return result.ToHttp(value => Results.Ok(value));
        });

        authed.MapPost("/scans/{scanId:guid}/observations", async (Guid scanId, ObservationBatch body, System.Security.Claims.ClaimsPrincipal principal, AgentProtocolService agents, CancellationToken ct) =>
        {
            var current = principal.GetCurrentAgent();
            if (current is null)
            {
                return Results.Unauthorized();
            }

            var result = await agents.UploadObservationsAsync(current, scanId, body, ct);
            return result.ToHttp(value => Results.Ok(value));
        });

        authed.MapPost("/scans/{scanId:guid}/complete", async (Guid scanId, CompleteRequest body, System.Security.Claims.ClaimsPrincipal principal, AgentProtocolService agents, CancellationToken ct) =>
        {
            var current = principal.GetCurrentAgent();
            if (current is null)
            {
                return Results.Unauthorized();
            }

            var result = await agents.CompleteAsync(current, scanId, body, ct);
            return result.ToHttp(_ => Results.NoContent());
        });

        return app;
    }
}
