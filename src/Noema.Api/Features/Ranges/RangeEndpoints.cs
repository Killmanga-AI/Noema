using Noema.Api.Common;
using Noema.Api.Security;

namespace Noema.Api.Features.Ranges;

internal static class RangeEndpoints
{
    public static IEndpointRouteBuilder MapRangeEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/authorized-ranges").WithTags("Authorized ranges");

        group.MapGet("/", async (RangeService ranges, CancellationToken ct) =>
                Results.Ok(await ranges.ListAsync(ct)))
            .RequireAuthorization(Policies.Operator);

        group.MapPost("/", async (CreateRangeRequest request, System.Security.Claims.ClaimsPrincipal principal, RangeService ranges, CancellationToken ct) =>
            {
                var actor = principal.GetCurrentUser();
                if (actor is null)
                {
                    return Results.Unauthorized();
                }

                var result = await ranges.CreateAsync(actor, request, ct);
                return result.ToHttp(value => Results.Created($"/api/v1/authorized-ranges/{value.Id}", value));
            })
            .RequireAuthorization(Policies.Admin);

        group.MapDelete("/{id:guid}", async (Guid id, System.Security.Claims.ClaimsPrincipal principal, RangeService ranges, CancellationToken ct) =>
            {
                var actor = principal.GetCurrentUser();
                if (actor is null)
                {
                    return Results.Unauthorized();
                }

                var result = await ranges.DeleteAsync(actor, id, ct);
                return result.ToHttp(_ => Results.NoContent());
            })
            .RequireAuthorization(Policies.Admin);

        return app;
    }
}
