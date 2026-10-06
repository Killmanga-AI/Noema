using Noema.Api.Common;
using Noema.Api.Security;

namespace Noema.Api.Features.Scans;

internal static class ScanEndpoints
{
    public static IEndpointRouteBuilder MapScanEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/scans").WithTags("Scans").RequireAuthorization(Policies.Operator);

        group.MapPost("/", async (RequestScanRequest request, System.Security.Claims.ClaimsPrincipal principal, ScanRequestService scans, CancellationToken ct) =>
        {
            var actor = principal.GetCurrentUser();
            if (actor is null)
            {
                return Results.Unauthorized();
            }

            var result = await scans.RequestAsync(actor, request, ct);
            return result.ToHttp(value => Results.Created($"/api/v1/scans/{value.Id}", value));
        });

        group.MapPost("/{id:guid}/cancel", async (Guid id, System.Security.Claims.ClaimsPrincipal principal, ScanRequestService scans, CancellationToken ct) =>
        {
            var actor = principal.GetCurrentUser();
            if (actor is null)
            {
                return Results.Unauthorized();
            }

            var result = await scans.CancelAsync(actor, id, ct);
            return result.ToHttp(value => Results.Ok(value));
        });

        group.MapGet("/{id:guid}/observations", async (Guid id, Guid? after, int? limit, ScanRequestService scans, CancellationToken ct) =>
        {
            var result = await scans.ObservationsAsync(id, after, limit, ct);
            return result.ToHttp(value => Results.Ok(value));
        });

        group.MapGet("/{id:guid}", async (Guid id, ScanRequestService scans, CancellationToken ct) =>
        {
            var result = await scans.GetAsync(id, ct);
            return result.ToHttp(value => Results.Ok(value));
        });

        group.MapGet("/", async (string? status, int? limit, ScanRequestService scans, CancellationToken ct) =>
        {
            var result = await scans.ListAsync(status, limit, ct);
            return result.ToHttp(value => Results.Ok(value));
        });

        return app;
    }
}
