using Noema.Api.Common;
using Noema.Api.Security;

namespace Noema.Api.Features.Audit;

internal static class AuditEndpoints
{
    public static IEndpointRouteBuilder MapAuditEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/v1/audit", async (
                string? action,
                string? actor,
                string? outcome,
                DateTimeOffset? before,
                int? limit,
                AuditQueryService audit,
                CancellationToken ct) =>
            {
                var result = await audit.QueryAsync(action, actor, outcome, before, limit, ct);
                return result.ToHttp(value => Results.Ok(value));
            })
            .WithTags("Audit")
            .RequireAuthorization(Policies.Admin);

        return app;
    }
}
