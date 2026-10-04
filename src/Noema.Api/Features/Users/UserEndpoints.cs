using Noema.Api.Common;
using Noema.Api.Security;

namespace Noema.Api.Features.Users;

internal static class UserEndpoints
{
    public static IEndpointRouteBuilder MapUserEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/users").WithTags("Users").RequireAuthorization(Policies.Admin);

        group.MapGet("/", async (UserAdminService users, CancellationToken ct) =>
            Results.Ok(await users.ListAsync(ct)));

        group.MapPost("/", async (CreateUserRequest request, System.Security.Claims.ClaimsPrincipal principal, UserAdminService users, CancellationToken ct) =>
        {
            var actor = principal.GetCurrentUser();
            if (actor is null)
            {
                return Results.Unauthorized();
            }

            var result = await users.CreateAsync(actor, request, ct);
            return result.ToHttp(value => Results.Created($"/api/v1/users/{value.Id}", value));
        });

        group.MapPatch("/{id:guid}", async (Guid id, UpdateUserRequest request, System.Security.Claims.ClaimsPrincipal principal, UserAdminService users, CancellationToken ct) =>
        {
            var actor = principal.GetCurrentUser();
            if (actor is null)
            {
                return Results.Unauthorized();
            }

            var result = await users.UpdateAsync(actor, id, request, ct);
            return result.ToHttp(value => Results.Ok(value));
        });

        group.MapPost("/{id:guid}/reset-password", async (Guid id, ResetPasswordRequest request, System.Security.Claims.ClaimsPrincipal principal, UserAdminService users, CancellationToken ct) =>
        {
            var actor = principal.GetCurrentUser();
            if (actor is null)
            {
                return Results.Unauthorized();
            }

            var result = await users.ResetPasswordAsync(actor, id, request, ct);
            return result.ToHttp(_ => Results.NoContent());
        });

        group.MapPost("/{id:guid}/unlock", async (Guid id, System.Security.Claims.ClaimsPrincipal principal, UserAdminService users, CancellationToken ct) =>
        {
            var actor = principal.GetCurrentUser();
            if (actor is null)
            {
                return Results.Unauthorized();
            }

            var result = await users.UnlockAsync(actor, id, ct);
            return result.ToHttp(value => Results.Ok(value));
        });

        return app;
    }
}
