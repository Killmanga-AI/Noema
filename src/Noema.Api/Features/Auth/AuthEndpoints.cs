using Noema.Api.Common;
using Noema.Api.Security;

namespace Noema.Api.Features.Auth;

internal static class AuthEndpoints
{
    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/auth").WithTags("Auth");

        group.MapPost("/login", async (LoginRequest request, AuthService auth, CancellationToken ct) =>
            {
                var result = await auth.LoginAsync(request, ct);
                return result.ToHttp(value => Results.Ok(value));
            })
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitPolicies.Auth);

        group.MapPost("/refresh", async (RefreshRequest request, AuthService auth, CancellationToken ct) =>
            {
                var result = await auth.RefreshAsync(request, ct);
                return result.ToHttp(value => Results.Ok(value));
            })
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitPolicies.Auth);

        group.MapPost("/logout", async (LogoutRequest request, System.Security.Claims.ClaimsPrincipal principal, AuthService auth, CancellationToken ct) =>
            {
                var current = principal.GetCurrentUser();
                if (current is null)
                {
                    return Results.Unauthorized();
                }

                var result = await auth.LogoutAsync(current, request, ct);
                return result.ToHttp(_ => Results.NoContent());
            })
            .RequireAuthorization();

        group.MapPost("/change-password", async (ChangePasswordRequest request, System.Security.Claims.ClaimsPrincipal principal, AuthService auth, CancellationToken ct) =>
            {
                var current = principal.GetCurrentUser();
                if (current is null)
                {
                    return Results.Unauthorized();
                }

                var result = await auth.ChangePasswordAsync(current, request, ct);
                return result.ToHttp(_ => Results.NoContent());
            })
            .RequireAuthorization();

        group.MapGet("/me", async (System.Security.Claims.ClaimsPrincipal principal, AuthService auth, CancellationToken ct) =>
            {
                var current = principal.GetCurrentUser();
                if (current is null)
                {
                    return Results.Unauthorized();
                }

                var result = await auth.MeAsync(current, ct);
                return result.ToHttp(value => Results.Ok(value));
            })
            .RequireAuthorization();

        return app;
    }
}
