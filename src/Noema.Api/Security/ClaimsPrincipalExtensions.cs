using System.Security.Claims;

namespace Noema.Api.Security;

public sealed record CurrentUser(Guid Id, string Username, string Role);

public static class ClaimsPrincipalExtensions
{
    public static CurrentUser? GetCurrentUser(this ClaimsPrincipal principal)
    {
        var id = principal.FindFirst("sub")?.Value;
        var name = principal.FindFirst("name")?.Value;
        var role = principal.FindFirst("role")?.Value;

        return Guid.TryParse(id, out var userId) && name is not null && role is not null
            ? new CurrentUser(userId, name, role)
            : null;
    }
}
