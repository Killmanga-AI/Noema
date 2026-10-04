namespace Noema.Api.Features.Users;

public sealed record CreateUserRequest(string? Username, string? Password, string? Role);

public sealed record UpdateUserRequest(string? Role, bool? IsDisabled);

public sealed record ResetPasswordRequest(string? NewPassword);

public sealed record UserDetail(
    Guid Id,
    string Username,
    string Role,
    bool IsDisabled,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastLoginAt,
    DateTimeOffset? LockedUntil);
