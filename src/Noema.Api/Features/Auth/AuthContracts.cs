namespace Noema.Api.Features.Auth;

public sealed record LoginRequest(string? Username, string? Password);

public sealed record RefreshRequest(string? RefreshToken);

public sealed record LogoutRequest(string? RefreshToken);

public sealed record ChangePasswordRequest(string? CurrentPassword, string? NewPassword);

public sealed record UserSummary(Guid Id, string Username, string Role, bool IsDisabled);

public sealed record AuthResponse(
    string AccessToken,
    DateTimeOffset AccessTokenExpiresAt,
    string RefreshToken,
    DateTimeOffset RefreshTokenExpiresAt,
    UserSummary User);
