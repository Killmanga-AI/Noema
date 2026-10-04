using Microsoft.EntityFrameworkCore;
using Noema.Api.Common;
using Noema.Api.Security;
using Noema.Domain;
using Noema.Infrastructure.Persistence;
using Noema.Infrastructure.Security;

namespace Noema.Api.Features.Auth;

internal sealed class AuthService(
    NoemaDbContext db,
    IPasswordHasher hasher,
    ITokenService tokens,
    IAuditWriter audit,
    TimeProvider time)
{
    private const int MaxLoginPasswordLength = 256;
    private const string InvalidCredentials = "Invalid username or password.";
    private const string InvalidSession = "The session is not valid. Sign in again.";

    private sealed record Session(AuthResponse Response, Guid RefreshTokenId);

    public async Task<ServiceResult<AuthResponse>> LoginAsync(LoginRequest request, CancellationToken ct)
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(request.Username))
        {
            errors["username"] = ["Username is required."];
        }

        if (string.IsNullOrEmpty(request.Password))
        {
            errors["password"] = ["Password is required."];
        }
        else if (request.Password.Length > MaxLoginPasswordLength)
        {
            errors["password"] = ["Password is too long."];
        }

        if (errors.Count > 0)
        {
            return ServiceResult<AuthResponse>.Fail(ServiceErrors.Validation(errors));
        }

        var password = request.Password!;
        var now = time.GetUtcNow();
        var username = User.NormalizeUsername(request.Username);

        var user = username.Length <= 64
            ? await db.Users.SingleOrDefaultAsync(u => u.Username == username, ct)
            : null;

        // Every failure path returns the same response after the same amount of hashing work,
        // so neither the message nor the timing reveals which usernames exist or which are locked.
        if (user is null)
        {
            hasher.SimulateVerify(password);
            audit.Add(
                "auth.login.failed",
                AuditOutcome.Failure,
                actorName: User.IsValidUsername(username) ? username : null,
                detail: new { reason = "unknown_user" });
            await SaveIgnoringConflictsAsync(ct);
            return Invalid();
        }

        if (!user.CanSignIn(now))
        {
            hasher.SimulateVerify(password);
            audit.Add(
                "auth.login.denied",
                AuditOutcome.Denied,
                user.Id,
                user.Username,
                "user",
                user.Id.ToString(),
                new { reason = user.IsDisabled ? "disabled" : "locked" });
            await SaveIgnoringConflictsAsync(ct);
            return Invalid();
        }

        var verification = hasher.Verify(user.PasswordHash, password);
        if (verification == PasswordVerification.Failed)
        {
            var locked = user.RecordFailedLogin(now);

            audit.Add("auth.login.failed", AuditOutcome.Failure, user.Id, user.Username, "user", user.Id.ToString(), new { reason = "bad_password" });
            if (locked)
            {
                audit.Add(
                    "auth.account.locked",
                    AuditOutcome.Denied,
                    user.Id,
                    user.Username,
                    "user",
                    user.Id.ToString(),
                    new { minutes = (int)User.LockoutDuration.TotalMinutes });
            }

            await SaveIgnoringConflictsAsync(ct);
            return Invalid();
        }

        if (verification == PasswordVerification.SuccessRehashNeeded)
        {
            user.ReplacePasswordHash(hasher.Hash(password));
        }

        user.RecordSuccessfulLogin(now);
        var session = IssueSession(user, now);
        audit.Add("auth.login.succeeded", AuditOutcome.Success, user.Id, user.Username, "user", user.Id.ToString());

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            return Invalid();
        }

        return ServiceResult<AuthResponse>.Ok(session.Response);
    }

    public async Task<ServiceResult<AuthResponse>> RefreshAsync(RefreshRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken) || request.RefreshToken.Length > 200)
        {
            return ServiceResult<AuthResponse>.Fail(ServiceErrors.Validation("refreshToken", "A refresh token is required."));
        }

        var now = time.GetUtcNow();
        var hash = tokens.HashRefreshToken(request.RefreshToken.Trim());
        var stored = await db.RefreshTokens.SingleOrDefaultAsync(t => t.TokenHash == hash, ct);

        if (stored is null)
        {
            audit.Add("auth.refresh.failed", AuditOutcome.Failure, detail: new { reason = "unknown_token" });
            await SaveIgnoringConflictsAsync(ct);
            return InvalidSessionResult();
        }

        if (stored.IsRevoked)
        {
            if (stored.ReplacedByTokenId is not null)
            {
                // This token was already exchanged for a new one. Someone is replaying a copy,
                // so end every session for the user and make them sign in again.
                var active = await db.RefreshTokens
                    .Where(t => t.UserId == stored.UserId && t.RevokedAt == null)
                    .ToListAsync(ct);

                foreach (var token in active)
                {
                    token.Revoke(now);
                }

                var actorName = await db.Users
                    .Where(u => u.Id == stored.UserId)
                    .Select(u => u.Username)
                    .SingleOrDefaultAsync(ct);

                audit.Add(
                    "auth.refresh.reuse_detected",
                    AuditOutcome.Denied,
                    stored.UserId,
                    actorName,
                    targetType: "user",
                    targetId: stored.UserId.ToString(),
                    detail: new { revokedSessions = active.Count });
            }
            else
            {
                audit.Add("auth.refresh.denied", AuditOutcome.Denied, stored.UserId, detail: new { reason = "revoked" });
            }

            await SaveIgnoringConflictsAsync(ct);
            return InvalidSessionResult();
        }

        if (stored.IsExpired(now))
        {
            audit.Add("auth.refresh.denied", AuditOutcome.Denied, stored.UserId, detail: new { reason = "expired" });
            await SaveIgnoringConflictsAsync(ct);
            return InvalidSessionResult();
        }

        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == stored.UserId, ct);
        if (user is null || !user.CanSignIn(now))
        {
            stored.Revoke(now);
            audit.Add("auth.refresh.denied", AuditOutcome.Denied, stored.UserId, user?.Username, detail: new { reason = "account_unavailable" });
            await SaveIgnoringConflictsAsync(ct);
            return InvalidSessionResult();
        }

        var session = IssueSession(user, now);
        stored.Revoke(now, session.RefreshTokenId);
        audit.Add("auth.refresh.succeeded", AuditOutcome.Success, user.Id, user.Username, "user", user.Id.ToString());

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            return InvalidSessionResult();
        }

        return ServiceResult<AuthResponse>.Ok(session.Response);
    }

    public async Task<ServiceResult<Unit>> LogoutAsync(CurrentUser current, LogoutRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken) || request.RefreshToken.Length > 200)
        {
            return ServiceResult<Unit>.Fail(ServiceErrors.Validation("refreshToken", "A refresh token is required."));
        }

        var now = time.GetUtcNow();
        var hash = tokens.HashRefreshToken(request.RefreshToken.Trim());
        var stored = await db.RefreshTokens.SingleOrDefaultAsync(t => t.TokenHash == hash && t.UserId == current.Id, ct);

        // Always answer the same way so this endpoint cannot be used to test whether a token exists.
        stored?.Revoke(now);
        audit.Add("auth.logout", AuditOutcome.Success, current.Id, current.Username, "user", current.Id.ToString());
        await SaveIgnoringConflictsAsync(ct);

        return ServiceResult<Unit>.Ok(default);
    }

    public async Task<ServiceResult<Unit>> ChangePasswordAsync(CurrentUser current, ChangePasswordRequest request, CancellationToken ct)
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrEmpty(request.CurrentPassword))
        {
            errors["currentPassword"] = ["The current password is required."];
        }
        else if (request.CurrentPassword.Length > MaxLoginPasswordLength)
        {
            errors["currentPassword"] = ["The current password is too long."];
        }

        if (errors.Count > 0)
        {
            return ServiceResult<Unit>.Fail(ServiceErrors.Validation(errors));
        }

        var now = time.GetUtcNow();
        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == current.Id, ct);
        if (user is null || !user.CanSignIn(now))
        {
            return ServiceResult<Unit>.Fail(ServiceErrors.Unauthorized(InvalidSession));
        }

        // Wrong guesses here count towards the same lockout as signing in,
        // so a stolen access token cannot be used to guess the password.
        if (hasher.Verify(user.PasswordHash, request.CurrentPassword!) == PasswordVerification.Failed)
        {
            user.RecordFailedLogin(now);
            audit.Add("auth.password.change_failed", AuditOutcome.Failure, user.Id, user.Username, "user", user.Id.ToString());
            await SaveIgnoringConflictsAsync(ct);
            return ServiceResult<Unit>.Fail(ServiceErrors.Validation("currentPassword", "The current password is wrong."));
        }

        var problems = PasswordPolicy.Check(request.NewPassword, user.Username);
        if (problems.Count == 0 && request.NewPassword == request.CurrentPassword)
        {
            problems = ["The new password must be different from the current one."];
        }

        if (problems.Count > 0)
        {
            return ServiceResult<Unit>.Fail(ServiceErrors.Validation("newPassword", string.Join(" ", problems)));
        }

        user.ChangePasswordHash(hasher.Hash(request.NewPassword!), now);
        user.RecordSuccessfulLogin(now);

        var sessions = await db.RefreshTokens.Where(t => t.UserId == user.Id && t.RevokedAt == null).ToListAsync(ct);
        foreach (var session in sessions)
        {
            session.Revoke(now);
        }

        audit.Add(
            "auth.password.changed",
            AuditOutcome.Success,
            user.Id,
            user.Username,
            "user",
            user.Id.ToString(),
            new { revokedSessions = sessions.Count });

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            return ServiceResult<Unit>.Fail(ServiceErrors.Conflict("The account was changed by another request. Try again."));
        }

        return ServiceResult<Unit>.Ok(default);
    }

    public async Task<ServiceResult<UserSummary>> MeAsync(CurrentUser current, CancellationToken ct)
    {
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == current.Id, ct);

        return user is null
            ? ServiceResult<UserSummary>.Fail(ServiceErrors.Unauthorized(InvalidSession))
            : ServiceResult<UserSummary>.Ok(ToSummary(user));
    }

    private Session IssueSession(User user, DateTimeOffset now)
    {
        var access = tokens.IssueAccessToken(user, now);
        var rawRefresh = tokens.NewRefreshToken();
        var refresh = RefreshToken.Issue(user.Id, tokens.HashRefreshToken(rawRefresh), now, tokens.RefreshTokenLifetime);

        db.RefreshTokens.Add(refresh);

        var response = new AuthResponse(access.Token, access.ExpiresAt, rawRefresh, refresh.ExpiresAt, ToSummary(user));
        return new Session(response, refresh.Id);
    }

    private async Task SaveIgnoringConflictsAsync(CancellationToken ct)
    {
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            // Another request changed the same account at the same moment. The caller already
            // answers with a generic failure, so losing this one update is acceptable.
        }
    }

    private static ServiceResult<AuthResponse> Invalid() =>
        ServiceResult<AuthResponse>.Fail(ServiceErrors.Unauthorized(InvalidCredentials));

    private static ServiceResult<AuthResponse> InvalidSessionResult() =>
        ServiceResult<AuthResponse>.Fail(ServiceErrors.Unauthorized(InvalidSession));

    internal static UserSummary ToSummary(User user) =>
        new(user.Id, user.Username, user.Role.ToString(), user.IsDisabled);
}
