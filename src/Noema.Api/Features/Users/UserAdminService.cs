using Microsoft.EntityFrameworkCore;
using Noema.Api.Common;
using Noema.Api.Security;
using Noema.Domain;
using Noema.Infrastructure.Persistence;
using Noema.Infrastructure.Security;

namespace Noema.Api.Features.Users;

internal sealed class UserAdminService(
    NoemaDbContext db,
    IPasswordHasher hasher,
    IAuditWriter audit,
    TimeProvider time)
{
    public async Task<IReadOnlyList<UserDetail>> ListAsync(CancellationToken ct)
    {
        var users = await db.Users.AsNoTracking().OrderBy(u => u.Username).ToListAsync(ct);
        return users.Select(ToDetail).ToList();
    }

    public async Task<ServiceResult<UserDetail>> CreateAsync(CurrentUser actor, CreateUserRequest request, CancellationToken ct)
    {
        var errors = new Dictionary<string, string[]>();
        var username = User.NormalizeUsername(request.Username);

        if (!User.IsValidUsername(username))
        {
            errors["username"] = ["A username is 3 to 64 characters: letters, digits, dot, dash or underscore, starting with a letter or digit."];
        }

        var problems = PasswordPolicy.Check(request.Password, username);
        if (problems.Count > 0)
        {
            errors["password"] = problems.ToArray();
        }

        if (!EnumParsing.TryParseName<UserRole>(request.Role, out var role))
        {
            errors["role"] = ["The role must be Admin or Operator."];
        }

        if (errors.Count > 0)
        {
            return ServiceResult<UserDetail>.Fail(ServiceErrors.Validation(errors));
        }

        if (await db.Users.AnyAsync(u => u.Username == username, ct))
        {
            return ServiceResult<UserDetail>.Fail(ServiceErrors.Conflict("That username is already taken."));
        }

        var now = time.GetUtcNow();
        var user = User.Create(username, hasher.Hash(request.Password!), role, now);
        db.Users.Add(user);
        audit.Add("user.created", AuditOutcome.Success, actor.Id, actor.Username, "user", user.Id.ToString(), new { username = user.Username, role = user.Role.ToString() });

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            return ServiceResult<UserDetail>.Fail(ServiceErrors.Conflict("That username is already taken."));
        }

        return ServiceResult<UserDetail>.Ok(ToDetail(user));
    }

    public async Task<ServiceResult<UserDetail>> UpdateAsync(CurrentUser actor, Guid id, UpdateUserRequest request, CancellationToken ct)
    {
        if (request.Role is null && request.IsDisabled is null)
        {
            return ServiceResult<UserDetail>.Fail(ServiceErrors.Validation("request", "Send a role, isDisabled, or both."));
        }

        UserRole? newRole = null;
        if (request.Role is not null)
        {
            if (!EnumParsing.TryParseName<UserRole>(request.Role, out var parsed))
            {
                return ServiceResult<UserDetail>.Fail(ServiceErrors.Validation("role", "The role must be Admin or Operator."));
            }

            newRole = parsed;
        }

        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == id, ct);
        if (user is null)
        {
            return ServiceResult<UserDetail>.Fail(ServiceErrors.NotFound("No such user."));
        }

        var losesAdmin = user is { Role: UserRole.Admin, IsDisabled: false }
            && ((newRole is not null && newRole != UserRole.Admin) || request.IsDisabled == true);

        if (losesAdmin && !await AnotherActiveAdminExistsAsync(user.Id, ct))
        {
            return ServiceResult<UserDetail>.Fail(ServiceErrors.Conflict("That would leave no active administrator."));
        }

        var now = time.GetUtcNow();
        var changes = new Dictionary<string, object?>();

        if (newRole is not null && newRole != user.Role)
        {
            changes["role"] = new { from = user.Role.ToString(), to = newRole.Value.ToString() };
            user.ChangeRole(newRole.Value);
        }

        if (request.IsDisabled is { } disabled && disabled != user.IsDisabled)
        {
            changes["isDisabled"] = disabled;

            if (disabled)
            {
                user.Disable();
                await RevokeSessionsAsync(user.Id, now, ct);
            }
            else
            {
                user.Enable();
            }
        }

        audit.Add("user.updated", AuditOutcome.Success, actor.Id, actor.Username, "user", user.Id.ToString(), changes);

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            return ServiceResult<UserDetail>.Fail(ServiceErrors.Conflict("The user was changed by another request. Try again."));
        }

        return ServiceResult<UserDetail>.Ok(ToDetail(user));
    }

    public async Task<ServiceResult<Unit>> ResetPasswordAsync(CurrentUser actor, Guid id, ResetPasswordRequest request, CancellationToken ct)
    {
        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == id, ct);
        if (user is null)
        {
            return ServiceResult<Unit>.Fail(ServiceErrors.NotFound("No such user."));
        }

        var problems = PasswordPolicy.Check(request.NewPassword, user.Username);
        if (problems.Count > 0)
        {
            return ServiceResult<Unit>.Fail(ServiceErrors.Validation("newPassword", string.Join(" ", problems)));
        }

        var now = time.GetUtcNow();
        user.ChangePasswordHash(hasher.Hash(request.NewPassword!), now);
        user.Unlock();
        var revoked = await RevokeSessionsAsync(user.Id, now, ct);

        audit.Add("user.password_reset", AuditOutcome.Success, actor.Id, actor.Username, "user", user.Id.ToString(), new { revokedSessions = revoked });

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            return ServiceResult<Unit>.Fail(ServiceErrors.Conflict("The user was changed by another request. Try again."));
        }

        return ServiceResult<Unit>.Ok(default);
    }

    public async Task<ServiceResult<UserDetail>> UnlockAsync(CurrentUser actor, Guid id, CancellationToken ct)
    {
        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == id, ct);
        if (user is null)
        {
            return ServiceResult<UserDetail>.Fail(ServiceErrors.NotFound("No such user."));
        }

        user.Unlock();
        audit.Add("user.unlocked", AuditOutcome.Success, actor.Id, actor.Username, "user", user.Id.ToString());

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            return ServiceResult<UserDetail>.Fail(ServiceErrors.Conflict("The user was changed by another request. Try again."));
        }

        return ServiceResult<UserDetail>.Ok(ToDetail(user));
    }

    private Task<bool> AnotherActiveAdminExistsAsync(Guid exceptUserId, CancellationToken ct) =>
        db.Users.AnyAsync(u => u.Role == UserRole.Admin && !u.IsDisabled && u.Id != exceptUserId, ct);

    private async Task<int> RevokeSessionsAsync(Guid userId, DateTimeOffset now, CancellationToken ct)
    {
        var sessions = await db.RefreshTokens.Where(t => t.UserId == userId && t.RevokedAt == null).ToListAsync(ct);
        foreach (var session in sessions)
        {
            session.Revoke(now);
        }

        return sessions.Count;
    }

    private static UserDetail ToDetail(User user) =>
        new(user.Id, user.Username, user.Role.ToString(), user.IsDisabled, user.CreatedAt, user.LastLoginAt, user.LockedUntil);
}
