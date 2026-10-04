using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Noema.Api.Common;
using Noema.Api.Security;
using Noema.Domain;
using Noema.Infrastructure.Persistence;
using Noema.Infrastructure.Security;

namespace Noema.Api.Features.Ranges;

internal sealed class RangeService(
    NoemaDbContext db,
    IOptions<SecurityOptions> security,
    IAuditWriter audit,
    TimeProvider time)
{
    public async Task<IReadOnlyList<RangeDetail>> ListAsync(CancellationToken ct)
    {
        var ranges = await db.AuthorizedRanges.AsNoTracking().OrderBy(r => r.CreatedAt).ToListAsync(ct);
        return ranges.Select(ToDetail).ToList();
    }

    public async Task<ServiceResult<RangeDetail>> CreateAsync(CurrentUser actor, CreateRangeRequest request, CancellationToken ct)
    {
        if (!CidrRange.TryParse(request.Cidr, out var cidr))
        {
            return ServiceResult<RangeDetail>.Fail(ServiceErrors.Validation(
                "cidr", "Use network notation such as 192.168.1.0/24 with no host bits set."));
        }

        var problem = ScanTargetRules.ValidateForAuthorization(cidr, security.Value.AllowPublicRanges);
        if (problem is not null)
        {
            audit.Add("range.create_denied", AuditOutcome.Denied, actor.Id, actor.Username, "range", cidr.ToString(), new { reason = problem });
            await db.SaveChangesAsync(ct);
            return ServiceResult<RangeDetail>.Fail(ServiceErrors.Validation("cidr", problem));
        }

        if (request.Description is { Length: > AuthorizedRange.MaxDescriptionLength })
        {
            return ServiceResult<RangeDetail>.Fail(ServiceErrors.Validation(
                "description", $"A description can be at most {AuthorizedRange.MaxDescriptionLength} characters."));
        }

        var text = cidr.ToString();
        if (await db.AuthorizedRanges.AnyAsync(r => r.Range == cidr, ct))
        {
            return ServiceResult<RangeDetail>.Fail(ServiceErrors.Conflict("That range is already authorized."));
        }

        var range = AuthorizedRange.Create(cidr, request.Description, actor.Id, time.GetUtcNow(), security.Value.AllowPublicRanges);
        db.AuthorizedRanges.Add(range);
        audit.Add("range.created", AuditOutcome.Success, actor.Id, actor.Username, "range", text, new { cidr = text });

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            return ServiceResult<RangeDetail>.Fail(ServiceErrors.Conflict("That range is already authorized."));
        }

        return ServiceResult<RangeDetail>.Ok(ToDetail(range));
    }

    public async Task<ServiceResult<Unit>> DeleteAsync(CurrentUser actor, Guid id, CancellationToken ct)
    {
        var range = await db.AuthorizedRanges.SingleOrDefaultAsync(r => r.Id == id, ct);
        if (range is null)
        {
            return ServiceResult<Unit>.Fail(ServiceErrors.NotFound("No such range."));
        }

        db.AuthorizedRanges.Remove(range);
        audit.Add("range.deleted", AuditOutcome.Success, actor.Id, actor.Username, "range", range.Range.ToString(), new { cidr = range.Range.ToString() });
        await db.SaveChangesAsync(ct);

        return ServiceResult<Unit>.Ok(default);
    }

    private static RangeDetail ToDetail(AuthorizedRange range) =>
        new(range.Id, range.Range.ToString(), range.Description, range.CreatedByUserId, range.CreatedAt);
}
