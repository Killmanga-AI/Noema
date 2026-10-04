namespace Noema.Api.Features.Ranges;

public sealed record CreateRangeRequest(string? Cidr, string? Description);

public sealed record RangeDetail(Guid Id, string Cidr, string? Description, Guid CreatedByUserId, DateTimeOffset CreatedAt);
