using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Noema.Domain;

namespace Noema.Infrastructure.Persistence.Converters;

/// <summary>Stores a short list of ranges as one comma separated text column.</summary>
internal static class CidrRangeList
{
    public static string Format(IReadOnlyList<CidrRange> ranges) =>
        string.Join(',', ranges.Select(range => range.ToString()));

    public static IReadOnlyList<CidrRange> Parse(string text) =>
        string.IsNullOrWhiteSpace(text)
            ? []
            : text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(CidrRange.Parse).ToList();
}

internal sealed class CidrRangeListConverter : ValueConverter<IReadOnlyList<CidrRange>, string>
{
    public CidrRangeListConverter()
        : base(
            ranges => CidrRangeList.Format(ranges),
            text => CidrRangeList.Parse(text))
    {
    }
}

internal sealed class CidrRangeListComparer : ValueComparer<IReadOnlyList<CidrRange>>
{
    public CidrRangeListComparer()
        : base(
            (left, right) => (left == null && right == null) || (left != null && right != null && left.SequenceEqual(right)),
            ranges => ranges.Aggregate(0, (hash, range) => HashCode.Combine(hash, range)),
            ranges => (IReadOnlyList<CidrRange>)ranges.ToList())
    {
    }
}
