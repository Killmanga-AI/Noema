using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Noema.Domain;

namespace Noema.Infrastructure.Persistence.Converters;

/// <summary>Stored as text so a bad value can never be read back as a different range.</summary>
internal sealed class CidrRangeConverter : ValueConverter<CidrRange, string>
{
    public CidrRangeConverter()
        : base(
            range => range.ToString(),
            text => CidrRange.Parse(text))
    {
    }
}
