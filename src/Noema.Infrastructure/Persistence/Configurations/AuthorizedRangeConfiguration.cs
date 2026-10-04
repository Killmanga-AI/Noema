using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Noema.Domain;
using Noema.Infrastructure.Persistence.Converters;

namespace Noema.Infrastructure.Persistence.Configurations;

internal sealed class AuthorizedRangeConfiguration : IEntityTypeConfiguration<AuthorizedRange>
{
    public void Configure(EntityTypeBuilder<AuthorizedRange> builder)
    {
        builder.ToTable("authorized_ranges");

        builder.HasKey(r => r.Id);
        builder.Property(r => r.Id).ValueGeneratedNever();

        builder.Property(r => r.Range)
            .HasConversion(new CidrRangeConverter())
            .HasMaxLength(64);

        builder.Property(r => r.Description).HasMaxLength(AuthorizedRange.MaxDescriptionLength);

        // An administrator who authorized ranges cannot be removed while those ranges exist.
        builder.HasOne<User>()
            .WithMany()
            .HasForeignKey(r => r.CreatedByUserId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasIndex(r => r.Range).IsUnique().HasDatabaseName("ux_authorized_ranges_range");
    }
}
