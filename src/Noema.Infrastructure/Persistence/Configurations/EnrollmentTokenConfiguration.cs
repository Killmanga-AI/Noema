using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Noema.Domain;

namespace Noema.Infrastructure.Persistence.Configurations;

internal sealed class EnrollmentTokenConfiguration : IEntityTypeConfiguration<EnrollmentToken>
{
    public void Configure(EntityTypeBuilder<EnrollmentToken> builder)
    {
        builder.ToTable("enrollment_tokens");

        builder.HasKey(t => t.Id);
        builder.Property(t => t.Id).ValueGeneratedNever();

        builder.Property(t => t.TokenHash).HasMaxLength(64).IsRequired();
        builder.Property(t => t.Label).HasMaxLength(EnrollmentToken.MaxLabelLength);

        // The token is single use. If two agents present it at once, only one save can succeed.
        builder.Property<uint>("xmin")
            .HasColumnType("xid")
            .ValueGeneratedOnAddOrUpdate()
            .IsConcurrencyToken();

        builder.HasOne<User>()
            .WithMany()
            .HasForeignKey(t => t.CreatedByUserId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne<Agent>()
            .WithMany()
            .HasForeignKey(t => t.AgentId)
            .OnDelete(DeleteBehavior.SetNull);

        builder.HasIndex(t => t.TokenHash).IsUnique().HasDatabaseName("ux_enrollment_tokens_token_hash");
        builder.HasIndex(t => t.ExpiresAt).HasDatabaseName("ix_enrollment_tokens_expires_at");
    }
}
