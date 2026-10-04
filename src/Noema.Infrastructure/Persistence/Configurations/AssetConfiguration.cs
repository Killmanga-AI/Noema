using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Noema.Domain;

namespace Noema.Infrastructure.Persistence.Configurations;

internal sealed class AssetConfiguration : IEntityTypeConfiguration<Asset>
{
    public void Configure(EntityTypeBuilder<Asset> builder)
    {
        builder.ToTable("assets", table =>
            table.HasCheckConstraint("ck_assets_seen_order", "last_seen_at >= first_seen_at"));

        builder.HasKey(a => a.Id);
        builder.Property(a => a.Id).ValueGeneratedNever();

        builder.Property(a => a.Name).HasMaxLength(Asset.MaxNameLength);
        builder.Property(a => a.Hostname).HasMaxLength(Asset.MaxHostnameLength);
        builder.Property(a => a.Kind).HasConversion<string>().HasMaxLength(32);

        // Optimistic concurrency using the Postgres row version, so two writers cannot silently overwrite each other.
        builder.Property<uint>("xmin")
            .HasColumnType("xid")
            .ValueGeneratedOnAddOrUpdate()
            .IsConcurrencyToken();

        builder.HasMany(a => a.Interfaces)
            .WithOne()
            .HasForeignKey(i => i.AssetId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.Navigation(a => a.Interfaces)
            .HasField("interfaces")
            .UsePropertyAccessMode(PropertyAccessMode.Field);

        builder.HasIndex(a => a.Hostname).HasDatabaseName("ix_assets_hostname");
        builder.HasIndex(a => a.LastSeenAt).HasDatabaseName("ix_assets_last_seen_at");
    }
}
