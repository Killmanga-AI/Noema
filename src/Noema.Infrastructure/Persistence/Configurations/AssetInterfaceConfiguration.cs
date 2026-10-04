using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Noema.Domain;
using Noema.Infrastructure.Persistence.Converters;

namespace Noema.Infrastructure.Persistence.Configurations;

internal sealed class AssetInterfaceConfiguration : IEntityTypeConfiguration<AssetInterface>
{
    public void Configure(EntityTypeBuilder<AssetInterface> builder)
    {
        builder.ToTable("asset_interfaces", table =>
            table.HasCheckConstraint("ck_asset_interfaces_seen_order", "last_seen_at >= first_seen_at"));

        builder.HasKey(i => i.Id);
        builder.Property(i => i.Id).ValueGeneratedNever();

        builder.Property(i => i.MacAddress)
            .HasConversion(new MacAddressConverter())
            .HasColumnType("macaddr");

        builder.HasMany(i => i.Addresses)
            .WithOne()
            .HasForeignKey(a => a.AssetInterfaceId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.Navigation(i => i.Addresses)
            .HasField("addresses")
            .UsePropertyAccessMode(PropertyAccessMode.Field);

        // The same MAC can legitimately appear on more than one asset (VRRP or HSRP virtual MACs, cloned NICs),
        // so it is indexed for lookup but not unique across assets. Identity resolution decides what to do about it.
        builder.HasIndex(i => i.MacAddress).HasDatabaseName("ix_asset_interfaces_mac_address");

        builder.HasIndex(i => new { i.AssetId, i.MacAddress })
            .IsUnique()
            .HasFilter("mac_address IS NOT NULL")
            .HasDatabaseName("ux_asset_interfaces_asset_id_mac");

        builder.HasIndex(i => i.AssetId)
            .IsUnique()
            .HasFilter("mac_address IS NULL")
            .HasDatabaseName("ux_asset_interfaces_asset_id_no_mac");
    }
}
