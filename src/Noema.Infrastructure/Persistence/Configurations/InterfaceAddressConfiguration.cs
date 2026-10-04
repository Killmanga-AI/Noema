using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Noema.Domain;

namespace Noema.Infrastructure.Persistence.Configurations;

internal sealed class InterfaceAddressConfiguration : IEntityTypeConfiguration<InterfaceAddress>
{
    public void Configure(EntityTypeBuilder<InterfaceAddress> builder)
    {
        builder.ToTable("interface_addresses", table =>
            table.HasCheckConstraint("ck_interface_addresses_seen_order", "last_seen_at >= first_seen_at"));

        builder.HasKey(a => a.Id);
        builder.Property(a => a.Id).ValueGeneratedNever();

        builder.Property(a => a.Address).HasColumnType("inet");
    }
}
