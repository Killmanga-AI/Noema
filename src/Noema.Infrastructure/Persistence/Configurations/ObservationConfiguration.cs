using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Noema.Domain;
using Noema.Infrastructure.Persistence.Converters;

namespace Noema.Infrastructure.Persistence.Configurations;

internal sealed class ObservationConfiguration : IEntityTypeConfiguration<Observation>
{
    public void Configure(EntityTypeBuilder<Observation> builder)
    {
        builder.ToTable("observations");

        builder.HasKey(o => o.Id);
        builder.Property(o => o.Id).ValueGeneratedNever();

        builder.Property(o => o.Kind).HasConversion<string>().HasMaxLength(32);
        builder.Property(o => o.Address).HasColumnType("inet");

        builder.Property(o => o.MacAddress)
            .HasConversion(new MacAddressConverter())
            .HasColumnType("macaddr");

        builder.Property(o => o.DetailJson).HasColumnType("jsonb");

        // Removing a scan run removes its observations, which is how retention will work later.
        builder.HasOne<ScanRun>()
            .WithMany()
            .HasForeignKey(o => o.ScanRunId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(o => o.ScanRunId).HasDatabaseName("ix_observations_scan_run_id");
        builder.HasIndex(o => o.ObservedAt).HasDatabaseName("ix_observations_observed_at");
    }
}
