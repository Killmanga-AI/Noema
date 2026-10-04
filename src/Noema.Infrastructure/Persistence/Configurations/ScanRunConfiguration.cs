using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Noema.Domain;
using Noema.Infrastructure.Persistence.Converters;

namespace Noema.Infrastructure.Persistence.Configurations;

internal sealed class ScanRunConfiguration : IEntityTypeConfiguration<ScanRun>
{
    public void Configure(EntityTypeBuilder<ScanRun> builder)
    {
        builder.ToTable("scan_runs", table =>
        {
            table.HasCheckConstraint(
                "ck_scan_runs_finished_after_started",
                "started_at IS NULL OR finished_at IS NULL OR finished_at >= started_at");

            // The database refuses states the domain would never produce.
            table.HasCheckConstraint(
                "ck_scan_runs_status_timestamps",
                "(status = 'Queued' AND started_at IS NULL AND finished_at IS NULL) " +
                "OR (status = 'Running' AND started_at IS NOT NULL AND finished_at IS NULL) " +
                "OR (status IN ('Completed', 'Failed', 'Cancelled') AND finished_at IS NOT NULL)");
        });

        builder.HasKey(s => s.Id);
        builder.Property(s => s.Id).ValueGeneratedNever();

        builder.Property(s => s.Target)
            .HasConversion(new CidrRangeConverter())
            .HasMaxLength(64);

        builder.Property(s => s.Probes).HasConversion<int>();
        builder.Property(s => s.Status).HasConversion<string>().HasMaxLength(16);
        builder.Property(s => s.FailureReason).HasMaxLength(ScanRun.MaxFailureReasonLength);

        builder.HasIndex(s => s.Status).HasDatabaseName("ix_scan_runs_status");
        builder.HasIndex(s => s.RequestedAt).HasDatabaseName("ix_scan_runs_requested_at");
    }
}
