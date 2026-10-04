using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Noema.Domain;

namespace Noema.Infrastructure.Persistence.Configurations;

internal sealed class AuditEntryConfiguration : IEntityTypeConfiguration<AuditEntry>
{
    public void Configure(EntityTypeBuilder<AuditEntry> builder)
    {
        builder.ToTable("audit_entries");

        builder.HasKey(a => a.Id);
        builder.Property(a => a.Id).ValueGeneratedNever();

        builder.Property(a => a.ActorName).HasMaxLength(AuditEntry.MaxActorNameLength);
        builder.Property(a => a.Action).HasMaxLength(64).IsRequired();
        builder.Property(a => a.TargetType).HasMaxLength(64);
        builder.Property(a => a.TargetId).HasMaxLength(128);
        builder.Property(a => a.Outcome).HasConversion<string>().HasMaxLength(16);
        builder.Property(a => a.DetailJson).HasColumnType("jsonb");
        builder.Property(a => a.RemoteAddress).HasColumnType("inet");
        builder.Property(a => a.CorrelationId).HasMaxLength(64);

        // No foreign key to users on purpose, the trail must survive if a user is ever removed.
        builder.HasIndex(a => a.OccurredAt).HasDatabaseName("ix_audit_entries_occurred_at");
        builder.HasIndex(a => a.Action).HasDatabaseName("ix_audit_entries_action");
        builder.HasIndex(a => a.ActorUserId).HasDatabaseName("ix_audit_entries_actor_user_id");
    }
}
