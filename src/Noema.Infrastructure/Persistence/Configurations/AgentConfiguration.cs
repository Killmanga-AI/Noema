using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Noema.Domain;
using Noema.Infrastructure.Persistence.Converters;

namespace Noema.Infrastructure.Persistence.Configurations;

internal sealed class AgentConfiguration : IEntityTypeConfiguration<Agent>
{
    public void Configure(EntityTypeBuilder<Agent> builder)
    {
        builder.ToTable("agents");

        builder.HasKey(a => a.Id);
        builder.Property(a => a.Id).ValueGeneratedNever();

        builder.Property(a => a.Name).HasMaxLength(64).IsRequired();
        builder.Property(a => a.CredentialHash).HasMaxLength(64).IsRequired();
        builder.Property(a => a.Status).HasConversion<string>().HasMaxLength(16);
        builder.Property(a => a.Version).HasMaxLength(Agent.MaxVersionLength);
        builder.Property(a => a.OperatingSystem).HasMaxLength(Agent.MaxOperatingSystemLength);
        builder.Property(a => a.Capabilities).HasConversion<int>();
        builder.Property(a => a.LastSeenAddress).HasColumnType("inet");

        builder.Property(a => a.ReportedRanges)
            .HasConversion(new CidrRangeListConverter(), new CidrRangeListComparer())
            .HasColumnType("text");

        // A revoke and a check in at the same moment must not silently overwrite each other.
        builder.Property<uint>("xmin")
            .HasColumnType("xid")
            .ValueGeneratedOnAddOrUpdate()
            .IsConcurrencyToken();

        builder.HasIndex(a => a.Status).HasDatabaseName("ix_agents_status");
    }
}
