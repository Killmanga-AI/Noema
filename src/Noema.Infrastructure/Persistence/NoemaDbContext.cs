using Microsoft.EntityFrameworkCore;
using Noema.Domain;
using Noema.Infrastructure.Persistence.Configurations;

namespace Noema.Infrastructure.Persistence;

public sealed class NoemaDbContext(DbContextOptions<NoemaDbContext> options) : DbContext(options)
{
    public DbSet<Asset> Assets => Set<Asset>();

    public DbSet<AssetInterface> AssetInterfaces => Set<AssetInterface>();

    public DbSet<InterfaceAddress> InterfaceAddresses => Set<InterfaceAddress>();

    public DbSet<ScanRun> ScanRuns => Set<ScanRun>();

    public DbSet<Observation> Observations => Set<Observation>();

    public DbSet<User> Users => Set<User>();

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    public DbSet<AuthorizedRange> AuthorizedRanges => Set<AuthorizedRange>();

    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfiguration(new AssetConfiguration());
        modelBuilder.ApplyConfiguration(new AssetInterfaceConfiguration());
        modelBuilder.ApplyConfiguration(new InterfaceAddressConfiguration());
        modelBuilder.ApplyConfiguration(new ScanRunConfiguration());
        modelBuilder.ApplyConfiguration(new ObservationConfiguration());
        modelBuilder.ApplyConfiguration(new UserConfiguration());
        modelBuilder.ApplyConfiguration(new RefreshTokenConfiguration());
        modelBuilder.ApplyConfiguration(new AuthorizedRangeConfiguration());
        modelBuilder.ApplyConfiguration(new AuditEntryConfiguration());

        // snake_case columns keep hand written SQL and reports readable. xmin is a Postgres system column.
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var property in entityType.GetProperties())
            {
                if (property.Name != "xmin")
                {
                    property.SetColumnName(SnakeCase.From(property.Name));
                }
            }
        }
    }
}
