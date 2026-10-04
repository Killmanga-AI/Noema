using Microsoft.EntityFrameworkCore;

namespace Noema.Infrastructure.Persistence;

public sealed class NoemaDbContext(DbContextOptions<NoemaDbContext> options) : DbContext(options);
