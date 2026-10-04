using System.ComponentModel.DataAnnotations;

namespace Noema.Infrastructure.Persistence;

public sealed class DatabaseOptions
{
    public const string SectionName = "Database";

    [Required(AllowEmptyStrings = false)]
    public string ConnectionString { get; set; } = string.Empty;

    /// <summary>
    /// Applies pending migrations when the API starts. Fine for a single instance such as a home lab or development.
    /// For several instances run migrations as a separate deployment step instead.
    /// </summary>
    public bool MigrateOnStartup { get; set; }
}
