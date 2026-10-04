namespace Noema.Infrastructure.Security;

/// <summary>Creates the first administrator when there are no users. Remove the password from configuration afterwards.</summary>
public sealed class BootstrapOptions
{
    public const string SectionName = "Bootstrap";

    public string? AdminUsername { get; set; }

    public string? AdminPassword { get; set; }
}
