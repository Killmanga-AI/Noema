namespace Noema.Domain;

internal static class Ids
{
    /// <summary>Time ordered ids keep Postgres b-tree indexes compact and inserts mostly sequential.</summary>
    public static Guid New(DateTimeOffset at) => Guid.CreateVersion7(at);
}
