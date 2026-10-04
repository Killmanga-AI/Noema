using Npgsql;

namespace Noema.Infrastructure.Tests;

internal static class PostgresErrors
{
    public static PostgresException? Find(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is PostgresException postgres)
            {
                return postgres;
            }
        }

        return null;
    }
}
