using System.Text;

namespace Noema.Infrastructure.Persistence;

internal static class SnakeCase
{
    public static string From(string name)
    {
        var builder = new StringBuilder(name.Length + 4);

        for (var i = 0; i < name.Length; i++)
        {
            var c = name[i];

            if (!char.IsUpper(c))
            {
                builder.Append(c);
                continue;
            }

            var hasPrevious = i > 0;
            var previousIsLowerOrDigit = hasPrevious && (char.IsLower(name[i - 1]) || char.IsDigit(name[i - 1]));
            var endsAcronym = hasPrevious && char.IsUpper(name[i - 1]) && i + 1 < name.Length && char.IsLower(name[i + 1]);

            if (previousIsLowerOrDigit || endsAcronym)
            {
                builder.Append('_');
            }

            builder.Append(char.ToLowerInvariant(c));
        }

        return builder.ToString();
    }
}
