namespace Noema.Api.Common;

public static class EnumParsing
{
    /// <summary>Parses an enum by name only. Numbers, lists and unknown names are refused.</summary>
    public static bool TryParseName<TEnum>(string? value, out TEnum result) where TEnum : struct, Enum
    {
        result = default;

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (!trimmed.All(char.IsAsciiLetter))
        {
            return false;
        }

        return Enum.TryParse(trimmed, ignoreCase: true, out result) && Enum.IsDefined(result);
    }
}
