namespace Noema.Domain;

/// <summary>
/// Length matters more than composition rules, so this asks for a long password and blocks the laziest choices.
/// </summary>
public static class PasswordPolicy
{
    public const int MinLength = 12;
    public const int MaxLength = 128;

    public static IReadOnlyList<string> Check(string? password, string? username = null)
    {
        var problems = new List<string>();

        if (string.IsNullOrEmpty(password))
        {
            problems.Add("A password is required.");
            return problems;
        }

        if (password.Length < MinLength)
        {
            problems.Add($"The password must be at least {MinLength} characters.");
        }

        if (password.Length > MaxLength)
        {
            problems.Add($"The password can be at most {MaxLength} characters.");
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            problems.Add("The password cannot be only whitespace.");
        }

        if (password.Length > 0 && password.All(c => c == password[0]))
        {
            problems.Add("The password cannot be a single repeated character.");
        }

        if (!string.IsNullOrWhiteSpace(username)
            && password.Contains(username.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            problems.Add("The password cannot contain the username.");
        }

        return problems;
    }
}
