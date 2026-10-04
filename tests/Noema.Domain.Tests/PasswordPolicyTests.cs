namespace Noema.Domain.Tests;

public sealed class PasswordPolicyTests
{
    [Theory]
    [InlineData("correct horse battery staple")]
    [InlineData("a1b2c3d4e5f6")]
    [InlineData("long enough passphrase here")]
    public void Accepts_long_enough_passwords(string password)
    {
        Assert.Empty(PasswordPolicy.Check(password, "latif"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Requires_a_password(string? password)
    {
        Assert.NotEmpty(PasswordPolicy.Check(password));
    }

    [Fact]
    public void Rejects_short_passwords()
    {
        Assert.NotEmpty(PasswordPolicy.Check(new string('a', PasswordPolicy.MinLength - 1)));
        Assert.NotEmpty(PasswordPolicy.Check("short1!"));
    }

    [Fact]
    public void Accepts_the_exact_minimum_and_maximum_lengths()
    {
        Assert.Empty(PasswordPolicy.Check("abcdefghijkl"));
        Assert.Empty(PasswordPolicy.Check(string.Concat(Enumerable.Repeat("ab", PasswordPolicy.MaxLength / 2))));
    }

    [Fact]
    public void Rejects_passwords_over_the_maximum()
    {
        Assert.NotEmpty(PasswordPolicy.Check(string.Concat(Enumerable.Repeat("ab", PasswordPolicy.MaxLength / 2 + 1))));
    }

    [Fact]
    public void Rejects_whitespace_only_and_single_repeated_characters()
    {
        Assert.NotEmpty(PasswordPolicy.Check("            "));
        Assert.NotEmpty(PasswordPolicy.Check("aaaaaaaaaaaaaaaa"));
    }

    [Fact]
    public void Rejects_passwords_containing_the_username_in_any_case()
    {
        Assert.NotEmpty(PasswordPolicy.Check("my-LATIF-password-1", "latif"));
        Assert.Empty(PasswordPolicy.Check("my-other-password-1", "latif"));
    }

    [Fact]
    public void Reports_every_problem_at_once()
    {
        var problems = PasswordPolicy.Check("aaa", "aaa");

        Assert.True(problems.Count >= 3);
    }
}
