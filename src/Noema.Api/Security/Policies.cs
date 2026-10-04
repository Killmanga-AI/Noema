namespace Noema.Api.Security;

public static class Policies
{
    /// <summary>Operators and administrators.</summary>
    public const string Operator = "Operator";

    /// <summary>Administrators only.</summary>
    public const string Admin = "Admin";
}

public static class RateLimitPolicies
{
    public const string Auth = "auth";
}
