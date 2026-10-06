using System.Security.Cryptography;
using System.Text;

namespace Noema.Infrastructure.Security;

/// <summary>
/// Random secrets for enrollment and agent credentials. They carry 256 bits of randomness, so a plain SHA256 of the
/// value is a safe thing to store, a slow password hash would add nothing. A short prefix makes leaked ones easy to spot.
/// </summary>
public static class SecretTokens
{
    public const string EnrollmentPrefix = "nmt_";
    public const string AgentSecretPrefix = "nma_";

    public static string NewEnrollmentToken() => EnrollmentPrefix + RandomPart();

    public static string NewAgentSecret() => AgentSecretPrefix + RandomPart();

    public static string Hash(string secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
    }

    /// <summary>Compares a presented secret with a stored hash in constant time.</summary>
    public static bool Matches(string? presented, string? storedHash)
    {
        if (string.IsNullOrEmpty(presented) || string.IsNullOrEmpty(storedHash))
        {
            return false;
        }

        var presentedHash = Encoding.UTF8.GetBytes(Hash(presented));
        var stored = Encoding.UTF8.GetBytes(storedHash);

        return CryptographicOperations.FixedTimeEquals(presentedHash, stored);
    }

    private static string RandomPart() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
