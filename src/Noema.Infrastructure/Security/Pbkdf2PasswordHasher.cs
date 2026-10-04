using System.Globalization;
using System.Security.Cryptography;

namespace Noema.Infrastructure.Security;

/// <summary>
/// PBKDF2 with HMAC SHA256 and a random salt per password. Stored as
/// pbkdf2-sha256$iterations$salt$hash so the cost can be raised later and old hashes still verify.
/// </summary>
public sealed class Pbkdf2PasswordHasher : IPasswordHasher
{
    public const int DefaultIterations = 600_000;

    private const int MinIterations = 1_000;
    private const int MaxAcceptedIterations = 10_000_000;
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const string Scheme = "pbkdf2-sha256";

    private readonly int iterations;
    private readonly Lazy<string> decoyHash;

    public Pbkdf2PasswordHasher(int iterations = DefaultIterations)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, MinIterations);
        this.iterations = iterations;
        decoyHash = new Lazy<string>(() => Hash("noema-decoy-password-for-timing"));
    }

    public string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, HashSize);

        return string.Join('$', Scheme, iterations.ToString(CultureInfo.InvariantCulture), Convert.ToBase64String(salt), Convert.ToBase64String(hash));
    }

    public PasswordVerification Verify(string storedHash, string password)
    {
        if (password is null || !TryParse(storedHash, out var storedIterations, out var salt, out var expected))
        {
            return PasswordVerification.Failed;
        }

        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, storedIterations, HashAlgorithmName.SHA256, expected.Length);

        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            return PasswordVerification.Failed;
        }

        return storedIterations < iterations
            ? PasswordVerification.SuccessRehashNeeded
            : PasswordVerification.Success;
    }

    public void SimulateVerify(string password) => Verify(decoyHash.Value, password ?? string.Empty);

    private static bool TryParse(string? stored, out int storedIterations, out byte[] salt, out byte[] hash)
    {
        storedIterations = 0;
        salt = [];
        hash = [];

        if (string.IsNullOrEmpty(stored))
        {
            return false;
        }

        var parts = stored.Split('$');
        if (parts.Length != 4 || parts[0] != Scheme)
        {
            return false;
        }

        if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out storedIterations)
            || storedIterations < MinIterations
            || storedIterations > MaxAcceptedIterations)
        {
            return false;
        }

        try
        {
            salt = Convert.FromBase64String(parts[2]);
            hash = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        return salt.Length >= 8 && hash.Length == HashSize;
    }
}
