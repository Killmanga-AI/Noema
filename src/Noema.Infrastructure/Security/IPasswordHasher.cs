namespace Noema.Infrastructure.Security;

public enum PasswordVerification
{
    Failed,
    Success,

    /// <summary>The password is right but the stored hash is weaker than the current settings, so it should be replaced.</summary>
    SuccessRehashNeeded
}

public interface IPasswordHasher
{
    string Hash(string password);

    PasswordVerification Verify(string storedHash, string password);

    /// <summary>
    /// Does the same work as a real check without any stored hash. Used when the user does not exist
    /// so that the response time does not reveal which usernames are real.
    /// </summary>
    void SimulateVerify(string password);
}
