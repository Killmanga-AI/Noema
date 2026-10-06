using System.Text.Json;

namespace Noema.Agent.Credentials;

/// <summary>Who this agent is and where it enrolled. The secret is what proves it, so treat this like a password.</summary>
public sealed record AgentCredentials(Uri ControlPlaneUrl, Guid AgentId, string AgentSecret)
{
    public override string ToString() => $"AgentCredentials {{ ControlPlaneUrl = {ControlPlaneUrl}, AgentId = {AgentId}, AgentSecret = ***** }}";
}

public interface ICredentialStore
{
    /// <summary>Where the credentials live, for messages to the person running the agent.</summary>
    string Location { get; }

    AgentCredentials? Load();

    void Save(AgentCredentials credentials);
}

public static class AgentPaths
{
    public const string DataDirectoryVariable = "NOEMA_AGENT_DATA_DIR";
    public const string CredentialsFileName = "agent-credentials.json";
    public const string SettingsFileName = "agent.settings.json";

    /// <summary>
    /// Picks the folder that holds this agent's credentials and local settings. An explicit setting wins, then the
    /// environment variable, then a standard per-operating-system location.
    /// </summary>
    public static string ResolveDataDirectory(
        string? configured,
        string? environmentValue,
        bool isWindows,
        bool isMacOS,
        string? programData)
    {
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured.Trim();
        }

        if (!string.IsNullOrWhiteSpace(environmentValue))
        {
            return environmentValue.Trim();
        }

        if (isWindows)
        {
            var root = string.IsNullOrWhiteSpace(programData) ? @"C:\ProgramData" : programData;
            return Path.Combine(root, "Noema", "Agent");
        }

        return isMacOS ? "/usr/local/var/noema-agent" : "/var/lib/noema-agent";
    }

    public static string CurrentDataDirectory(string? configured = null) =>
        ResolveDataDirectory(
            configured,
            Environment.GetEnvironmentVariable(DataDirectoryVariable),
            OperatingSystem.IsWindows(),
            OperatingSystem.IsMacOS(),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));

    public static string CredentialsPath(string dataDirectory) => Path.Combine(dataDirectory, CredentialsFileName);

    public static string SettingsPath(string dataDirectory) => Path.Combine(dataDirectory, SettingsFileName);
}

internal sealed record StoredCredentials(string? ControlPlaneUrl, Guid AgentId, string? AgentSecret);

/// <summary>
/// Keeps the credentials in one JSON file. On Linux and macOS the file is created readable by its owner only,
/// from the first byte. On Windows its access list is cut down to administrators, the system, and the local service account.
/// The file is replaced in one step so a crash never leaves half a credential behind.
/// </summary>
public sealed class FileCredentialStore(string path) : ICredentialStore
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public string Location => path;

    public AgentCredentials? Load()
    {
        if (!File.Exists(path))
        {
            return null;
        }

        StoredCredentials? stored;
        try
        {
            stored = JsonSerializer.Deserialize<StoredCredentials>(File.ReadAllText(path), Json);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"The credentials file {path} is damaged. Enroll the agent again.", ex);
        }

        if (stored is null
            || stored.AgentId == Guid.Empty
            || string.IsNullOrWhiteSpace(stored.AgentSecret)
            || !Uri.TryCreate(stored.ControlPlaneUrl, UriKind.Absolute, out var url))
        {
            throw new InvalidDataException($"The credentials file {path} is incomplete. Enroll the agent again.");
        }

        return new AgentCredentials(url, stored.AgentId, stored.AgentSecret);
    }

    public void Save(AgentCredentials credentials)
    {
        ArgumentNullException.ThrowIfNull(credentials);

        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(directory);

        var temporary = path + ".tmp";
        File.Delete(temporary);

        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        var stored = new StoredCredentials(credentials.ControlPlaneUrl.ToString(), credentials.AgentId, credentials.AgentSecret);
        using (var stream = new FileStream(temporary, options))
        {
            JsonSerializer.Serialize(stream, stored, Json);
        }

        File.Move(temporary, path, overwrite: true);

        if (OperatingSystem.IsWindows())
        {
            WindowsFileSecurity.RestrictToServiceAccounts(path);
        }
    }
}
