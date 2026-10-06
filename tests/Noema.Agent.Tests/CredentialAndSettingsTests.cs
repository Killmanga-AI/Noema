using Noema.Agent.Credentials;

namespace Noema.Agent.Tests;

public sealed class AgentPathsTests
{
    [Fact]
    public void An_explicit_setting_wins_over_everything()
    {
        Assert.Equal("/custom", AgentPaths.ResolveDataDirectory(" /custom ", "/from-env", false, false, null));
    }

    [Fact]
    public void The_environment_variable_comes_next()
    {
        Assert.Equal("/from-env", AgentPaths.ResolveDataDirectory(null, " /from-env ", false, false, null));
        Assert.Equal("/from-env", AgentPaths.ResolveDataDirectory("   ", "/from-env", true, false, null));
    }

    [Fact]
    public void Defaults_follow_the_operating_system()
    {
        Assert.Equal("/var/lib/noema-agent", AgentPaths.ResolveDataDirectory(null, null, false, false, null));
        Assert.Equal("/usr/local/var/noema-agent", AgentPaths.ResolveDataDirectory(null, null, false, true, null));
        Assert.Equal(Path.Combine(@"D:\Data", "Noema", "Agent"), AgentPaths.ResolveDataDirectory(null, null, true, false, @"D:\Data"));
        Assert.Equal(Path.Combine(@"C:\ProgramData", "Noema", "Agent"), AgentPaths.ResolveDataDirectory(null, "", true, false, null));
    }

    [Fact]
    public void File_names_live_inside_the_data_directory()
    {
        Assert.Equal(Path.Combine("data", "agent-credentials.json"), AgentPaths.CredentialsPath("data"));
        Assert.Equal(Path.Combine("data", "agent.settings.json"), AgentPaths.SettingsPath("data"));
    }
}

public sealed class FileCredentialStoreTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "noema-tests-" + Guid.NewGuid().ToString("N"));

    private string CredentialPath => Path.Combine(directory, "nested", "agent-credentials.json");

    public void Dispose()
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static AgentCredentials Sample(string secret = "nma_secret-value") =>
        new(new Uri("https://noema.example.com:8443/"), Guid.NewGuid(), secret);

    [Fact]
    public void Nothing_is_loaded_before_anything_is_saved()
    {
        Assert.Null(new FileCredentialStore(CredentialPath).Load());
    }

    [Fact]
    public void Credentials_round_trip_and_the_folder_is_created()
    {
        var store = new FileCredentialStore(CredentialPath);
        var saved = Sample();

        store.Save(saved);
        var loaded = store.Load();

        Assert.Equal(saved, loaded);
        Assert.Equal(CredentialPath, store.Location);
    }

    [Fact]
    public void Saving_again_replaces_the_credential_and_leaves_no_temporary_file()
    {
        var store = new FileCredentialStore(CredentialPath);
        store.Save(Sample("nma_first"));
        var second = Sample("nma_second");

        store.Save(second);

        Assert.Equal(second, store.Load());
        Assert.False(File.Exists(CredentialPath + ".tmp"));
        Assert.Single(Directory.GetFiles(Path.GetDirectoryName(CredentialPath)!));
    }

    [Fact]
    public void On_unix_only_the_owner_can_read_the_file()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        new FileCredentialStore(CredentialPath).Save(Sample());

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(CredentialPath));
    }

    [Fact]
    public void A_stale_temporary_file_from_a_crash_does_not_block_saving()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(CredentialPath)!);
        File.WriteAllText(CredentialPath + ".tmp", "leftover");
        var store = new FileCredentialStore(CredentialPath);

        store.Save(Sample());

        Assert.NotNull(store.Load());
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("{}")]
    [InlineData("{\"controlPlaneUrl\":\"https://x.example\",\"agentId\":\"00000000-0000-0000-0000-000000000000\",\"agentSecret\":\"s\"}")]
    [InlineData("{\"controlPlaneUrl\":\"https://x.example\",\"agentId\":\"6f1c6f0e-9d0a-4f4e-9d1e-1f0a8a6f6f11\",\"agentSecret\":\"\"}")]
    [InlineData("{\"controlPlaneUrl\":\"not a url\",\"agentId\":\"6f1c6f0e-9d0a-4f4e-9d1e-1f0a8a6f6f11\",\"agentSecret\":\"s\"}")]
    public void A_damaged_or_incomplete_file_is_reported_clearly(string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(CredentialPath)!);
        File.WriteAllText(CredentialPath, content);

        var thrown = Assert.Throws<InvalidDataException>(() => new FileCredentialStore(CredentialPath).Load());

        Assert.Contains("Enroll the agent again", thrown.Message);
    }

    [Fact]
    public void The_secret_never_appears_when_credentials_are_printed()
    {
        var text = Sample("nma_top-secret-value").ToString();

        Assert.DoesNotContain("nma_top-secret-value", text);
        Assert.Contains("noema.example.com", text);
    }

    [Fact]
    public void Saving_requires_credentials()
    {
        Assert.Throws<ArgumentNullException>(() => new FileCredentialStore(CredentialPath).Save(null!));
    }
}

public sealed class SettingsFileTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "noema-tests-" + Guid.NewGuid().ToString("N"));

    private string SettingsPath => Path.Combine(directory, "agent.settings.json");

    public void Dispose()
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Creates_the_file_with_the_server_and_ranges()
    {
        SettingsFile.Update(SettingsPath, new Uri("https://noema.example.com/"), ["192.168.1.0/24", "10.0.0.0/8"]);

        var text = File.ReadAllText(SettingsPath);
        Assert.Contains("\"ControlPlaneUrl\": \"https://noema.example.com/\"", text);
        Assert.Contains("192.168.1.0/24", text);
        Assert.Contains("10.0.0.0/8", text);
        Assert.False(File.Exists(SettingsPath + ".tmp"));
    }

    [Fact]
    public void Existing_unrelated_settings_are_kept_and_ours_are_replaced()
    {
        Directory.CreateDirectory(directory);
        File.WriteAllText(SettingsPath, "{\"Logging\":{\"LogLevel\":{\"Default\":\"Debug\"}},\"Agent\":{\"PollInterval\":\"00:00:10\",\"ControlPlaneUrl\":\"https://old.example\"},\"Scanning\":{\"Burst\":7,\"AllowedRanges\":[\"1.2.3.0/24\"]}}");

        SettingsFile.Update(SettingsPath, new Uri("https://new.example/"), ["192.168.5.0/24"]);

        var text = File.ReadAllText(SettingsPath);
        Assert.Contains("\"Default\": \"Debug\"", text);
        Assert.Contains("\"PollInterval\": \"00:00:10\"", text);
        Assert.Contains("\"Burst\": 7", text);
        Assert.Contains("https://new.example/", text);
        Assert.DoesNotContain("old.example", text);
        Assert.DoesNotContain("1.2.3.0/24", text);
        Assert.Contains("192.168.5.0/24", text);
    }

    [Fact]
    public void An_empty_range_list_is_written_as_an_empty_array()
    {
        SettingsFile.Update(SettingsPath, new Uri("https://noema.example.com/"), []);

        Assert.Contains("\"AllowedRanges\": []", File.ReadAllText(SettingsPath));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[1,2,3]")]
    public void A_settings_file_that_is_not_a_json_object_is_refused_not_overwritten(string content)
    {
        Directory.CreateDirectory(directory);
        File.WriteAllText(SettingsPath, content);

        Assert.Throws<InvalidDataException>(() => SettingsFile.Update(SettingsPath, new Uri("https://noema.example.com/"), []));
        Assert.Equal(content, File.ReadAllText(SettingsPath));
    }
}
