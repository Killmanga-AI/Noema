using System.Text.Json;
using System.Text.Json.Nodes;

namespace Noema.Agent;

/// <summary>
/// The agent's local settings file, written once by the enroll command so the service knows which server to talk
/// to and which ranges it may scan. Anything else already in the file is left alone.
/// </summary>
public static class SettingsFile
{
    public static void Update(string path, Uri controlPlaneUrl, IReadOnlyList<string> allowedRanges)
    {
        JsonObject root;
        if (File.Exists(path))
        {
            try
            {
                root = JsonNode.Parse(File.ReadAllText(path)) as JsonObject
                    ?? throw new InvalidDataException($"The settings file {path} is not a JSON object.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException($"The settings file {path} is not valid JSON.", ex);
            }
        }
        else
        {
            root = new JsonObject();
        }

        Section(root, "Agent")["ControlPlaneUrl"] = controlPlaneUrl.ToString();

        var ranges = new JsonArray();
        foreach (var range in allowedRanges)
        {
            ranges.Add(range);
        }

        Section(root, "Scanning")["AllowedRanges"] = ranges;

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            root.WriteTo(writer);
        }

        var temporary = path + ".tmp";
        File.WriteAllBytes(temporary, buffer.ToArray());
        File.Move(temporary, path, overwrite: true);
    }

    private static JsonObject Section(JsonObject root, string name)
    {
        if (root[name] is JsonObject existing)
        {
            return existing;
        }

        var created = new JsonObject();
        root[name] = created;
        return created;
    }
}
