using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Noema.Agent.Credentials;
using Noema.Contracts;

namespace Noema.Agent.ControlPlane;

/// <summary>
/// Talks to the control plane over HTTPS using only outbound requests. HTTP failures are turned into
/// ControlPlaneException so the rest of the agent can decide what to do without knowing about HTTP.
/// </summary>
public sealed class HttpControlPlaneClient(HttpClient http) : IControlPlaneClient
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    public static HttpControlPlaneClient Create(AgentCredentials credentials, HttpMessageHandler? handler = null, TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(credentials);

        var client = handler is null ? new HttpClient() : new HttpClient(handler, disposeHandler: false);
        client.BaseAddress = credentials.ControlPlaneUrl;
        client.Timeout = timeout ?? DefaultTimeout;
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            AgentProtocol.AuthenticationScheme,
            AgentProtocol.AuthorizationValue(credentials.AgentId, credentials.AgentSecret));

        return new HttpControlPlaneClient(client);
    }

    public async Task<ClaimedJob?> ClaimAsync(ClaimRequest request, CancellationToken cancellationToken)
    {
        using var response = await PostAsync("api/v1/agent/claim", request, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.NoContent)
        {
            return null;
        }

        return await ReadAsync<ClaimedJob>(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ProgressResponse> ReportProgressAsync(Guid scanId, ProgressRequest request, CancellationToken cancellationToken)
    {
        using var response = await PostAsync($"api/v1/agent/scans/{scanId}/progress", request, cancellationToken).ConfigureAwait(false);
        return await ReadAsync<ProgressResponse>(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ObservationBatchResponse> UploadObservationsAsync(Guid scanId, ObservationBatch batch, CancellationToken cancellationToken)
    {
        using var response = await PostAsync($"api/v1/agent/scans/{scanId}/observations", batch, cancellationToken).ConfigureAwait(false);
        return await ReadAsync<ObservationBatchResponse>(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task CompleteAsync(Guid scanId, CompleteRequest request, CancellationToken cancellationToken)
    {
        using var response = await PostAsync($"api/v1/agent/scans/{scanId}/complete", request, cancellationToken).ConfigureAwait(false);
        _ = response;
    }

    /// <summary>Maps an HTTP status to what the agent should do about it.</summary>
    public static ControlPlaneErrorKind Classify(HttpStatusCode status) =>
        (int)status switch
        {
            401 or 403 => ControlPlaneErrorKind.Unauthorized,
            404 => ControlPlaneErrorKind.NotFound,
            409 => ControlPlaneErrorKind.Conflict,
            408 or 429 => ControlPlaneErrorKind.Transient,
            >= 500 => ControlPlaneErrorKind.Transient,
            _ => ControlPlaneErrorKind.Rejected
        };

    internal static async Task<HttpResponseMessage> SendAsync<T>(HttpClient http, string path, T body, CancellationToken cancellationToken)
    {
        HttpResponseMessage response;

        try
        {
            response = await http.PostAsJsonAsync(path, body, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new ControlPlaneException(ControlPlaneErrorKind.Transient, $"Could not reach the control plane: {ex.Message}", ex);
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new ControlPlaneException(ControlPlaneErrorKind.Transient, "The control plane did not answer in time.", ex);
        }

        if (response.IsSuccessStatusCode)
        {
            return response;
        }

        var exception = await ToExceptionAsync(response, cancellationToken).ConfigureAwait(false);
        response.Dispose();
        throw exception;
    }

    private Task<HttpResponseMessage> PostAsync<T>(string path, T body, CancellationToken cancellationToken) =>
        SendAsync(http, path, body, cancellationToken);

    private static async Task<T> ReadAsync<T>(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            var value = await response.Content.ReadFromJsonAsync<T>(cancellationToken).ConfigureAwait(false);
            return value ?? throw new ControlPlaneException(ControlPlaneErrorKind.Rejected, "The control plane sent an empty answer.");
        }
        catch (JsonException ex)
        {
            throw new ControlPlaneException(ControlPlaneErrorKind.Rejected, "The control plane sent an answer this agent does not understand.", ex);
        }
    }

    private static async Task<ControlPlaneException> ToExceptionAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var kind = Classify(response.StatusCode);
        var detail = await TryReadTitleAsync(response, cancellationToken).ConfigureAwait(false);
        var message = $"The control plane answered {(int)response.StatusCode}" + (detail is null ? "." : $": {detail}");

        return new ControlPlaneException(kind, message);
    }

    private static async Task<string?> TryReadTitleAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(text) || text.Length > 8192)
            {
                return null;
            }

            using var document = JsonDocument.Parse(text);
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("title", out var title)
                && title.ValueKind == JsonValueKind.String
                    ? title.GetString()
                    : null;
        }
        catch (Exception ex) when (ex is JsonException or HttpRequestException or InvalidOperationException)
        {
            return null;
        }
    }
}

/// <summary>Enrollment happens before the agent has a credential, so it is separate from the authenticated client.</summary>
public static class ControlPlaneEnrollment
{
    public static async Task<EnrollResponse> EnrollAsync(HttpClient http, EnrollRequest request, CancellationToken cancellationToken)
    {
        using var response = await HttpControlPlaneClient.SendAsync(http, "api/v1/agent/enroll", request, cancellationToken).ConfigureAwait(false);

        try
        {
            var body = await response.Content.ReadFromJsonAsync<EnrollResponse>(cancellationToken).ConfigureAwait(false);
            return body ?? throw new ControlPlaneException(ControlPlaneErrorKind.Rejected, "The control plane sent an empty answer.");
        }
        catch (JsonException ex)
        {
            throw new ControlPlaneException(ControlPlaneErrorKind.Rejected, "The control plane sent an answer this agent does not understand.", ex);
        }
    }
}
