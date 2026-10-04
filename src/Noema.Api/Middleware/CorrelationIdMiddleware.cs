namespace Noema.Api.Middleware;

public sealed class CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
{
    public const string HeaderName = "X-Correlation-Id";
    public const int MaxLength = 64;

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = Resolve(context.Request.Headers[HeaderName].ToString());

        context.TraceIdentifier = correlationId;
        context.Response.Headers[HeaderName] = correlationId;

        using (logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = correlationId }))
        {
            await next(context);
        }
    }

    /// <summary>
    /// Keeps a caller supplied id only when it is short and made of safe characters,
    /// otherwise generates a new one. This stops log injection through the header.
    /// </summary>
    public static string Resolve(string? incoming)
    {
        if (!string.IsNullOrWhiteSpace(incoming)
            && incoming.Length <= MaxLength
            && incoming.All(IsAllowed))
        {
            return incoming;
        }

        return Guid.NewGuid().ToString("N");
    }

    private static bool IsAllowed(char c) => char.IsAsciiLetterOrDigit(c) || c is '-' or '_';
}
