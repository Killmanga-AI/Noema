using System.Net;

namespace Noema.Api.Security;

public interface IRequestContext
{
    IPAddress? RemoteAddress { get; }

    string? CorrelationId { get; }
}

internal sealed class HttpRequestContext(IHttpContextAccessor accessor) : IRequestContext
{
    public IPAddress? RemoteAddress => accessor.HttpContext?.Connection.RemoteIpAddress;

    public string? CorrelationId => accessor.HttpContext?.TraceIdentifier;
}
