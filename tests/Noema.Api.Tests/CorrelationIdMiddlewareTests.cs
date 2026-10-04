using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Noema.Api.Middleware;

namespace Noema.Api.Tests;

public sealed class CorrelationIdMiddlewareTests
{
    [Theory]
    [InlineData("abc-123_XYZ")]
    [InlineData("0f8fad5bd9cb469fa16570867728950e")]
    public void Resolve_keeps_a_safe_incoming_id(string incoming)
    {
        Assert.Equal(incoming, CorrelationIdMiddleware.Resolve(incoming));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("bad id with spaces")]
    [InlineData("line\r\nbreak")]
    [InlineData("<script>alert(1)</script>")]
    public void Resolve_replaces_missing_or_unsafe_ids(string? incoming)
    {
        var resolved = CorrelationIdMiddleware.Resolve(incoming);

        Assert.NotEqual(incoming, resolved);
        Assert.Equal(32, resolved.Length);
        Assert.True(Guid.TryParseExact(resolved, "N", out _));
    }

    [Fact]
    public void Resolve_replaces_ids_that_are_too_long()
    {
        var tooLong = new string('a', CorrelationIdMiddleware.MaxLength + 1);

        Assert.NotEqual(tooLong, CorrelationIdMiddleware.Resolve(tooLong));
    }

    [Fact]
    public async Task InvokeAsync_sets_trace_identifier_and_response_header()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers[CorrelationIdMiddleware.HeaderName] = "caller-supplied-1";
        var middleware = new CorrelationIdMiddleware(_ => Task.CompletedTask, NullLogger<CorrelationIdMiddleware>.Instance);

        await middleware.InvokeAsync(context);

        Assert.Equal("caller-supplied-1", context.TraceIdentifier);
        Assert.Equal("caller-supplied-1", context.Response.Headers[CorrelationIdMiddleware.HeaderName].ToString());
    }

    [Fact]
    public async Task InvokeAsync_generates_an_id_when_none_is_sent()
    {
        var context = new DefaultHttpContext();
        var middleware = new CorrelationIdMiddleware(_ => Task.CompletedTask, NullLogger<CorrelationIdMiddleware>.Instance);

        await middleware.InvokeAsync(context);

        var header = context.Response.Headers[CorrelationIdMiddleware.HeaderName].ToString();
        Assert.False(string.IsNullOrEmpty(header));
        Assert.Equal(header, context.TraceIdentifier);
    }
}
