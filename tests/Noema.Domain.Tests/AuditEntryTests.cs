using System.Net;

namespace Noema.Domain.Tests;

public sealed class AuditEntryTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Creates_an_entry_with_all_fields()
    {
        var actor = Guid.NewGuid();

        var entry = AuditEntry.Create(
            "auth.login.failed", AuditOutcome.Failure, T0, actor, "latif", "user", "abc",
            "{\"reason\":\"bad_password\"}", IPAddress.Parse("::ffff:192.168.1.5"), "corr-1");

        Assert.NotEqual(Guid.Empty, entry.Id);
        Assert.Equal("auth.login.failed", entry.Action);
        Assert.Equal(AuditOutcome.Failure, entry.Outcome);
        Assert.Equal(actor, entry.ActorUserId);
        Assert.Equal("latif", entry.ActorName);
        Assert.Equal("user", entry.TargetType);
        Assert.Equal("abc", entry.TargetId);
        Assert.Equal(IPAddress.Parse("192.168.1.5"), entry.RemoteAddress);
        Assert.Equal("corr-1", entry.CorrelationId);
        Assert.Equal(T0, entry.OccurredAt);
    }

    [Theory]
    [InlineData("auth.login.succeeded")]
    [InlineData("scan.requested")]
    [InlineData("auth.refresh.reuse_detected")]
    public void Accepts_well_formed_actions(string action)
    {
        Assert.Equal(action, AuditEntry.Create(action, AuditOutcome.Success, T0).Action);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("login")]
    [InlineData("Auth.Login")]
    [InlineData("auth..login")]
    [InlineData("auth.login failed")]
    [InlineData(".auth.login")]
    [InlineData("auth.login.")]
    [InlineData("1auth.login")]
    public void Rejects_malformed_actions(string? action)
    {
        Assert.Throws<ArgumentException>(() => AuditEntry.Create(action!, AuditOutcome.Success, T0));
    }

    [Fact]
    public void Rejects_overlong_actions()
    {
        Assert.Throws<ArgumentException>(() => AuditEntry.Create("auth." + new string('a', 70), AuditOutcome.Success, T0));
    }

    [Fact]
    public void Rejects_unknown_outcomes_and_non_utc_times()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => AuditEntry.Create("auth.login", (AuditOutcome)9, T0));
        Assert.Throws<ArgumentException>(() =>
            AuditEntry.Create("auth.login", AuditOutcome.Success, new DateTimeOffset(2026, 10, 4, 14, 0, 0, TimeSpan.FromHours(2))));
    }

    [Fact]
    public void Trims_blank_fields_to_null_and_truncates_long_text()
    {
        var entry = AuditEntry.Create(
            "auth.login", AuditOutcome.Success, T0, null, "   ", " ", null, null, null, new string('c', 200));

        Assert.Null(entry.ActorName);
        Assert.Null(entry.TargetType);
        Assert.Equal(64, entry.CorrelationId!.Length);
    }

    [Fact]
    public void Validates_detail_json_and_size()
    {
        Assert.Throws<ArgumentException>(() => AuditEntry.Create("auth.login", AuditOutcome.Success, T0, detailJson: "not json"));
        Assert.Throws<ArgumentException>(() => AuditEntry.Create(
            "auth.login", AuditOutcome.Success, T0, detailJson: "\"" + new string('a', AuditEntry.MaxDetailLength) + "\""));
        Assert.Null(AuditEntry.Create("auth.login", AuditOutcome.Success, T0, detailJson: "  ").DetailJson);
    }
}
