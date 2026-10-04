namespace Noema.Scanning;

public enum ProbeStatus
{
    /// <summary>The host answered. Observations carry what it said.</summary>
    Responded,

    /// <summary>Nothing came back, which is the normal answer for an empty address.</summary>
    NoResponse,

    /// <summary>The probe itself could not do its job, for example a missing permission or a broken network.</summary>
    Error,

    /// <summary>The probe did not finish in time and was stopped by the engine.</summary>
    TimedOut
}

public sealed record ProbeResult
{
    private ProbeResult(ProbeStatus status, IReadOnlyList<ProbeObservation> observations, string? error)
    {
        Status = status;
        Observations = observations;
        Error = error;
    }

    public ProbeStatus Status { get; }

    public IReadOnlyList<ProbeObservation> Observations { get; }

    public string? Error { get; }

    public static ProbeResult NoResponse { get; } = new(ProbeStatus.NoResponse, [], null);

    public static ProbeResult TimedOut { get; } = new(ProbeStatus.TimedOut, [], "The probe did not finish in time.");

    public static ProbeResult Responded(params ProbeObservation[] observations) =>
        new(ProbeStatus.Responded, observations, null);

    public static ProbeResult Failure(string error) =>
        new(ProbeStatus.Error, [], string.IsNullOrWhiteSpace(error) ? "The probe failed." : error);
}
