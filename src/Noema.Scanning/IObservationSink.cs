namespace Noema.Scanning;

/// <summary>Where the engine delivers what it finds. The engine calls it one write at a time, so it need not be thread safe.</summary>
public interface IObservationSink
{
    ValueTask WriteAsync(ProbeObservation observation, CancellationToken cancellationToken);
}
