using System.Collections.Concurrent;
using Noema.Scanning;

namespace Noema.Agent.Jobs;

/// <summary>Holds what the engine finds until the runner has uploaded it, so scanning never waits on the network.</summary>
public sealed class BufferingObservationSink : IObservationSink
{
    private readonly ConcurrentQueue<ProbeObservation> queue = new();

    public int Count => queue.Count;

    public ValueTask WriteAsync(ProbeObservation observation, CancellationToken cancellationToken)
    {
        queue.Enqueue(observation);
        return ValueTask.CompletedTask;
    }

    /// <summary>Removes and returns up to max items, oldest first.</summary>
    public IReadOnlyList<ProbeObservation> Take(int max)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(max, 1);

        var taken = new List<ProbeObservation>(Math.Min(max, queue.Count));
        while (taken.Count < max && queue.TryDequeue(out var item))
        {
            taken.Add(item);
        }

        return taken;
    }
}

/// <summary>Remembers the latest progress the engine reported so the runner can pass it on.</summary>
public sealed class ProgressTracker : IProgress<ScanProgress>
{
    private ScanProgress latest = new(0, 0, 0);

    public void Report(ScanProgress value) => Volatile.Write(ref latest, value);

    public ScanProgress Snapshot() => Volatile.Read(ref latest);
}
