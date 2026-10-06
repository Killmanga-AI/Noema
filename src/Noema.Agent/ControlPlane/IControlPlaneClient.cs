using Noema.Contracts;

namespace Noema.Agent.ControlPlane;

/// <summary>The agent's side of the conversation with the control plane. Every call is made as the enrolled agent.</summary>
public interface IControlPlaneClient
{
    /// <summary>Checks in and asks for work. Returns null when there is nothing to do.</summary>
    Task<ClaimedJob?> ClaimAsync(ClaimRequest request, CancellationToken cancellationToken);

    Task<ProgressResponse> ReportProgressAsync(Guid scanId, ProgressRequest request, CancellationToken cancellationToken);

    Task<ObservationBatchResponse> UploadObservationsAsync(Guid scanId, ObservationBatch batch, CancellationToken cancellationToken);

    Task CompleteAsync(Guid scanId, CompleteRequest request, CancellationToken cancellationToken);
}
