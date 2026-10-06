namespace Noema.Agent.ControlPlane;

public enum ControlPlaneErrorKind
{
    /// <summary>The credential was refused. The agent may have been revoked.</summary>
    Unauthorized,

    /// <summary>The control plane no longer knows the scan, or it belongs to someone else.</summary>
    NotFound,

    /// <summary>The scan is no longer in a state that accepts this, for example it was cancelled or timed out.</summary>
    Conflict,

    /// <summary>The control plane refused the content as invalid. Sending it again will not help.</summary>
    Rejected,

    /// <summary>Network trouble or a busy server. Trying again later is reasonable.</summary>
    Transient
}

public sealed class ControlPlaneException(ControlPlaneErrorKind kind, string message, Exception? inner = null)
    : Exception(message, inner)
{
    public ControlPlaneErrorKind Kind { get; } = kind;
}
