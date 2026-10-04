namespace Noema.Api.Common;

public enum ErrorKind
{
    Validation,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict
}

public sealed record ServiceError(ErrorKind Kind, string Title, IReadOnlyDictionary<string, string[]>? Errors = null);

public readonly record struct Unit;

public sealed class ServiceResult<T>
{
    private ServiceResult(T? value, ServiceError? error)
    {
        Value = value;
        Error = error;
    }

    public T? Value { get; }

    public ServiceError? Error { get; }

    public bool IsSuccess => Error is null;

    public static ServiceResult<T> Ok(T value) => new(value, null);

    public static ServiceResult<T> Fail(ServiceError error) => new(default, error);
}

public static class ServiceErrors
{
    public static ServiceError Validation(string field, string message) =>
        new(ErrorKind.Validation, "One or more validation errors occurred.", new Dictionary<string, string[]> { [field] = [message] });

    public static ServiceError Validation(IReadOnlyDictionary<string, string[]> errors) =>
        new(ErrorKind.Validation, "One or more validation errors occurred.", errors);

    public static ServiceError Unauthorized(string message) => new(ErrorKind.Unauthorized, message);

    public static ServiceError Forbidden(string message) => new(ErrorKind.Forbidden, message);

    public static ServiceError NotFound(string message) => new(ErrorKind.NotFound, message);

    public static ServiceError Conflict(string message) => new(ErrorKind.Conflict, message);
}

public static class ServiceResultExtensions
{
    public static IResult ToHttp<T>(this ServiceResult<T> result, Func<T, IResult> onSuccess)
    {
        if (result.IsSuccess)
        {
            return onSuccess(result.Value!);
        }

        var error = result.Error!;

        return error.Kind switch
        {
            ErrorKind.Validation => Results.ValidationProblem(
                error.Errors is null
                    ? new Dictionary<string, string[]> { ["request"] = [error.Title] }
                    : new Dictionary<string, string[]>(error.Errors),
                title: error.Title),
            ErrorKind.Unauthorized => Results.Problem(statusCode: StatusCodes.Status401Unauthorized, title: error.Title),
            ErrorKind.Forbidden => Results.Problem(statusCode: StatusCodes.Status403Forbidden, title: error.Title),
            ErrorKind.NotFound => Results.Problem(statusCode: StatusCodes.Status404NotFound, title: error.Title),
            ErrorKind.Conflict => Results.Problem(statusCode: StatusCodes.Status409Conflict, title: error.Title),
            _ => Results.Problem(statusCode: StatusCodes.Status500InternalServerError, title: "Unexpected error.")
        };
    }
}
