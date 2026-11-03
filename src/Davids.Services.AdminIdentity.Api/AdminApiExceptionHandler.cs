using Davids.Services.AdminIdentity.Core.Exceptions;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.IdentityModel.Tokens;

namespace Davids.Services.AdminIdentity.Api;

public sealed class AdminApiExceptionHandler(ILogger<AdminApiExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        if (exception is OperationCanceledException && httpContext.RequestAborted.IsCancellationRequested)
        {
            if (!httpContext.Response.HasStarted)
            {
                httpContext.Response.StatusCode = StatusCodes.Status499ClientClosedRequest;
            }

            return true;
        }

        var (status, code, reason) = exception switch
        {
            AdminNotFoundException ex => (StatusCodes.Status404NotFound, ex.Code, ex.Message),
            AdminEmailInUseException ex => (StatusCodes.Status409Conflict, ex.Code, ex.Message),
            LastActiveAdminException ex => (StatusCodes.Status409Conflict, ex.Code, ex.Message),
            AdminAccountDisabledException ex => (StatusCodes.Status403Forbidden, ex.Code, ex.Message),
            AdminAccountLockedException ex => (StatusCodes.Status429TooManyRequests, ex.Code, ex.Message),
            AdminDomainException ex => (StatusCodes.Status400BadRequest, ex.Code, ex.Message),
            SecurityTokenException => (StatusCodes.Status400BadRequest, "invalid_access_token", "The provided administrator access token is invalid."),
            ArgumentException => (StatusCodes.Status400BadRequest, "invalid_request", "Invalid request."),
            InvalidDataException => (StatusCodes.Status400BadRequest, "invalid_request", "Malformed request payload."),
            BadHttpRequestException => (StatusCodes.Status400BadRequest, "invalid_request", "Invalid request body or parameters."),
            _ => (0, null, null)
        };

        if (status == 0)
        {
            logger.LogError(exception, "Unhandled exception in Davids.Services.AdminIdentity.");
            return false;
        }

        httpContext.Response.StatusCode = status;
        await httpContext.Response.WriteAsJsonAsync(new { code, reason }, cancellationToken);
        return true;
    }
}
