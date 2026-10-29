using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Davids.Services.AdminIdentity.Infrastructure.Persistence;

public sealed class AdminDatabaseHealthCheck(AdminIdentityDbContext db) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            return await db.Database.CanConnectAsync(cancellationToken)
                ? HealthCheckResult.Healthy()
                : HealthCheckResult.Unhealthy("Cannot connect to adminidentitydb.");
        }
        catch (OperationCanceledException)
        {
            return HealthCheckResult.Unhealthy("Health check canceled.");
        }
    }
}
