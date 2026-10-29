using Davids.Services.AdminIdentity.Core.Entities;
using Davids.Services.AdminIdentity.Core.Repositories;
using Davids.Services.AdminIdentity.Infrastructure.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Davids.Services.AdminIdentity.Infrastructure.Persistence;

public sealed class AdminUserRepository(AdminIdentityDbContext db) : IAdminUserRepository
{
    public async Task<AdminUser?> GetAsync(Guid id, CancellationToken cancellationToken = default)
        => Map(await db.AdminUsers.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, cancellationToken));

    public async Task<AdminUser?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        var normalized = email.Trim().ToLowerInvariant();
        return Map(await db.AdminUsers.AsNoTracking().SingleOrDefaultAsync(x => x.Email == normalized, cancellationToken));
    }

    public async Task<IReadOnlyList<AdminUser>> BrowseAsync(CancellationToken cancellationToken = default)
    {
        var rows = await db.AdminUsers.AsNoTracking()
            .OrderByDescending(x => x.CreatedAt)
            .ToListAsync(cancellationToken);
        return rows.Select(r => Map(r)!).ToArray();
    }

    public async Task AddAsync(AdminUser adminUser, CancellationToken cancellationToken = default)
    {
        db.AdminUsers.Add(new AdminUserRow
        {
            Id = adminUser.Id,
            Email = adminUser.Email,
            PasswordHash = adminUser.PasswordHash,
            FullName = adminUser.FullName,
            IsActive = adminUser.IsActive,
            CreatedAt = adminUser.CreatedAt,
            FailedLoginCount = adminUser.FailedLoginCount,
            LockoutEndUtc = adminUser.LockoutEndUtc
        });
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task UpdateAsync(AdminUser adminUser, CancellationToken cancellationToken = default)
    {
        var row = await db.AdminUsers.SingleOrDefaultAsync(x => x.Id == adminUser.Id, cancellationToken)
            ?? throw new InvalidOperationException($"Administrator '{adminUser.Id}' was not found.");
        row.IsActive = adminUser.IsActive;
        row.FailedLoginCount = adminUser.FailedLoginCount;
        row.LockoutEndUtc = adminUser.LockoutEndUtc;
        await db.SaveChangesAsync(cancellationToken);
    }

    private static AdminUser? Map(AdminUserRow? row)
        => row is null
            ? null
            : new AdminUser(
                row.Id,
                row.Email,
                row.PasswordHash,
                row.FullName,
                row.IsActive,
                DateTime.SpecifyKind(row.CreatedAt, DateTimeKind.Utc),
                row.FailedLoginCount,
                row.LockoutEndUtc.HasValue ? DateTime.SpecifyKind(row.LockoutEndUtc.Value, DateTimeKind.Utc) : null);
}

public sealed class AdminLoginAuditRepository(
    AdminIdentityDbContext db,
    ILoggerFactory? loggerFactory = null) : IAdminLoginAuditRepository
{
    public async Task AddAsync(AdminLoginAuditEntry entry, CancellationToken cancellationToken = default)
    {
        db.AdminLoginAuditLogs.Add(new AdminLoginAuditLogRow
        {
            Id = entry.Id,
            OccurredAtUtc = entry.OccurredAtUtc,
            AdminUserId = entry.AdminUserId,
            Email = entry.Email,
            Succeeded = entry.Succeeded,
            Outcome = entry.Outcome,
            FailureReason = entry.FailureReason,
            ClientId = entry.ClientId,
            ClientIpAddress = entry.ClientIpAddress,
            UserAgent = entry.UserAgent,
            CorrelationId = entry.CorrelationId
        });
        await db.SaveChangesAsync(cancellationToken);

        AdminIdentitySecurityMetrics.RecordLoginAudit(entry.Outcome, entry.Succeeded);
        var auditLogger = loggerFactory?.CreateLogger("Davids.Security.Audit");
        if (entry.Succeeded)
        {
            auditLogger?.LogInformation(
                "Audit: recorded {AuthDomain} login outcome {Outcome} (Succeeded={Succeeded}, SecurityAuditEvent={SecurityAuditEvent}, ClientId={ClientId}, ClientIp={ClientIp}, CorrelationId={CorrelationId}).",
                "admin",
                entry.Outcome,
                true,
                "LoginAudit",
                entry.ClientId ?? "unknown",
                entry.ClientIpAddress ?? "unknown",
                entry.CorrelationId ?? "none");
        }
        else
        {
            auditLogger?.LogWarning(
                "Audit: recorded {AuthDomain} login failure {Outcome} (Succeeded={Succeeded}, SecurityAuditEvent={SecurityAuditEvent}, ClientId={ClientId}, ClientIp={ClientIp}, CorrelationId={CorrelationId}).",
                "admin",
                entry.Outcome,
                false,
                "LoginAudit",
                entry.ClientId ?? "unknown",
                entry.ClientIpAddress ?? "unknown",
                entry.CorrelationId ?? "none");
        }
    }

    public async Task<IReadOnlyList<AdminLoginAuditEntry>> BrowseRecentAsync(
        int limit = 100,
        bool? succeeded = null,
        string? email = null,
        CancellationToken cancellationToken = default)
    {
        var clamped = Math.Clamp(limit, 1, 500);
        IQueryable<AdminLoginAuditLogRow> query = db.AdminLoginAuditLogs.AsNoTracking();

        if (succeeded.HasValue)
        {
            query = query.Where(x => x.Succeeded == succeeded.Value);
        }

        if (!string.IsNullOrWhiteSpace(email))
        {
            var normalized = email.Trim().ToLowerInvariant();
            query = query.Where(x => x.Email == normalized);
        }

        var rows = await query
            .OrderByDescending(x => x.OccurredAtUtc)
            .ThenByDescending(x => x.Id)
            .Take(clamped)
            .ToListAsync(cancellationToken);

        return rows.Select(Map).ToArray();
    }

    private static AdminLoginAuditEntry Map(AdminLoginAuditLogRow row)
        => new(
            row.Id,
            DateTime.SpecifyKind(row.OccurredAtUtc, DateTimeKind.Utc),
            row.AdminUserId,
            row.Email,
            row.Succeeded,
            row.Outcome,
            row.FailureReason,
            row.ClientId,
            row.ClientIpAddress,
            row.UserAgent,
            row.CorrelationId);
}
