using Davids.Services.AdminIdentity.Core.Entities;

namespace Davids.Services.AdminIdentity.Application.DTO;

public sealed record AdminUserDto(
    Guid Id,
    string Email,
    string FullName,
    string Role,
    bool IsActive,
    DateTime CreatedAt)
{
    public static AdminUserDto FromEntity(AdminUser admin)
        => new(admin.Id, admin.Email, admin.FullName, admin.Role, admin.IsActive, admin.CreatedAt);
}

public sealed record AdminLoginRequestMetadata(
    string? ClientId = null,
    string? ClientIpAddress = null,
    string? UserAgent = null,
    string? CorrelationId = null);

public sealed record AdminLoginAuditDto(
    Guid Id,
    DateTime OccurredAtUtc,
    Guid? AdminUserId,
    string Email,
    bool Succeeded,
    string Outcome,
    string? FailureReason,
    string? ClientId,
    string? ClientIpAddress,
    string? UserAgent,
    string? CorrelationId)
{
    public static AdminLoginAuditDto FromEntity(AdminLoginAuditEntry entry)
        => new(
            entry.Id,
            entry.OccurredAtUtc,
            entry.AdminUserId,
            entry.Email,
            entry.Succeeded,
            entry.Outcome,
            entry.FailureReason,
            entry.ClientId,
            entry.ClientIpAddress,
            entry.UserAgent,
            entry.CorrelationId);
}
