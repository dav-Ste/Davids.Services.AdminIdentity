using System.Text.Json;
using System.Text.Json.Serialization;
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
    public DateTime? LockoutEndUtc { get; init; }
    public bool IsLockedOut => LockoutEndUtc.HasValue && LockoutEndUtc.Value > DateTime.UtcNow;

    public static AdminUserDto FromEntity(AdminUser admin)
        => new(admin.Id, admin.Email, admin.FullName, admin.Role, admin.IsActive, admin.CreatedAt)
        {
            LockoutEndUtc = admin.LockoutEndUtc
        };
}

public sealed record AdminActorMetadata(
    Guid ActorAdminUserId,
    string? ActorEmail,
    string ActorRole,
    string? CorrelationId = null,
    string? CurrentAccessTokenJti = null,
    DateTime? CurrentAccessTokenExpiresAtUtc = null);

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

public sealed record AdminFieldChangeDto(
    [property: JsonPropertyName("field")] string Field,
    [property: JsonPropertyName("oldValue")] string? OldValue,
    [property: JsonPropertyName("newValue")] string? NewValue);

public sealed record AdminChangeAuditDto(
    Guid Id,
    string Service,
    string Action,
    string TargetType,
    string TargetId,
    string? TargetLabel,
    string ActorSub,
    string? ActorEmail,
    string ActorRole,
    string ActorAuthority,
    IReadOnlyList<AdminFieldChangeDto> Changes,
    string? CorrelationId,
    DateTime OccurredAtUtc)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static AdminChangeAuditDto FromEntity(AdminChangeAuditEntry entry)
    {
        var changes = string.IsNullOrWhiteSpace(entry.ChangedFieldsJson)
            ? []
            : JsonSerializer.Deserialize<List<AdminFieldChangeDto>>(entry.ChangedFieldsJson, JsonOptions) ?? [];

        return new AdminChangeAuditDto(
            entry.Id,
            "admin-identity",
            entry.Action,
            "employee_account",
            entry.TargetAdminUserId.ToString("D"),
            entry.TargetEmail,
            entry.ActorAdminUserId.ToString("D"),
            entry.ActorEmail,
            entry.ActorRole,
            "employee",
            changes,
            entry.CorrelationId,
            entry.OccurredAtUtc);
    }
}
