namespace Davids.Services.AdminIdentity.Core.Entities;

public sealed class AdminChangeAuditEntry
{
    public Guid Id { get; }
    public DateTime OccurredAtUtc { get; }
    public Guid TargetAdminUserId { get; }
    public string TargetEmail { get; }
    public string Action { get; }
    public Guid ActorAdminUserId { get; }
    public string? ActorEmail { get; }
    public string ActorRole { get; }
    public string ChangedFieldsJson { get; }
    public string? CorrelationId { get; }

    public AdminChangeAuditEntry(
        Guid id,
        DateTime occurredAtUtc,
        Guid targetAdminUserId,
        string targetEmail,
        string action,
        Guid actorAdminUserId,
        string? actorEmail,
        string actorRole,
        string changedFieldsJson,
        string? correlationId)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("Change audit ID cannot be empty.", nameof(id));
        }

        if (targetAdminUserId == Guid.Empty)
        {
            throw new ArgumentException("Target employee ID cannot be empty.", nameof(targetAdminUserId));
        }

        if (actorAdminUserId == Guid.Empty)
        {
            throw new ArgumentException("Actor employee ID cannot be empty.", nameof(actorAdminUserId));
        }

        if (string.IsNullOrWhiteSpace(action))
        {
            throw new ArgumentException("Audit action cannot be empty.", nameof(action));
        }

        Id = id;
        OccurredAtUtc = occurredAtUtc;
        TargetAdminUserId = targetAdminUserId;
        TargetEmail = Truncate(targetEmail?.Trim() ?? string.Empty, 320);
        Action = Truncate(action.Trim(), 64);
        ActorAdminUserId = actorAdminUserId;
        ActorEmail = string.IsNullOrWhiteSpace(actorEmail) ? null : Truncate(actorEmail.Trim(), 320);
        ActorRole = Truncate(string.IsNullOrWhiteSpace(actorRole) ? AdminUser.AdminRole : actorRole.Trim(), 32);
        ChangedFieldsJson = string.IsNullOrWhiteSpace(changedFieldsJson) ? "[]" : changedFieldsJson;
        CorrelationId = string.IsNullOrWhiteSpace(correlationId) ? null : Truncate(correlationId.Trim(), 128);
    }

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];
}
