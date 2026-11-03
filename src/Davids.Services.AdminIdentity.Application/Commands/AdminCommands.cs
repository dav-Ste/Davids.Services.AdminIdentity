namespace Davids.Services.AdminIdentity.Application.Commands;

public sealed record CreateAdminUser(
    Guid AdminId,
    string Email,
    string Password,
    string? FullName = null,
    string? Role = null);

public sealed record ChangeAdminPassword(
    string CurrentPassword,
    string NewPassword);

public sealed record UpdateAdminUser(
    string? Role = null,
    bool? IsActive = null,
    string? FullName = null);
