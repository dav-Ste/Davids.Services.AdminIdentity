namespace Davids.Services.AdminIdentity.Application.Commands;

public sealed record CreateAdminUser(
    Guid AdminId,
    string Email,
    string Password,
    string? FullName = null);
