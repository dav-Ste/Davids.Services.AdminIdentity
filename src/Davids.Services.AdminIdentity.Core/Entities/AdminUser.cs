using System.Net.Mail;
using Davids.Services.AdminIdentity.Core.Exceptions;

namespace Davids.Services.AdminIdentity.Core.Entities;

public sealed class AdminUser
{
    public const string AdminRole = "admin";
    public const string SupportRole = "support";
    public const string AuditorRole = "auditor";

    public static readonly IReadOnlyList<string> ValidRoles =
    [
        AdminRole,
        SupportRole,
        AuditorRole
    ];

    public Guid Id { get; }
    public string Email { get; }
    public string PasswordHash { get; private set; }
    public string FullName { get; private set; }
    public string Role { get; private set; }
    public bool IsActive { get; private set; }
    public DateTime CreatedAt { get; }
    public int FailedLoginCount { get; private set; }
    public DateTime? LockoutEndUtc { get; private set; }

    public AdminUser(
        Guid id,
        string email,
        string passwordHash,
        string? fullName,
        bool isActive,
        DateTime createdAt,
        int failedLoginCount = 0,
        DateTime? lockoutEndUtc = null,
        string? role = null)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("Administrator ID cannot be empty.", nameof(id));
        }

        Email = NormalizeAndValidateEmail(email);

        if (string.IsNullOrWhiteSpace(passwordHash))
        {
            throw new InvalidAdminPasswordException();
        }

        var trimmedName = ValidateAndTrimFullName(fullName);
        var normalizedRole = string.IsNullOrWhiteSpace(role)
            ? AdminRole
            : NormalizeAndValidateRole(role);

        Id = id;
        PasswordHash = passwordHash;
        FullName = trimmedName;
        Role = normalizedRole;
        IsActive = isActive;
        CreatedAt = createdAt;
        FailedLoginCount = Math.Max(0, failedLoginCount);
        LockoutEndUtc = lockoutEndUtc;
    }

    public bool IsLockedOut(DateTime utcNow)
        => LockoutEndUtc.HasValue && LockoutEndUtc.Value > utcNow;

    public bool RecordFailedLogin(DateTime utcNow, int maxFailedAccessAttempts, TimeSpan lockoutDuration)
    {
        if (LockoutEndUtc.HasValue && LockoutEndUtc.Value <= utcNow)
        {
            LockoutEndUtc = null;
            FailedLoginCount = 0;
        }

        FailedLoginCount++;
        var threshold = Math.Max(1, maxFailedAccessAttempts);
        if (FailedLoginCount >= threshold)
        {
            LockoutEndUtc = utcNow.Add(lockoutDuration <= TimeSpan.Zero ? TimeSpan.FromMinutes(15) : lockoutDuration);
            FailedLoginCount = 0;
            return true;
        }

        return false;
    }

    public void ResetFailedLogins()
    {
        FailedLoginCount = 0;
        LockoutEndUtc = null;
    }

    public void ChangePasswordHash(string newPasswordHash)
    {
        if (string.IsNullOrWhiteSpace(newPasswordHash))
        {
            throw new InvalidAdminPasswordException();
        }

        PasswordHash = newPasswordHash;
        ResetFailedLogins();
    }

    public void UpdateProfileAndAccess(string? role, bool? isActive, string? fullName)
    {
        if (role is not null)
        {
            Role = NormalizeAndValidateRole(role);
        }

        if (isActive.HasValue)
        {
            IsActive = isActive.Value;
        }

        if (fullName is not null)
        {
            FullName = ValidateAndTrimFullName(fullName);
        }
    }

    public static bool IsValidWorkforceRole(string? role)
    {
        if (string.IsNullOrWhiteSpace(role))
        {
            return false;
        }

        var candidate = role.Trim();
        return string.Equals(candidate, AdminRole, StringComparison.Ordinal) ||
               string.Equals(candidate, SupportRole, StringComparison.Ordinal) ||
               string.Equals(candidate, AuditorRole, StringComparison.Ordinal);
    }

    public static string NormalizeAndValidateRole(string? role)
    {
        if (string.IsNullOrWhiteSpace(role))
        {
            throw new InvalidAdminRoleException(role);
        }

        var normalized = role.Trim().ToLowerInvariant();
        if (normalized is not (AdminRole or SupportRole or AuditorRole))
        {
            throw new InvalidAdminRoleException(role);
        }

        return normalized;
    }

    private static string ValidateAndTrimFullName(string? fullName)
    {
        if (fullName is not null && (fullName.EnumerateRunes().Count() > 100 || fullName.Contains('\0')))
        {
            throw new InvalidAdminFullNameException();
        }

        var trimmedName = fullName?.Trim() ?? string.Empty;
        if (trimmedName.EnumerateRunes().Count() > 100 || trimmedName.Contains('\0'))
        {
            throw new InvalidAdminFullNameException();
        }

        return trimmedName;
    }

    private static readonly System.Text.RegularExpressions.Regex StrictEmailRegex = new(
        @"^[A-Za-z0-9_%+\-]{1,20}(?:\.[A-Za-z0-9_%+\-]{1,20}){0,2}@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,30}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$",
        System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    public static string NormalizeAndValidateEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            throw new InvalidAdminEmailException(email);
        }

        if (!string.Equals(email, email.Trim(), StringComparison.Ordinal))
        {
            throw new InvalidAdminEmailException(email);
        }

        var normalized = email.ToLowerInvariant();
        var atIndex = normalized.IndexOf('@');
        if (normalized.Length < 6 || normalized.Length > 254 ||
            atIndex < 1 || atIndex > 64 || normalized.Contains('\0'))
        {
            throw new InvalidAdminEmailException(email);
        }

        try
        {
            var parsed = new MailAddress(normalized);
            if (!string.Equals(parsed.Address, normalized, StringComparison.OrdinalIgnoreCase) ||
                !StrictEmailRegex.IsMatch(normalized))
            {
                throw new InvalidAdminEmailException(email);
            }
        }
        catch (FormatException)
        {
            throw new InvalidAdminEmailException(email);
        }
        catch (System.Text.RegularExpressions.RegexMatchTimeoutException)
        {
            throw new InvalidAdminEmailException(email);
        }

        return normalized;
    }
}
