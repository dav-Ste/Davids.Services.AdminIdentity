using System.Net.Mail;
using Davids.Services.AdminIdentity.Core.Exceptions;

namespace Davids.Services.AdminIdentity.Core.Entities;

public sealed class AdminUser
{
    public const string AdminRole = "admin";

    public Guid Id { get; }
    public string Email { get; }
    public string PasswordHash { get; }
    public string FullName { get; }
    public string Role => AdminRole;
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
        DateTime? lockoutEndUtc = null)
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

        if (fullName is not null && (fullName.Length > 200 || fullName.Contains('\0')))
        {
            throw new InvalidAdminFullNameException();
        }

        var trimmedName = fullName?.Trim() ?? string.Empty;
        if (trimmedName.Length > 200 || trimmedName.Contains('\0'))
        {
            throw new InvalidAdminFullNameException();
        }

        Id = id;
        PasswordHash = passwordHash;
        FullName = trimmedName;
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

        var normalized = email.Trim().ToLowerInvariant();
        var atIndex = normalized.IndexOf('@');
        if (email.Length < 6 || email.Length > 254 || normalized.Length < 6 || normalized.Length > 254 ||
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
