# Security Implementation Report

This report details the implementation of security features for the Bookworms Online web application.

## 1. Membership Registration and User Data Management

### 1.1. Member Model

The `BookwormsOnline/Models/Member.cs` model is created to store user information in the database.

```csharp
using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Models
{
    public class Member
    {
        public int Id { get; set; }

        [Required, MaxLength(100)]
        public string FirstName { get; set; }

        [Required, MaxLength(100)]
        public string LastName { get; set; }

        [Required, CreditCard]
        public string CreditCardNo { get; set; }

        [Required, Phone]
        public string MobileNo { get; set; }

        [Required, MaxLength(255)]
        public string BillingAddress { get; set; }

        [Required, MaxLength(255)]
        public string ShippingAddress { get; set; }

        [Required, EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }

        public string? PhotoURL { get; set; }
    }
}
```

This model includes data annotations for basic validation, such as `[Required]`, `[MaxLength]`, `[CreditCard]`, `[Phone]`, and `[EmailAddress]`. These attributes help enforce data integrity at the model level.

### 1.2. Registration View Model and Password Complexity

The `BookwormsOnline/ViewModels/Register.cs` view model is used for the registration form. It includes password complexity validation and ensures that the password and confirmation password match.

```csharp
using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.ViewModels
{
    public class Register
    {
        [Required, MaxLength(100)]
        public string FirstName { get; set; }

        [Required, MaxLength(100)]
        public string LastName { get; set; }

        [Required, CreditCard]
        public string CreditCardNo { get; set; }

        [Required, Phone]
        public string MobileNo { get; set; }

        [Required, MaxLength(255)]
        public string BillingAddress { get; set; }

        [Required, MaxLength(255)]
        public string ShippingAddress { get; set; }

        [Required, EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{12,}$")]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }

        public IFormFile Photo { get; set; }
    }
}
```

**Security Features Implemented:**

*   **Strong Password Policy:** The `[RegularExpression]` attribute on the `Password` property enforces a strong password policy (minimum 12 characters, with uppercase, lowercase, number, and special character). This is a server-side validation.
*   **Password Confirmation:** The `[Compare]` attribute ensures that the user enters the same password in both password fields.

### 1.3. Data Encryption

Sensitive data, such as the user's credit card number, is encrypted before being stored in the database. This is accomplished using the `IDataProtectionProvider` service in ASP.NET Core.

In the `AccountController`, a protector is created with a specific purpose string. The `Protect` method is used to encrypt the data, and the `Unprotect` method is used to decrypt it when needed.

**Encryption in `AccountController.cs`:**

```csharp
_protector = dataProtectionProvider.CreateProtector("BookwormsOnline.CreditCard.v1");
// ...
var member = new Member
{
    // ...
    CreditCardNo = _protector.Protect(model.CreditCardNo),
    // ...
};
```

**Decryption in `HomeController.cs`:**

```csharp
var decryptedCreditCardNo = _protector.Unprotect(member.CreditCardNo);
```

## 2. Input Validation

### 2.1. Cross-Site Scripting (XSS) Protection

ASP.NET Core Razor views automatically encode all output from `@` expressions, which helps to prevent XSS attacks. A search of the project confirms that `Html.Raw()` is not used, so all user-provided data will be properly encoded by default.

In addition, a Content Security Policy (CSP) has been implemented in the `_Layout.cshtml` file to further mitigate the risk of XSS attacks. The CSP restricts the sources of content, such as scripts and styles, to trusted domains.

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://www.google.com https://www.gstatic.com; style-src 'self' 'unsafe-inline'; frame-src 'self' https://www.google.com;" />
<meta http-equiv="X-Content-Type-Options" content="nosniff" />
<meta http-equiv="X-Frame-Options" content="DENY" />
<meta http-equiv="X-XSS-Protection" content="1; mode=block" />
```

### 2.2. CSRF Protection

Cross-Site Request Forgery (CSRF) attacks are prevented by using the `[ValidateAntiForgeryToken]` attribute on all `[HttpPost]` actions in the `AccountController`. This ensures that all form submissions are legitimate and originate from the application itself.

### 2.3. File Upload Validation

In the `Register` action of the `AccountController`, the uploaded file is validated to ensure that it is a `.jpg` file. This helps prevent the upload of potentially malicious files.

### 2.4. Anti-Bot Protection

Google reCAPTCHA v3 is implemented on the registration page to prevent automated bot registrations. A `ReCaptchaService` is created to verify the reCAPTCHA token with Google's servers.

**reCAPTCHA Verification in `AccountController.cs`:**

```csharp
if (!await _reCaptchaService.Verify(model.recaptcha_token))
{
    ModelState.AddModelError("", "reCAPTCHA validation failed.");
    return View(model);
}
```

## 3. Session Management

### 3.1. Session Timeout

Session timeout is configured in `Program.cs` to automatically log out inactive users after a specific period. The session idle timeout is set to 1 minute.

```csharp
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(1);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});
```

## 4. Login/Logout Security

### 4.1. Rate Limiting

Rate limiting is implemented to prevent brute-force attacks on the login page. ASP.NET Core Identity's lockout feature is configured in `Program.cs` to lock out a user for 1 minute after 3 failed login attempts.

```csharp
// Lockout settings
options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
options.Lockout.MaxFailedAccessAttempts = 3;
options.Lockout.AllowedForNewUsers = true;
```

### 4.2. Audit Logging

An audit trail of user activities is implemented to track important events such as registration, login (successful and failed), and logout. The `Audit.cs` model is used to store audit information, and the `AccountController` is updated to log these events.

**Audit Log Entry Creation in `AccountController.cs`:**

```csharp
// Successful Registration
var audit = new Audit
{
    UserId = user.Id,
    Action = "Register",
    Timestamp = DateTime.UtcNow,
    Details = $"User {user.Email} registered successfully."
};
_context.AuditLogs.Add(audit);

// Successful Login
var audit = new Audit
{
    UserId = user.Id,
    Action = "Login",
    Timestamp = DateTime.UtcNow,
    Details = $"User {user.Email} logged in successfully."
};
_context.AuditLogs.Add(audit);

// Failed Login
var failedLoginAudit = new Audit
{
    UserId = user?.Id ?? "N/A",
    Action = "Login Failure",
    Timestamp = DateTime.UtcNow,
    Details = $"Failed login attempt for email {model.Email}."
};
_context.AuditLogs.Add(failedLoginAudit);

// Logout
var audit = new Audit
{
    UserId = userId,
    Action = "Logout",
    Timestamp = DateTime.UtcNow,
    Details = $"User {User.Identity.Name} logged out successfully."
};
_context.AuditLogs.Add(audit);
```

## 5. Advanced Security Features

### 5.1. Password History

To prevent users from reusing old passwords, a password history feature has been implemented. The `PasswordHistory` model stores a hash of the user's previous passwords. When a user changes their password, the new password is compared against the last two passwords in their history. If a match is found, the user is prompted to choose a different password.

**Password History Check in `AccountController.cs`:**

```csharp
var passwordHistories = _context.PasswordHistories.Where(p => p.UserId == user.Id).OrderByDescending(p => p.CreatedDate).Take(2).ToList();
foreach (var passwordHistory in passwordHistories)
{
    var passwordVerificationResult = _userManager.PasswordHasher.VerifyHashedPassword(user, passwordHistory.PasswordHash, model.NewPassword);
    if (passwordVerificationResult == PasswordVerificationResult.Success)
    {
        ModelState.AddModelError("NewPassword", "You cannot reuse a password you have recently used.");
        return View(model);
    }
}
```

### 5.2. Two-Factor Authentication (2FA)

Two-factor authentication (2FA) using an authenticator app has been implemented to provide an extra layer of security. Users can enable 2FA in their account settings. When 2FA is enabled, users are required to enter a code from their authenticator app in addition to their password when logging in.

**2FA Login Flow in `AccountController.cs`:**

```csharp
// In the Login action
if (result.RequiresTwoFactor)
{
    return RedirectToAction(nameof(LoginWith2fa));
}

// The LoginWith2fa action
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model)
{
    // ...
    var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, false, model.RememberMachine);
    // ...
}
```
