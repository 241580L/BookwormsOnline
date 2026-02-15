# BookwormsOnline Security Implementation Report

## 0. Introduction

Bookworms Online is an online bookstore web application. It is constructed with ASP.Net Core MVC and its database is built with Entity Framework Core. This application is fortified with multiple layers of security, each of which is designed to fend off one or more cyberattacks from XSS to CRSF. Provided is a description of each and every security feature, as well as the types of cyberthreats it protects the application against.

---

## 1. User Registration & Data Protection

### Feature: Strong Password Requirements

**Description:**

Strong passwords are the basic security of an account. Millions of simple and common passwords have been used to hack into the accounts of innocents. This application counters this security hazard by meting out a password rule in the Program.cs file.

Based on server-defined password guidelines, it is compulsory for every password to have a length of at least twelve characters, and contain at least one character from four character categories: uppercase letters, lowercase letters, digits, and non-alphanumeric characters (symbols and punctuation). Password validation is performed in both client-side and server-side, and the strength is determined by zxcvbn library and the password strength meter is updated in real time as the user types their password.

**Code Implementation:**

*Server-side password policy (Program.cs):*
```csharp
bildr.Services.AddIdentity<IdentityUser, IdentityRole>(o =>
{
    // Note: `o` is the single-letter abbreviation for options.
    // Password settings
    o.Password.RequireDigit = true;
    o.Password.RequireLowercase = true;
    o.Password.RequireUppercase = true;
    o.Password.RequireNonAlphanumeric = true;
    o.Password.RequiredLength = 12;
    o.Password.RequiredUniqueChars = 1;

    // Lockout settings
    o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    o.Lockout.MaxFailedAccessAttempts = 3;
    o.Lockout.AllowedForNewUsers = true;

    // User settings
    o.User.RequireUniqueEmail = true;

    // Require confirmed account before sign-in (for password reset/2FA flows)
    o.SignIn.RequireConfirmedAccount = true;
})
```

*Client-side validation (Register.cs ViewModel):*
```csharp
[Required]
[DataType(DataType.Password)]
[RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{12,}$")]
public string Password { get; set; }
```

---

### Feature: Encrypted Sensitive Information

**Description:**

To diminish the impact of data breaches, every credential that is listed in the login page is encrypted.
Given that credit card numbers are extremely sensitive credentials, they must be encrypted in the database along with other sensitive data.

The data is immediately encrypted upon storage, and the credit card information is decrypted only when it is needed. No one, not even hackers or administrators, can view the credentials without possession of the encryption key. The key-housing DataProtection-Keys is listed as one of the folders in the .gitignore file so that they are never ever committed to the repository.

Note: Remember the PCI DSS standards that were mentioned in the previous written assignment? Per se, this application is not fully PCI DSS compliant, as some additional measures, such as secure payment gateways such as Stripe, require payment in order to follow the standards.

**Code Implementation:**

*Data Protection Setup (Program.cs):*
```csharp
// persist the data-protection keys so encrypted data survives restarts
var keysFolder = Path.Combine(bildr.Environment.ContentRootPath, "DataProtection-Keys");
Directory.CreateDirectory(keysFolder);
bildr.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keysFolder))
    .SetApplicationName("BookwormsOnline");
```

*Encryption in Action (AccountController.cs):*
```csharp
private readonly IDataProtector _protector;

public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, AuthDbContext ctx, IDataProtectionProvider dataProtectionProvider, IWebHostEnvironment webHostEnvironment, ReCaptchaService reCaptchaService, IEmailService emailService, IEncryptionService encryptionService)
{
    _userManager = userManager;
    _signInManager = signInManager;
    _ctx = ctx;
    _webHostEnvironment = webHostEnvironment;
    _protector = dataProtectionProvider.CreateProtector("BookwormsOnline.CreditCard.v1");
    _reCaptchaService = reCaptchaService;
    _emailService = emailService;
    _encryptionService = encryptionService;
}

// Every sensitive data field is encrypted using the encryption service.
var member = new Member
{
    FirstName = _encryptionService.Encrypt(model.FirstName),
    LastName = _encryptionService.Encrypt(model.LastName),
    CreditCardNo = _encryptionService.Encrypt(model.CreditCardNo),
    MobileNo = _encryptionService.Encrypt(model.MobileNo),
    BillingAddress = _encryptionService.Encrypt(model.BillingAddress),
    ShippingAddress = _encryptionService.Encrypt(model.ShippingAddress),
    Email = _encryptionService.Encrypt(model.Email),
    IdentityUserId = user.Id,
    PhotoURL = photoUrl,
    PasswordLastChanged = DateTime.UtcNow,
    SessionId = HttpContext.Session.Id
};
```

*.gitignore Entry:*
```/DataProtection-Keys/
```

---

### Feature: Email Uniqueness Verification

**Description:**

If users were to somehow be given the ability to map their accounts to already existing email addresses, this ability would be exploited as soon as it is implemented. Bad actors could use other people's email to perfectly steal the identity of other people, and get them into unnecessary trouble. As a countermeasure against duplicate emails, the system checks if an email address has been taken by another user, thereby preventing more than one account from possessing the same email address and making this method of impersonation infeasible.

**Code Implementation:**

*Identity Configuration (Program.cs):*
```csharp
bildr.Services.AddIdentity<IdentityUser, IdentityRole>(o =>
{
    // Password settings
    o.Password.RequireDigit = true;
    o.Password.RequireLowercase = true;
    o.Password.RequireUppercase = true;
    o.Password.RequireNonAlphanumeric = true;
    o.Password.RequiredLength = 12;
    o.Password.RequiredUniqueChars = 1;

    // Lockout settings
    o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    o.Lockout.MaxFailedAccessAttempts = 3;
    o.Lockout.AllowedForNewUsers = true;

    // User settings
    o.User.RequireUniqueEmail = true;

    // Require confirmed account before sign-in (for password reset/2FA flows)
    o.SignIn.RequireConfirmedAccount = true;
})
```

---

### Feature: File Upload Restrictions

**Description:**

To prevent the file storage from being abused by being cluttered with large files, the maximum acceptable file size is configured to 2 mebibytes (2×1024² bytes, not to be confused with 2 decimal megabytes, or 2×1000² bytes), and a whitelist that permits only one file type: JPG. Given that sole client-side validation is easily bypassable via the inspect element tool, the system also validates file input on server-side, which cannot be edited from the frontend directly.

It is also possible for hackers to use special file names such as those containing a chain of "../"'s. This set of three characters means to traverse to the parent directory, and hackers use them in bulk to traverse all the way to the root directory, eventually gaining them access to sensitive credentials on the server's local devices. This exploit is forstalled by giving each file a random 32-hexadecimal character name generated by GUID (Globally Unique IDentifier), and suffixing the original file name for reference.

**Code Implementation:**

*Server-side validation (AccountController.cs):*
```csharp
if (model.Photo != null && model.Photo.Length > 0)
{
    // Validate image size (max 2MiB) and content type
    const long maxFileSize = 2 * 1024 * 1024;
    if (model.Photo.Length > maxFileSize)
    {
        ModelState.AddModelError("Photo", "File too large. Maximum allowed is 2MB.");
        await _userManager.DeleteAsync(user);
        return View(model);
    }

    if (!string.Equals(model.Photo.ContentType, "image/jpeg", StringComparison.OrdinalIgnoreCase)
        && !string.Equals(model.Photo.ContentType, "image/pjpeg", StringComparison.OrdinalIgnoreCase))
    {
        ModelState.AddModelError("Photo", "Only .JPG files are allowed.");
        await _userManager.DeleteAsync(user);
        return View(model);
    }

    var uploadsFolder = Path.Combine(_webHostEnvironment.WebRootPath ?? "", "uploads");
    Directory.CreateDirectory(uploadsFolder);

    // Sanitize filename
    var safeFileName = Path.GetFileName(model.Photo.FileName);
    // use GUID to prevent path traversal
    var uniqueFileName = Guid.NewGuid().ToString("N") + "_" + safeFileName;
    var filePath = Path.Combine(uploadsFolder, uniqueFileName);

    // Save file
    using (var fileStream = new FileStream(filePath, FileMode.Create))
    {
        await model.Photo.CopyToAsync(fileStream);
    }

    photoUrl = "/uploads/" + uniqueFileName;
}
```

*Client-side validation (Register.cshtml):*
```html
<div class="form-group">
    <label asp-for="Photo">Photo (.JPG only)</label>
    <input asp-for="Photo" type="file" accept=".jpg,image/jpeg" class="form-control-file" id="photoInput" />
    <span asp-validation-for="Photo" class="text-danger"></span>
</div> <!-- Client-side validation for file type and size (2MB max) -->
```
---

## 2. Session Management & Login Security

### Feature: Session Timeout

**Description:**

Let's say a person leaves their laptop behind in a public place. What if somebody were to find their laptop and misuse their logged in session? We do not want that to happen. To prevent this, all user sessions of this site have a configured timeout of sixty seconds (measured from the last user action) before expiration, after which the user is automatically logged out. This way, user sessions of laptops left unattended cannot be used by other people, and those who discover the session have limited time to use the session. This helpful system has also been implemented in the online school platform PoliteMall, where sessions expire after three consecutive hours of inactivity.

**Code Implementation:**

*Session Configuration (Program.cs):*
```csharp
bildr.Services.AddSession(o =>
{
    o.IdleTimeout = TimeSpan.FromMinutes(1); // 1-minute timeout
    o.Cookie.HttpOnly = true;
    o.Cookie.IsEssential = true;
    o.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
    o.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict;
});

// Harden identity cookie
bildr.Services.ConfigureApplicationCookie(o =>
{
    o.Cookie.HttpOnly = true;
    o.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
    o.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict;
    o.ExpireTimeSpan = TimeSpan.FromMinutes(1);
    o.SlidingExpiration = true;
    o.LoginPath = "/Account/Login";
    o.AccessDeniedPath = "/ErrorHandler/403";
});
```

---

### Feature: Single Session Per User

**Description:**

Multiple devices sharing the same account can engender concurrent session attacks, where the real user and an attacker with unauthorized access - despite using different devices and being miles apart from each other - are logged in to the same account at the same time. It would be awful if you happen to be the user and there's nothing you can do to stop the hacker from abusing your stolen account.

Concurrent session attacks are rendered unviable using a single session middleware, which ensures that a user can be logged in on only one device at a time; hence the name "single session". If a user account's session is active on Device 1 and this account is logged in on Device 2, the session on Device 1 is automatically logged out. After this, the user who had used Device 1 needs to log back in to regain access to their account and log out the session on Device 2. By preventing multiple people having the same account on different devices, it precludes the risk of concurrent session attacks and credential sharing abuse.

**Code Implementation:**

*Single Session Check (SingleSessionMiddleware.cs):*
```csharp
public async Task InvokeAsync(HttpContext ctx)
{
    if (ctx.User?.Identity?.IsAuthenticated == true)
    {
        var userId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!string.IsNullOrEmpty(userId))
        {
            var db = ctx.RequestServices.GetService(typeof(AuthDbContext)) as AuthDbContext;
            if (db != null)
            {
                var member = await db.Members.FirstOrDefaultAsync(m => m.IdentityUserId == userId);
                var currentSessionId = ctx.Session.Id;
                if (member != null && !string.IsNullOrEmpty(member.SessionId) && member.SessionId != currentSessionId)
                {
                    // Sign out this request because user's stored session does not match
                    await ctx.SignOutAsync(IdentityConstants.ApplicationScheme);
                    ctx.Session.Clear();
                    ctx.Response.Redirect("/Account/Login?message=SessionExpired");
                    return;
                }
            }
        }
    }
    await _next(ctx);
}
```

*Logout Session Management (AccountController.cs):*
```csharp
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Logout()
{
    var userId = _userManager.GetUserId(User);
    var member = _ctx.Members.FirstOrDefault(m => m.IdentityUserId == userId);
    if (member != null)
    {
        member.SessionId = null;
        _ctx.SaveChanges();
    }
    await _signInManager.SignOutAsync();
    HttpContext.Session.Clear();

    var audit = new Audit
    {
        UserId = userId,
        Action = "Logout",
        Timestamp = DateTime.UtcNow,
        Details = $"User {User.Identity.Name} logged out successfully."
    };
    _ctx.AuditLogs.Add(audit);
    await _ctx.SaveChangesAsync();

    return RedirectToAction("Login", "Account", new { message = "LogoutSuccess" });
}
```

---

### Feature: Account Lockout After Failed Logins

**Description:**

Ever since passwords have been invented, attackers have created automated scripts that are programmed to perform trial and error on the password fields at light speed. The list of tested passwords can range from a list of common passwords to passwords leaked from other websites. This application defends against these brute-force attacks with an account lockout policy, causing such tools to use up all their failed login attempts as quick as it is implemented. The policy defines that every 3 failed login attempts, the account is locked out for 1 minute, after which the user can try logging in again.

**Code Implementation:**

*Lockout Settings (Program.cs):*
```csharp
bildr.Services.AddIdentity<IdentityUser, IdentityRole>(o =>
{
    // o stands for options; anything else is self explanatory
    o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    o.Lockout.MaxFailedAccessAttempts = 3;
    o.Lockout.AllowedForNewUsers = true;
})
```

*Login with Lockout (AccountController.cs):*
```csharp
var result = await _signInManager.PasswordSignInAsync(
    user, 
    model.Password, 
    false, 
    lockoutOnFailure: true  // Enable lockout on failed attempts
);
```

---

## 3. Password Security & Access Recovery

### Feature: Password History Tracking

**Description:**

When passwords get leaked online, the most recommended first step is to change it posthaste. However, if users were to be granted the ability to reuse their old passwords, they might simply recycle the compromised password, therefore re-compromising their accounts. Enforcing a password history policy, instructs users to create new, unique passwords every time they change them. The system that enforces this rule also tracks and remembers up to two of the most recently used passwords, and prohibits their owners from using them. As a result, compromised passwords cannot be re-used.

**Code Implementation:**

*Storing Password History (AccountController.cs):*
```csharp
// When user registers
var initialSalt = GenerateSalt();
var initialHash = HashPasswordWithSalt(model.Password, initialSalt);
var pwdHistory = new PasswordHistory
{
    UserId = user.Id,
    PasswordHash = initialHash,
    Salt = initialSalt,
    CreatedDate = DateTime.UtcNow
};
_ctx.PasswordHistories.Add(pwdHistory);

// When user changes password
var passwordHistories = _ctx.PasswordHistories
    .Where(p => p.UserId == user.Id)
    .OrderByDescending(p => p.CreatedDate)
    .Take(2)  // Get last 2 passwords
    .ToList();

foreach (var pwdHistory in passwordHistories)
{
    if (string.IsNullOrEmpty(pwdHistory?.Salt) || string.IsNullOrEmpty(pwdHistory.PasswordHash))
        continue;
    
    var candidateHash = HashPasswordWithSalt(model.NewPassword, pwdHistory.Salt);
    if (SecureEquals(candidateHash, pwdHistory.PasswordHash))
    {
        ModelState.AddModelError("NewPassword", "You cannot reuse a password you have recently used.");
        return View(model);
    }
}
```

---

### Feature: Password Age Enforcement

**Description:**

Passwords are not allowed to be changed when its age is 1 minute or shorter. If this restriction were to be absent, users may change their passwords multiple times in succession to unscrupulously circumvent the "do not re-use previously used passwords" rule. For example, if a user had used "Password001!" as their password, and then altered it to "Password002!", "Password003!", and so on up to "Password010!" in rapid succession, they could then change it back to "Password001!" which goes against the rule.

Passwords are not allowed to be active for ninety days or longer. If this restriction were to be absent, users may continue using compromised passwords indefinitely if they do not change them. For example, if a user's password "Password001!" were to be leaked online and the user did not change it, an attacker could use this password to access the user's account at any time in the future. When the day comes that the password reaches its ninetieth day of use, the user is required by rule to change it to a password that had not been recently used before they can log in once again.

**Code Implementation:**

*Password Age Check (AccountController.cs):*
```csharp
[HttpPost]
public async Task<IActionResult> Login(Login model)
{
    var user = await _userManager.FindByEmailAsync(model.Email);
    if (user != null)
    {
        var member = _ctx.Members.FirstOrDefault(m => m.Email == model.Email);
        
        // Check if password has expired (90 days)
        if (member.PasswordLastChanged.AddDays(90) < DateTime.UtcNow)
        {
            ModelState.AddModelError("", "Your password has expired. Please reset your password.");
            return View(model);
        }
    }
}
```

*Change Password Frequency Limit (AccountController.cs):*
```csharp
public async Task<IActionResult> ChangePassword(ChangePassword model)
{
    var member = _ctx.Members.FirstOrDefault(m => m.Email == user.Email);
    
    // Prevent changing password more than once per minute
    if (member != null && member.PasswordLastChanged.AddMinutes(1) > DateTime.UtcNow)
    {
        ModelState.AddModelError("", "You cannot change your password more than once per minute.");
        return View(model);
    }
    
    // Update password last changed timestamp
    if (result.Succeeded)
    {
        member.PasswordLastChanged = DateTime.UtcNow;
        _ctx.SaveChanges();
    }
}
```

---

### Feature: Password Reset via Email Link

**Description:**

From a stoic perspective, it is normal for a netizen to forget their password to their account. Varying statistics from [survey](https://www.securitymagazine.com/articles/99116-51-of-users-admit-to-resetting-forgotten-passwords-once-a-month) to [survey](https://www.businesswire.com/news/home/20250423085569/en/Gen-Zs-Password-Fatigue-Finds-72-of-Digital-Natives-Reuse-the-Same-Password-Across-Accounts) show that approximately half of all people on the internet have forgetten their passwords often enough to trigger a password reset.

The security of the password reset feature is vitally epochal, as it is possible that attackers will abuse this feature to perform a larcenous act of account theft. This scenario of unauthorized access is prevented by generating a secure one-time-use reset link that is sent to the user's inbox on their email. The fate of this link only has two endings: it is either used for the first and last time to reset the password, or it expires after a configured time period, usually 1 hour or less. If an attacker were to intercept the link, they would be unable to use it if it has already been used or has expired by the time they obtained it.

**Code Implementation:**

*Forgot Password Request (AccountController.cs):*
```csharp
[HttpPost]
public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
{
    if (ModelState.IsValid)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user != null)
        {
            // Generate one-time token
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var passwordResetLink = Url.Action("ResetPassword", "Account", 
                new { email = model.Email, token = token }, Request.Scheme);

            // log the link for user (cannot send email in demo)
            Console.WriteLine(passwordResetLink);
        }
        
        // Always return success to prevent user enumeration
        return View("ForgotPasswordConfirmation");
    }
    return View(model);
}
```

*Reset Password (AccountController.cs):*
```csharp
[HttpPost]
public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
{
    if (ModelState.IsValid)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user != null)
        {
            // Token is validated by the framework (one-time use, expiration built-in)
            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
            if (result.Succeeded)
            {
                return View("ResetPasswordConfirmation");
            }
        }
        return View("ResetPasswordConfirmation");
    }
    return View(model);
}
```

---

## 4. Advanced Authentication: Two-Factor Authentication (2FA)

### Feature: Multi-Factor Authentication

**Description:**

Emails and passwords are not enough to ensure a person is whom they claim to be. If login fields only consisted of emails and passwords, attackers with knowledge of a particular innocent user's email-password combination can use them to infiltrate their account with relative ease. To verify the user's identity, we need to affix an extra layer of security by requiring users to provide one or more additional forms of verification alongside a valid password entry.

The Two-Factor Authentication (2FA) process of this application involves sending confirmation emails to users every time they log in to their account. In the user's inbox, a random six-digit security code is generated, and the user must enter the numeric code at the time it is active for a successful login. When an account has enabled 2FA, hackers who have no access to the that account's email are barred from logging in to the account, even with a stolen password.

**Code Implementation:**

*2FA Configuration (Program.cs):*
```csharp
bildr.Services.AddIdentity<IdentityUser, IdentityRole>(o =>
{
    // Require confirmed account before sign-in (for password reset/2FA flows)
    o.SignIn.RequireConfirmedAccount = true;
})
```

*Enable Authenticator (ManageController.cs):*
```csharp
public ManageController(UserManager<IdentityUser> userManager, IEmailService emailService)
{
    _userManager = userManager;
    _emailService = emailService;
}

public async Task<IActionResult> Index()
{
    var user = await _userManager.GetUserAsync(User);
    var model = new ManageViewModel
    {
        IsTwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user),
        RecoveryCodesLeft = await _userManager.CountRecoveryCodesAsync(user),
    };

    return View(model);
}

[HttpGet]
public async Task<IActionResult> EnableAuthenticator()
{
    var user = await _userManager.GetUserAsync(User);
    // Generate email verification code (short numeric via Email two-factor provider)
    var code = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
    
    // Send email with verification code
    var emailBody = $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <style>
        body {{ font-family: Arial, sans-serif; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #4CAF50; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; background-color: #f9f9f9; }}
        .code {{ font-size: 24px; font-weight: bold; text-align: center; color: #4CAF50; margin: 20px 0; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Enable 2FA</h1>
        </div>
        <div class='content'>
            <p>Hello {user.Email},</p>
            <p>You have requested to enable two-factor authentication for your Bookworms Online account.</p>
            <p>Your verification code is:</p>
            <div class='code'>{code}</div>
            <p>This code will expire in 15 minutes.</p>
            <p>If you did not request this, please ignore this email.</p>
        </div>
        <div class='footer'>
            <p>&copy; 2026 Bookworms Online. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";
    
    await _emailService.SendEmailAsync(user.Email, "Enable Two-Factor Authentication", emailBody);
    var model = new EnableAuthenticatorViewModel { Code = "" };
    return View(model);
}

[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> EnableAuthenticator(EnableAuthenticatorViewModel model)
{
    if (ModelState.IsValid)
    {
        var user = await _userManager.GetUserAsync(User);
        // Verify the email code sent to user's email (using Email two-factor provider)
        var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user, "Email", model.Code);
        if (succeeded)
        {
            await _userManager.SetTwoFactorEnabledAsync(user, true);
            return RedirectToAction(nameof(Index));
        }
        else
        {
            ModelState.AddModelError("Code", "Invalid code. Please check your email and try again.");
            return View(model);
        }
    }
    return View(model);
}

[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> GenerateRecoveryCodes()
{
    var user = await _userManager.GetUserAsync(User);
    var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
    var model = new GenerateRecoveryCodesViewModel { RecoveryCodes = recoveryCodes.ToArray() };
    return View(model);
}
```

*2FA Login (AccountController.cs):*
```csharp
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model)
{
    if (!ModelState.IsValid)
    {
        return View(model);
    }

    var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
    if (user == null)
    {
        throw new InvalidOperationException($"Unable to load two-factor authentication user.");
    }

    var emailCode = model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

    // Verify the email code using the Email two-factor provider
    var result = await _signInManager.TwoFactorSignInAsync("Email", emailCode, false, model.RememberMachine);

    if (result.Succeeded)
    {
        var audit = new Audit
        {
            UserId = user.Id,
            Action = "Login with 2FA",
            Timestamp = DateTime.UtcNow,
            Details = $"User {user.Email} logged in with 2FA."
        };
        _ctx.AuditLogs.Add(audit);
        await _ctx.SaveChangesAsync();

        return RedirectToAction("Index", "Home");
    }
    else
    {
        ModelState.AddModelError(string.Empty, "Invalid email code. Please check your email.");
        return View(model);
    }
}
```

*Recovery Codes Generation (ManageController.cs):*
```csharp
[HttpPost]
public async Task<IActionResult> GenerateRecoveryCodes()
{
    var user = await _userManager.GetUserAsync(User);
    var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
    var model = new GenerateRecoveryCodesViewModel { RecoveryCodes = recoveryCodes.ToArray() };
    return View(model);
}
```

---

## 5. Attack Prevention: Cross-Site & Injection Attacks

### Feature: CSRF Protection (Cross-Site Request Forgery)

Time for a little PSA: When you see a form on the internet, you must always check the URL of the website you are on. If you are on a shady website, and you see a form that looks like it belongs to your bank, do **not** fill it out. That is a CSRF attack in action.

In Cross-Site Request Forgery (CSRF). A single click on the "submit" button of a dubious form leads to an unauthorized transaction, such as changing password hashes to strings with no matching hashes. Every form submission has an invisible security token that is unique per session and per form. It is used by the server to verify if it matches the user's session before the form data is processed. As a result, only solicited requests from the official website are processed as normal, and requests from anywhere else - including dicey forms on suspicious websites - are blocked.

**Code Implementation:**

*Global CSRF Protection (Program.cs):*
```csharp
// Global antiforgery validation for non-GET requests (adds defense-in-depth)
bildr.Services.AddControllersWithViews(o =>
{
    o.Filters.Add(new Microsoft.AspNetCore.Mvc.AutoValidateAntiforgeryTokenAttribute());
});
```

*Form-level CSRF Protection (Register.cshtml):*
```html
<form asp-action="Register" asp-controller="Account" method="post">
    <!-- Automatically includes CSRF token -->
</form>
```

*Controller Action (AccountController.cs):*
```csharp
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Register(Register model)
{
    // Server validates the CSRF token
    if (ModelState.IsValid)
    {
        // Process form only if token is valid
    }
}
```

---

### Feature: SQL Injection Prevention

**Description:**

Structured Query Language (SQL), a popular language for constructing databases from MySQL to Oracle, is exceptionally vulnerable to injections that the attack has a given name of its own. During an SQL Injection, attackers insert fragments of SQL commands into input fields. If the system is not well-guarded against SQL injections, the system concatenates into SQL queries, thus resulting in unwanted CRUD actions such as en masse data retrieval, credential modification, deletion of entire databases, and so on.

Instead, this application's database uses an alternative to SQL. Entity Framework Core, the database of the Bookworms Online application is built on, is an Object-Relational Mapping (ORM) framework that abstracts away direct SQL queries. Using LINQ (Language Integrated Query) and Entity Framework's intrinsic parameterization, every input from the user is strictly treated as data instead of executable code which could come in the form of malware. Attempted SQL payloads become harmless strings, shielding all database actions from SQL injection.

**Code Implementation:**

*Safe Database Queries with Entity Framework (AccountController.cs):*
```csharp
// Safe: User input is parameterized in lieu of concatenation
var user = await _userManager.FindByEmailAsync(model.Email);  // Safe parameterization

// Safe: LINQ queries are translated to parameterized SQL
var member = _ctx.Members.FirstOrDefault(m => m.Email == model.Email);

// Safe: Password verification uses built-in hashing, never raw SQL
var result = await _signInManager.PasswordSignInAsync(user, model.Password, false, lockoutOnFailure: true);

// Safe: Queries use LINQ methods
var passwordHistories = _ctx.PasswordHistories
    .Where(p => p.UserId == user.Id)  // Parameterized WHERE clause, hence SQL payloads will never work
    .OrderByDescending(p => p.CreatedDate)
    .Take(2)
    .ToList();
```

---

### Feature: XSS Protection (Cross-Site Scripting)

**Description:**

You know that a website is vulnerable to XSS when `<script>alert("Hello World!")</script>` on a comment displays an alert pop-up. This alert message, despite seeming friendly, is a sign of a successful XSS attack. It opens the door for more harmful scripts to run on the user's browser. Stealing cookies. Redirection to phishing sites. Logging keystrokes. The list of the aftermaths of XSS attacks are endless, which can ultimately leave users falling victim to malicious script elements.

As a countermeasure against XSS, the system translates special characters to their HTML counterparts. Just like catching a quadruplet of runaway alligators, this mechanism catches the angle brackets of the script tags and translates them into innocuous escape characters. `<` becomes `&lt;`, `>` becomes `&gt;`, and script tags including potentially malicious code become harmless.

In addition, the Content Security Policy (CSP) adds an extra layer of defense by whitelisting the sources from which scripts can be loaded. Any source that is not on the allowlist is denied, including those that can facilitate the trafficking of JavaScript malware, (e.g. data:// payloads) further mitigating the risk of XSS attacks.

**Code Implementation:**

*Automatic HTML Encoding in Razor (.cshtml):*
```html
<!-- User input is automatically encoded when displayed -->
<div>@Model.UserInput</div>  <!-- If UserInput = "<script>alert('xss')</script>"
                                  it displays as: &lt;script&gt;alert('xss')&lt;/script&gt; -->
```

*HTML Helper for Extra Safety:*
```html
<!-- Additional encoding layer if needed -->
@Html.DisplayFor(m => m.UserInput)
```

*Content Security Policy (SecurityHeadersMiddleware.cs):*
```csharp
var csp = "default-src 'self'; " +
            "script-src 'self' https://www.google.com https://www.gstatic.com https://www.recaptcha.net 'unsafe-inline'; " +
            "script-src-elem 'self' 'unsafe-inline' https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/4.4.2/zxcvbn.js https://www.google.com/recaptcha/api.js https://www.google.com https://www.gstatic.com https://www.recaptcha.net; " +
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://www.gstatic.com; " +
            "img-src 'self' data: https://www.gstatic.com; " +
            "font-src 'self' https://fonts.gstatic.com; " +
            "connect-src 'self' https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/ https://www.google.com https://www.gstatic.com https://www.recaptcha.net http://localhost:* https://localhost:* ws://localhost:* wss://localhost:*; " +
            "frame-src https://google.com https://www.google.com https://www.recaptcha.net https://recaptcha.net; " +
            "frame-ancestors 'none'; " +
            "base-uri 'self';";
ctx.Response.Headers["Content-Security-Policy"] = csp;
```

*HttpOnly Cookies (prevent JavaScript access):*
```csharp
bildr.Services.AddSession(o =>
{
    o.Cookie.HttpOnly = true;  // JavaScript cannot access this cookie
});

bildr.Services.ConfigureApplicationCookie(o =>
{
    o.Cookie.HttpOnly = true;  // JavaScript cannot access authentication cookie
});
```

---

### Feature: Input Validation & Sanitization

**Description:**

Take this Python snippet as an example: If the code `u = int(input("Enter a number"))` is executed and the user enters a non-numeric value, the entire program crashes due to the unhandled exception. The same thing could happen to this application if input validation measures are absent. If the system were to attempt to send a password reset link to a user with a malformed email address, the system could throw an exception and crash just like the Python program.

In this application, input validation is performed on every field in the login page, the register pages, and almost any other page that contains input fields. Mobile numbers must contain only digits, email address must be a valid email with one commercial at symbol followed by a domain name, credit card numbers are validated with checksum algorithms, and passwords must follow the password rule defined by a regular expression.

Memory overflow attacks are also latent: attackers fill the input fields with gluts of characters by the myriads, causing the system to run out of memory and crash. Input size limits declared by the system specify a maximum length of 200 characters for billing and shipping addresses, and 50 characters for first and last names. This obviates memory overflow attacks and buffer overflow.

The combo of client- and server-side validation has been used in aforementioned features, such as passwords and file uploads, and the list of features for which they are applied to extends to the input fields. Client-side validation enhances the UX of this application by giving user feedback, making sure that the user fills out all the fields correctly before they can submit the form. Server-side validation serves as the client-side's backup: when an attacker modifies or straight up removes the client-side validation mechanism, the server-side validation will remain in the backend, unchanged and immutable, with the same validation rules as that of the client-side.

**Code Implementation:**

*Data Annotations Validation (Register.cs ViewModel):*
```csharp
public class Register
{ 
    [Required(ErrorMessage = "First name is required")]
    [StringLength(50, MinimumLength = 1, ErrorMessage = "First name must be between 1 and 50 characters")]
    public string FirstName { get; set; }

    [Required(ErrorMessage = "Last name is required")]
    [StringLength(50, MinimumLength = 1, ErrorMessage = "Last name must be between 1 and 50 characters")]
    public string LastName { get; set; }

    [Required(ErrorMessage = "Credit card number is required")]
    [StringLength(19, MinimumLength = 13, ErrorMessage = "Credit card number must be between 13 and 19 digits")]
    [RegularExpression(@"^\d[\d\s\-]{11,17}\d$", ErrorMessage = "Please enter a valid credit card number")]
    public string CreditCardNo { get; set; }

    [Required(ErrorMessage = "Mobile number is required")]
    [StringLength(20, MinimumLength = 7, ErrorMessage = "Mobile number must be between 7 and 20 characters")]
    [RegularExpression(@"^[\d\s\+\-\(\)]{7,20}$", ErrorMessage = "Please enter a valid mobile number")]
    public string MobileNo { get; set; }

    [Required(ErrorMessage = "Billing address is required")]
    [StringLength(200, MinimumLength = 5, ErrorMessage = "Billing address must be between 5 and 200 characters")]
    public string BillingAddress { get; set; }

    [Required(ErrorMessage = "Shipping address is required")]
    [StringLength(200, MinimumLength = 5, ErrorMessage = "Shipping address must be between 5 and 200 characters")]
    public string ShippingAddress { get; set; }

    [Required, EmailAddress]
    [StringLength(100)]
    public string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{12,}$")]
    public string Password { get; set; }

    [Compare(nameof(Password), ErrorMessage = "Passwords do not match.")]
    public string ConfirmPassword { get; set; }
}
```

*Server-side Validation (AccountController.cs):*
```csharp
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Register(Register model)
{
    // ModelState.IsValid checks all data annotations
    if (ModelState.IsValid)
    {
        // All validation passed, safe to process
        var user = new IdentityUser { 
            UserName = model.Email, 
            Email = model.Email 
        };
        var result = await _userManager.CreateAsync(user, model.Password);
        // ...
    }

    return View(model);  // Re-display with validation errors
}
```

*Member Model Validation:*
```csharp
public class Member
{
    [Required, MaxLength(500)]
    public string FirstName { get; set; } = null!;

    [Required, MaxLength(500)]
    public string LastName { get; set; } = null!;

    [Required, MaxLength(500)]
    public string CreditCardNo { get; set; } = null!;

    [Required, MaxLength(500)]
    public string MobileNo { get; set; } = null!;

    [Required, MaxLength(1000)]
    public string BillingAddress { get; set; } = null!;

    [Required, MaxLength(1000)]
    public string ShippingAddress { get; set; } = null!;

    [Required, MaxLength(500)]
    public string Email { get; set; } = null!;
}
```

---

## 6. Automated Protection: Bot & Bot Detection

### Feature: Google reCAPTCHA v2

**Description:**

A year or two ago, [bot traffic has surpassed human activity online, accounting for more than half of all internet traffic.](https://www.securityweek.com/bot-traffic-surpasses-humans-online-driven-by-ai-and-criminal-innovation/) Given that two thirds of those bots are "bad bots" used for devious activity like scraping and fraud, bad bots using this site can lead to automated accounts dominating the list, and scripts performing rapid-fire guess-and-check on the automatic brute force attack.

In response, an anti-bot tool is implemented to separate man from machine. The "CAPTCHA" in "reCAPTCHA" stands for "Completely Automated Public Turing test to tell Computers and Humans Apart". The version of reCAPTCHA that most of us are more familiar with is v2 Checkbox, where users click on a checkbox and select all squares containing traffic lights or zebra crossings. However, there exists a less known, but more advanced version of reCAPTCHA called v3 Score. Websites protected with reCAPTCHA v3 typically have a tab on the bottom right corner, reading "protected by reCAPTCHA".

V3's verification process is invisible to users, and works in the background to analyze user behavior and assigns it a score from 0 to 1, where a score closer to one indicates that the user is likely human. Cursors moving at perfectly perpendicular paths or unrealistically high speeds and greater-than-one-kiloword-per-minute typing rates raise red flags and drive the score closer and closer to zero. If a user score falls below the acceptable score threshold of 0.7 (configured in appsettings.json), the user is blocked from registration or resetting their password.

**Code Implementation:**

*reCAPTCHA Configuration (Program.cs):*
```csharp
bildr.Services.Configure<ReCaptchaSettings>(bildr.Configuration.GetSection("reCAPTCHA"));
bildr.Services.AddHttpClient<ReCaptchaService>();
```

*reCAPTCHA Service (ReCaptchaService.cs):*
```csharp
public async Task<bool> Verify(string token)
{
    var response = await _httpClient.PostAsync(
        $"https://www.google.com/recaptcha/api/siteverify?secret={_reCaptchaSettings.SecretKey}&response={token}", 
        null);
    var jsonString = await response.Content.ReadAsStringAsync();
    var json = JObject.Parse(jsonString);
    
    // reCAPTCHA v3: Check both success and score
    bool success = json.Value<bool>("success");
    double score = json.Value<double?>("score") ?? 0.0;
    
    // Score ranges from 0.0 to 1.0
    // 1.0 is very likely a legitimate interaction, 0.0 is very likely a bot
    // Use configured threshold to determine if user should be allowed
    double threshold = _reCaptchaSettings.ScoreThreshold;
    
    return success && score >= threshold;
}
```

*Registration with reCAPTCHA (AccountController.cs):*
```csharp
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Register(Register model)
{
    if (!await _reCaptchaService.Verify(model.recaptcha_token))
    {
        ModelState.AddModelError("", "reCAPTCHA validation failed.");
        return View(model);
    }

    if (ModelState.IsValid)
    {
        // Process registration
    }
}
```

*Client-side reCAPTCHA (Register.cshtml):*
```html
<!-- Google reCAPTCHA v3 -->
<script src="https://www.google.com/recaptcha/api.js?render=@siteKey"></script>

<script>
    grecaptcha.ready(function() {
        grecaptcha.execute('@siteKey', {action: 'submit'}).then(function(token) {
            document.getElementById('recaptcha_token').value = token;
        });
    });
</script>
```

*Threshold configuration (appsettings.json)*
```
"reCAPTCHA": {
    "SiteKey": "your-site-key",
    "SecretKey": "your-secret-key",
    "ScoreThreshold": 0.7
}
```

---

## 7. Monitoring & Accountability: Audit Logging

### Feature: Comprehensive Audit Trail

**Description:**

Audit logging is a popular tool in the field of digital forensics, renowned for its ability to monitor the actions of users and anyone else interacting with the security features of the application. Each entry on the log contains the user ID (or "N/A" for failed login attempts without a valid user), the type of action performed, the timestamp of the action, and any relevant details (e.g. email used for registration or login).

With audit logs in place, administrators can examine their entries to check for any suspicious activity, such as anomolous access times or multiple failed logins. If suspicions arise regarding an insider breach that has already occurred, the log items can be used as evidence to determine the culprit.

**Code Implementation:**

*Audit Log Model (Audit.cs):*
```csharp
public class Audit
{
    public int Id { get; set; }

    [Required]
    public string UserId { get; set; }

    [Required]
    public string Action { get; set; }

    [Required]
    public DateTime Timestamp { get; set; }

    public string Details { get; set; }
}
```

*Audit Logging in Action (AccountController.cs):*
```csharp
// After successful registration
var audit = new Audit
{
    UserId = user.Id,
    Action = "Register",
    Timestamp = DateTime.UtcNow,
    Details = $"User {user.Email} registered successfully."
};
_ctx.AuditLogs.Add(audit);

// After login attempt
if (result.Succeeded)
{
    var audit = new Audit
    {
        UserId = user.Id,
        Action = "Login",
        Timestamp = DateTime.UtcNow,
        Details = $"User {user.Email} logged in successfully."
    };
    _ctx.AuditLogs.Add(audit);
}

// Failed login logging
var failedLoginAudit = new Audit
{
    UserId = user?.Id ?? "N/A",
    Action = "Login Failure",
    Timestamp = DateTime.UtcNow,
    Details = $"Failed login attempt for email {model.Email}."
};
_ctx.AuditLogs.Add(failedLoginAudit);

// Password change logging
var audit = new Audit
{
    UserId = user.Id,
    Action = "Change Password",
    Timestamp = DateTime.UtcNow,
    Details = "User changed their password successfully."
};
_ctx.AuditLogs.Add(audit);
```

---

## 8. Communication Security: HTTPS

### Feature: Encrypted Web Communication

**Description:**

HTTP stands for "HyperText Transfer Protocol". HTTPS, the more secure version of HTTP, stands for "HyperText Transfer Protocol Secure". The "S" in HTTPS means that all communications between client and server is encrypted using the latest SSL (Secure Sockets Layer) or TLS (Transport Layer Security) protocols, protecting sensitive data from interception via man-in-the-middle attacks. Every time a user tries to access the website using the regular and less secure HTTP, the system turns HTTP to HTTPS, ensuring that session cookies remain unhijacked and passwords remain unsniffed.

**Code Implementation:**

*HTTPS Enforcement (Program.cs):*
```csharp
app.UseHttpsRedirection();

// For non-development, use HSTS
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}
```

---

## 9. Application Hardening: Security Headers

### Feature: Security Response Headers

**Description:**

Every GET, POST, and any other HTTP request to the server receives a response with a set of defensive security headers, each of which is designed to forfend one or more types of cyberthreats. A full description on what each header does and what attacks they forestall is provided in the comments of the code implementation below.

**Code Implementation:**

*Security Headers Middleware (SecurityHeadersMiddleware.cs):*
```csharp
public async Task Invoke(HttpContext ctx)
{
    // Let's say someone were to write or take a .js script, replace the .js with .jpg, and upload it as their profile picture. Serving this file with a MIME type of "image/jpeg" would obviously fail, but serving this file with a MIME type of "text/javascript" or similar may result in a hazardous XSS script being executed, even if its file type is jpg. This header discourages the risky trial-and-error of the content type, and commands the browser to strictly follow the content type as declared in the HTTP response header.
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";

    // Sometimes, the web page is framed within a 100% transparent iframe on a dodgy website, making the users think that it is the real website. Unbeknownst to them, the clicks on what appear to be visible buttons can trigger a set of unpremeditated actions such as password changes. This is called clickjacking and it is thwarted with the use of the below line.
    ctx.Response.Headers["X-Frame-Options"] = "DENY";

    // Moving on to the referrer policy declaration and putting string setting etymology in block letters, "no-referrer-when-downgrade" means that NO REFERRER information is sent WHEN the https is DOWNGRADEd to regular http. When transmitting over insecure HTTP protocol, the referrer header is stipped of all sensitive information, ultimately preventing info leakage.
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer-when-downgrade";

    // Geolocation, microphone and camera are not used in this application, so the permissions policy declares that they will be denied altogether, preventing scripts from tapping into their devices and using them for stalking, eavesdropping, or recording videos without consent of the device's owner.
    ctx.Response.Headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()";

    // As mentioned five descriptions ago, CSP stands for Content Security Policy. It is a whitelist that permits its listed sources and denies the rest.
    var csp = "default-src 'self'; " +
                "script-src 'self' https://www.google.com https://www.gstatic.com https://www.recaptcha.net 'unsafe-inline'; " +
                "script-src-elem 'self' 'unsafe-inline' https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/4.4.2/zxcvbn.js https://www.google.com/recaptcha/api.js https://www.google.com https://www.gstatic.com https://www.recaptcha.net; " +
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://www.gstatic.com; " +
                "img-src 'self' data: https://www.gstatic.com; " +
                "font-src 'self' https://fonts.gstatic.com; " +
                "connect-src 'self' https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/ https://www.google.com https://www.gstatic.com https://www.recaptcha.net http://localhost:* https://localhost:* ws://localhost:* wss://localhost:*; " +
                "frame-src https://google.com https://www.google.com https://www.recaptcha.net https://recaptcha.net; " +
                "frame-ancestors 'none'; " +
                "base-uri 'self';";
    ctx.Response.Headers["Content-Security-Policy"] = csp;

    // Man-in-the-middle attacks that attempt to downgrade the connection to HTTP are averted with the use of this line. HSTS (Hypertext Strict Transport Security) makes the S in HTTPS a must-have, making it the standard for client-server communication for the next year of visits. "preload" means that the domain is included in browsers' HSTS preload lists, making sure that S in HTTPS is never excluded from the very first visit.
    if (!ctx.Response.Headers.ContainsKey("Strict-Transport-Security"))
    {
        ctx.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload";
    }

    await _next(ctx);
}
```

*Middleware Registration (Program.cs):*
```csharp
// Add security headers middleware early
app.UseMiddleware<SecurityHeadersMiddleware>();
```

---

## 10. Error Handling & Information Disclosure Prevention

### Feature: Custom Error Pages

**Description:**

Nigh everyone who has ever browsed the internet has seen at least one or two error pages in their lifetime. By default, when no error page is implemented, the are procedurally generated by the web server, which can display technical details about the error which are meant to be kept private. Examples of those details include stack traces, database connection strings with plaintext passwords in them, the file system's structure, and et cetera. These sensitive information, when disclosed, can inadventently give knowledge to prospective attackers, and help them map the system architecture in reconnaissance and plan their invasions accordingly.

The default error page can be safely overwritten with a set of defined error pages, one for each error code. These include 404 (Not Found), 403 (Forbidden), 500 (Internal Server Error), and for some reason, 418 (I'm A Teapot). Errors that are not found in the error list return a generic error message to cover the all possible remaining errors in existence. Detailed error information is only logged on the backend console for some errors such as the Internal Server Error. Introducing custom-made error pages improves the user experience of the site by avoiding to fill the user's peripheral vision with technical jargon. Not only that, internal details will not be disclosed by the error pages, leaving attackers devoid of knowledge of the system architecture.

**Code Implementation:**

*Error Handler Pipeline (Program.cs):*
```csharp
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseStatusCodePagesWithReExecute("/ErrorHandler/{0}");
}
```

*Custom Error Controller (ErrorHandlerController.cs):*
```csharp
[Route("ErrorHandler/{statusCode}")]
public IActionResult HttpStatusCodeHandler(int statusCode)
{
    switch (statusCode)
    {
        case 404:
            ViewBag.ErrorMessage = "Sorry, the resource you requested could not be found.";
            break;
        case 403:
            ViewBag.ErrorMessage = "Sorry, you do not have access to this resource.";
            break;
    }

    return View("Error");
}
```

---

## 11. Data Persistence & Integrity

### Feature: Secure Data Storage

**Description:**

The principle of persistent storage is applied in many ways one of which is the storage of data protection keys that are used to encrypt and decrypt sensitive data. Losing those keys will make the encrypted data permanently undecipherable. For security reasons, they are .gitignored so that they will not be committed and leaked on remote repositories, leading to the compromise of the keys.

Passwords are never stored in plaintext, they are instead hashed with salt with the use of robust algorithms, such as PBKDF2. The salt and the hashed password is stored in the database so that the system can hash the password of a login attempt with the same salt. This hash is then compared with the stored hash to verify if the password is correct.

---

## 12. Authorization & Access Control

### Feature: Role-Based Access Control

**Description:**

Authentication verifies the identity of the user using the identity system, whereas authorization scrutinizes their permissions with role-based checks, and finalizes their privileges that determine what they can access or what actions they can perform. Every sensitive action respective to authorized user, such as viewing their own data, has an [Authorize] attribute on its controller, meaning that the user, and only the user, can perform these actions. Attempting to access a protected resource without the required permissions, or entering a url to a resource that users are not supposed to access, will result in an automatic redirect to a 403 error.

**Code Implementation:**

*Authorization on Controllers (ManageController.cs):*
```csharp
[Authorize]  // Only authenticated users can access
public class ManageController : Controller
{
    public async Task<IActionResult> Index()
    {
        var user = await _userManager.GetUserAsync(User);
        // Only the authenticated user can access their own data
    }
}
```

*Authorization in Program.cs:*
```csharp
bildr.Services.AddIdentity<IdentityUser, IdentityRole>(o =>
{
    // ... configuration ...
})
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();
```

*Login Path Configuration:*
```csharp
bildr.Services.ConfigureApplicationCookie(o =>
{
    o.LoginPath = "/Account/Login";
    o.AccessDeniedPath = "/ErrorHandler/403";
});
```

---

## 13. Security Scanning on Github

**Description:**

Ensuring that an application is free from vulnerabilities is an extremely difficult task. Given this, a tool called CodeQL analyzes the entire codebase on the remote repository and checks for security holes that go unnoticed. At the end of each security evaluation a list of discovered susceptibilities is each of which is assigned a threat level from low to critical.

The first scan performed on the remote repository resulted in 6 alerts raised for every weaknesses in the system, half of which are marked high. The most severe weakness detected is the creation of log entries from user input, where the logs can be fraudulently tampered with the use of control characters such as backspace and newline. This issue is fixed by purging all control characters from the user input.

---

## 14. Security Architecture Diagram

The security features co-operate across multiple layers, as in the below diagram:

```
┌─────────────────────────────────────────────┐
│      USER INPUTS (Registration, Login)      │
├─────────────────────────────────────────────┤
│ Layer 1: Browser-side validation            │
│        - Format checking                    │
│        - Length limits                      │
├─────────────────────────────────────────────┤
│ Layer 2: Bot detection (reCAPTCHA)          │
│        - Prevents automated attacks         │
├─────────────────────────────────────────────┤
│ Layer 3: Server-side validation             │
│        - Re-validates all input             │
│        - SQL injection prevention           │
├─────────────────────────────────────────────┤
│ Layer 4: Encryption                         │
│        - HTTPS for transit                  │
│        - Data encryption at rest            │
├─────────────────────────────────────────────┤
│ Layer 5: Session & Authentication           │
│        - Session timeout                    │
│        - Single session enforcement         │
│        - 2FA verification                   │
├─────────────────────────────────────────────┤
│ Layer 6: Authorization checks               │
│        - Role verification                  │
|        - CSRF token validation              │
├─────────────────────────────────────────────┤
│ Layer 7: Logging & Monitoring               │
│        - Audit trail creation               │
│        - Anomaly detection ready            │
├─────────────────────────────────────────────┤
│          PROTECTED DATA (Database)          │
└─────────────────────────────────────────────┘
```

---

## 15. Conclusion

Using a comprehensive, defense-in-depth security infrastructure, the BookwormsOnline application combines a diverse set of security features, ranging from content security policies to audit logging. Each individual feature addresses one or more attack vectors targeting both the users and the system itself. Other web applications have adapted these security features to safeguard their systems against cyberthreats.

**Key Strengths:**
- Multiple layered defense (browser, application, transport, database)
- Encrypting sensitive data both at rest and in transit
- Strong authentications (password rules + 2FA option)
- Session security (expiration, single session, timeout)
- Attack-specific preventions (CSRF, XSS, SQL injection, MITM)
- Audit logging for accountability and forensics
- Input validation at multiple layers

---
