using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using BookwormsOnline.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.IO;

namespace BookwormsOnline.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly AuthDbContext _ctx;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly IDataProtector _protector;
        private readonly ReCaptchaService _reCaptchaService;
        private readonly IEmailService _emailService;
        private readonly IEncryptionService _encryptionService;

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

        public IActionResult Register()
        {
            return View();
        }

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
                var existingUser = await _userManager.FindByEmailAsync(model.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError(string.Empty, $"Email '{model.Email}' is already taken.");
                    return View(model);
                }

                var user = new IdentityUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    // Generate email confirmation token and send email
                    var emailConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmationLink = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, token = emailConfirmationToken }, Request.Scheme);

                    // Send confirmation email
                    var emailSubject = "Confirm Your Bookworms Online Account";
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
        .button {{ display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Welcome to Bookworms Online!</h1>
        </div>
        <div class='content'>
            <p>Hello {user.Email},</p>
            <p>Thank you for registering with Bookworms Online. Please confirm your email address by clicking the button below:</p>
            <p style='text-align: center; margin: 30px 0;'>
                <a href='{confirmationLink}' class='button'>Confirm Email Address</a>
            </p>
            <p>Or copy and paste this link in your browser:</p>
            <p>{confirmationLink}</p>
            <p>This link will expire in 24 hours.</p>
            <p>If you did not create this account, please ignore this email.</p>
        </div>
        <div class='footer'>
            <p>&copy; 2026 Bookworms Online. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";

                    await _emailService.SendEmailAsync(user.Email, emailSubject, emailBody);

                    var audit = new Audit
                    {
                        UserId = user.Id,
                        Action = "Register",
                        Timestamp = DateTime.UtcNow,
                        Details = $"User {user.Email} registered successfully. Confirmation email sent."
                    };
                    _ctx.AuditLogs.Add(audit);

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

                    string photoUrl = null;

                    if (model.Photo != null && model.Photo.Length > 0)
                    {
                        // Validate image size (max 2MB) and content type
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

                    _ctx.Members.Add(member);
                    await _ctx.SaveChangesAsync();

                    return RedirectToAction("Login", "Account", new { message = "ConfirmEmailSent" });
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(token))
            {
                return BadRequest("Invalid email confirmation request.");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                var audit = new Audit
                {
                    UserId = user.Id,
                    Action = "Confirm Email",
                    Timestamp = DateTime.UtcNow,
                    Details = $"User {user.Email} confirmed their email address."
                };
                _ctx.AuditLogs.Add(audit);
                await _ctx.SaveChangesAsync();

                return RedirectToAction("Login", "Account");
            }

            return BadRequest("Email confirmation failed. The token may have expired.");
        }

        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(Login model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                Microsoft.AspNetCore.Identity.SignInResult result = null;
                BookwormsOnline.Models.Member member = null;

                if (user != null)
                {
                    member = _ctx.Members.FirstOrDefault(m => m.IdentityUserId == user.Id);
                    if (member != null && !string.IsNullOrEmpty(member.SessionId))
                    {
                        // Invalidate previous session
                        await SignOut(member.SessionId);
                    }

                    if (member != null && member.PasswordLastChanged.AddDays(90) < DateTime.UtcNow)
                    {
                        ModelState.AddModelError("", "Your password has expired. Please reset your password.");
                        return View(model);
                    }

                    result = await _signInManager.PasswordSignInAsync(user, model.Password, false, lockoutOnFailure: true);

                    if (result.Succeeded)
                    {
                        if (member != null)
                        {
                            member.SessionId = HttpContext.Session.Id;
                            _ctx.SaveChanges();
                        }

                        var audit = new Audit
                        {
                            UserId = user.Id,
                            Action = "Login",
                            Timestamp = DateTime.UtcNow,
                            Details = $"User {user.Email} logged in successfully."
                        };
                        _ctx.AuditLogs.Add(audit);
                        await _ctx.SaveChangesAsync();

                        Console.WriteLine($"Setting User ID");
                        HttpContext.Session.SetString("UserId", user.Id);

                        return RedirectToAction("Index", "Home");
                    }

                    if (result.RequiresTwoFactor)
                    {
                        // Send 2FA code via email (short numeric via Email two-factor provider)
                        var code = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
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
            <h1>Login Verification</h1>
        </div>
        <div class='content'>
            <p>Hello {user.Email},</p>
            <p>Someone tried to log in to your Bookworms Online account. Your verification code is:</p>
            <div class='code'>{code}</div>
            <p>This code will expire in 15 minutes.</p>
            <p>If you did not attempt to log in, please ignore this email and your account will remain secure.</p>
        </div>
        <div class='footer'>
            <p>&copy; 2026 Bookworms Online. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";
                        await _emailService.SendEmailAsync(user.Email, "Login Verification Code", emailBody);
                        return RedirectToAction(nameof(LoginWith2fa));
                    }
                }

                // Handle cases where sign-in did not succeed (or user was null)
                if (result != null)
                {
                    if (result.IsLockedOut)
                    {
                        var audit = new Audit
                        {
                            UserId = user?.Id ?? "N/A",
                            Action = "Login LockedOut",
                            Timestamp = DateTime.UtcNow,
                            Details = $"Account locked out for email {model.Email} due to failed attempts."
                        };
                        _ctx.AuditLogs.Add(audit);
                        await _ctx.SaveChangesAsync();

                        ModelState.AddModelError(string.Empty, "You have made too many failed login attempts. Try again in a minute.");
                    }
                    else if (result.IsNotAllowed)
                    {
                        // Usually indicates the account is not allowed to sign in (commonly email not confirmed)
                        if (user != null && !await _userManager.IsEmailConfirmedAsync(user))
                        {
                            // Redirect user to a page where they can resend confirmation
                            return RedirectToAction("ResendConfirmation", new { email = model.Email });
                        }

                        var audit = new Audit
                        {
                            UserId = user?.Id ?? "N/A",
                            Action = "Login NotAllowed",
                            Timestamp = DateTime.UtcNow,
                            Details = $"NotAllowed login attempt for email {model.Email}."
                        };
                        _ctx.AuditLogs.Add(audit);
                        await _ctx.SaveChangesAsync();

                        ModelState.AddModelError(string.Empty, "Your account is not allowed to sign in.");
                    }
                    else
                    {
                        var failedLoginAudit = new Audit
                        {
                            UserId = user?.Id ?? "N/A",
                            Action = "Login Failure",
                            Timestamp = DateTime.UtcNow,
                            Details = $"Failed login attempt for email {model.Email}."
                        };
                        _ctx.AuditLogs.Add(failedLoginAudit);
                        await _ctx.SaveChangesAsync();

                        ModelState.AddModelError(string.Empty, "Invalid email or password.");
                    }
                }
                else
                {
                    // No result indicates user was null or sign-in was not attempted; avoid revealing which
                    var failedLoginAudit = new Audit
                    {
                        UserId = user?.Id ?? "N/A",
                        Action = "Login Failure",
                        Timestamp = DateTime.UtcNow,
                        Details = $"Failed login attempt for email {model.Email}."
                    };
                    _ctx.AuditLogs.Add(failedLoginAudit);
                    await _ctx.SaveChangesAsync();

                    ModelState.AddModelError(string.Empty, "Invalid email or password.");
                }
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult LoginWith2fa()
        {
            ViewBag.Message = TempData["Message"] as string;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Resend2fa()
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
            }

            var code = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
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
            <h1>Login Verification</h1>
        </div>
        <div class='content'>
            <p>Hello {user.Email},</p>
            <p>Your new verification code is:</p>
            <div class='code'>{code}</div>
            <p>This code will expire in 15 minutes.</p>
        </div>
        <div class='footer'>
            <p>&copy; 2026 Bookworms Online. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";

            await _emailService.SendEmailAsync(user.Email, "Login Verification Code", emailBody);
            TempData["Message"] = "A new verification code has been sent to your email.";
            return RedirectToAction(nameof(LoginWith2fa));
        }

        [HttpGet]
        public IActionResult ResendConfirmation(string email)
        {
            var model = new BookwormsOnline.ViewModels.ResendEmailViewModel { Email = email };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResendConfirmation(BookwormsOnline.ViewModels.ResendEmailViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null && !await _userManager.IsEmailConfirmedAsync(user))
            {
                var emailConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, token = emailConfirmationToken }, Request.Scheme);
                var emailSubject = "Confirm Your Bookworms Online Account";
                var emailBody = $@"Please confirm your email by clicking the link: {confirmationLink}";
                await _emailService.SendEmailAsync(user.Email, emailSubject, emailBody);
            }

            // To avoid user enumeration, always show the same confirmation message
            model.Message = "If an account with that email exists, a confirmation email has been sent.";
            return View(model);
        }

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
                // Retrieve or create Member record and set SessionId for single-session enforcement
                var member = _ctx.Members.FirstOrDefault(m => m.IdentityUserId == user.Id);
                if (member != null)
                {
                    member.SessionId = HttpContext.Session.Id;
                }

                var audit = new Audit
                {
                    UserId = user.Id,
                    Action = "Login with 2FA",
                    Timestamp = DateTime.UtcNow,
                    Details = $"User {user.Email} logged in with 2FA."
                };
                _ctx.AuditLogs.Add(audit);
                
                // Set session UserId for client-side validation and session extension
                HttpContext.Session.SetString("UserId", user.Id);
                
                await _ctx.SaveChangesAsync();

                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid email code. Please check your email.");
                return View(model);
            }
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var pwdResetLink = Url.Action("ResetPassword", "Account", new { email = model.Email, token = token }, Request.Scheme);

                    // Send password reset email
                    var emailSubject = "Reset Your Bookworms Online Password";
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
        .button {{ display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Password Reset Request</h1>
        </div>
        <div class='content'>
            <p>Hello {user.Email},</p>
            <p>We received a request to reset the password for your Bookworms Online account. Click the button below to reset your password:</p>
            <p style='text-align: center; margin: 30px 0;'>
                <a href='{pwdResetLink}' class='button'>Reset Password</a>
            </p>
            <p>Or copy and paste this link in your browser:</p>
            <p>{pwdResetLink}</p>
            <p>This link will expire in 24 hours.</p>
            <p>If you did not request a password reset, please ignore this email and your password will remain unchanged.</p>
        </div>
        <div class='footer'>
            <p>&copy; 2026 Bookworms Online. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";

                    await _emailService.SendEmailAsync(user.Email, emailSubject, emailBody);

                    return View("ForgotPasswordConfirmation");
                }

                // To prevent enumeration attacks, don't reveal that the user does not exist
                return View("ForgotPasswordConfirmation");
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            var model = new ResetPasswordViewModel { Token = token, Email = email };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
                    if (result.Succeeded)
                    {
                        var member = _ctx.Members.FirstOrDefault(m => m.IdentityUserId == user.Id);
                        if (member != null)
                        {
                            member.PasswordLastChanged = DateTime.UtcNow;
                            _ctx.SaveChanges();
                        }
                        return View("ResetPasswordConfirmation");
                    }

                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }

                    return View(model);
                }

                // To prevent enumeration attacks, don't reveal that the user does not exist
                return View("ResetPasswordConfirmation");
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }


        [Authorize]
        public IActionResult ChangePassword()
        {
            return View();
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePassword model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                {
                    return RedirectToAction("Login");
                }

                var member = _ctx.Members.FirstOrDefault(m => m.IdentityUserId == user.Id);
                if (member != null && member.PasswordLastChanged.AddMinutes(1) > DateTime.UtcNow)
                {
                    ModelState.AddModelError("", "You cannot change your password more than once per minute.");
                    return View(model);
                }

                var pwdHistories = _ctx.PasswordHistories.Where(p => p.UserId == user.Id).OrderByDescending(p => p.CreatedDate).Take(2).ToList();
                foreach (var pwdHistory in pwdHistories)
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

                var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
                if (result.Succeeded)
                {
                    var newSalt = GenerateSalt();
                    var newHash = HashPasswordWithSalt(model.NewPassword, newSalt);
                    var pwdHistory = new PasswordHistory
                    {
                        UserId = user.Id,
                        PasswordHash = newHash,
                        Salt = newSalt,
                        CreatedDate = DateTime.UtcNow
                    };
                    _ctx.PasswordHistories.Add(pwdHistory);

                    if (member != null)
                    {
                        member.PasswordLastChanged = DateTime.UtcNow;
                        _ctx.SaveChanges();
                    }

                    var audit = new Audit
                    {
                        UserId = user.Id,
                        Action = "Change Password",
                        Timestamp = DateTime.UtcNow,
                        Details = "User changed their password successfully."
                    };
                    _ctx.AuditLogs.Add(audit);
                    await _ctx.SaveChangesAsync();

                    await _signInManager.RefreshSignInAsync(user);
                    return RedirectToAction("Index", "Home");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }
            return View(model);
        }

        [HttpPost]
        [Authorize]
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

        public async Task SignOut(string sessionId)
        {
            var member = _ctx.Members.FirstOrDefault(m => m.SessionId == sessionId);
            if (member != null)
            {
                member.SessionId = null;
                _ctx.SaveChanges();
            }
            await _signInManager.SignOutAsync();
        }

        private string GenerateSalt(int size = 16)
        {
            var saltBytes = new byte[size];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(saltBytes);
            }
            return Convert.ToBase64String(saltBytes);
        }

        private string HashPasswordWithSalt(string password, string salt, int iterations = 100_000, int hashByteSize = 32)
        {
            var saltBytes = Convert.FromBase64String(salt);
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, saltBytes, iterations, HashAlgorithmName.SHA256))
            {
                var hash = pbkdf2.GetBytes(hashByteSize);
                return Convert.ToBase64String(hash);
            }
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> CheckSessionValid()
        {
            // This endpoint is called via AJAX to check if the session is still valid
            // and to extend the server-side session timeout by writing to session.
            var userId = _userManager.GetUserId(User);
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }
            
            // Write to session to extend its timeout (required for session sliding expiration to work)
            HttpContext.Session.SetString("UserId", userId);
            var currentSessionId = HttpContext.Session.Id;
            
            // Also update Member.SessionId to ensure single-session enforcement stays valid
            var member = _ctx.Members.FirstOrDefault(m => m.IdentityUserId == userId);
            if (member != null && member.SessionId != currentSessionId)
            {
                member.SessionId = currentSessionId;
                await _ctx.SaveChangesAsync();
            }

            return Json(new { valid = true, sessionId = currentSessionId });
        }

        private bool SecureEquals(string aBase64, string bBase64)
        {
            if (string.IsNullOrEmpty(aBase64) || string.IsNullOrEmpty(bBase64))
                return false;

            try
            {
                var a = Convert.FromBase64String(aBase64);
                var b = Convert.FromBase64String(bBase64);
                return CryptographicOperations.FixedTimeEquals(a, b);
            }
            catch
            {
                return false;
            }
        }
    }
}
