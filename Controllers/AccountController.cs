using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using BookwormsOnline.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IO;

namespace BookwormsOnline.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly AuthDbContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly IDataProtector _protector;
        private readonly ReCaptchaService _reCaptchaService;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, AuthDbContext context, IDataProtectionProvider dataProtectionProvider, IWebHostEnvironment webHostEnvironment, ReCaptchaService reCaptchaService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
            _webHostEnvironment = webHostEnvironment;
            _protector = dataProtectionProvider.CreateProtector("BookwormsOnline.CreditCard.v1");
            _reCaptchaService = reCaptchaService;
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
                var user = new IdentityUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    var audit = new Audit
                    {
                        UserId = user.Id,
                        Action = "Register",
                        Timestamp = DateTime.UtcNow,
                        Details = $"User {user.Email} registered successfully."
                    };
                    _context.AuditLogs.Add(audit);

                    var passwordHistory = new PasswordHistory
                    {
                        UserId = user.Id,
                        PasswordHash = user.PasswordHash,
                        CreatedDate = DateTime.UtcNow
                    };
                    _context.PasswordHistories.Add(passwordHistory);

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
                        FirstName = model.FirstName,
                        LastName = model.LastName,
                        CreditCardNo = _protector.Protect(model.CreditCardNo),
                        MobileNo = model.MobileNo,
                        BillingAddress = model.BillingAddress,
                        ShippingAddress = model.ShippingAddress,
                        Email = model.Email,
                        IdentityUserId = user.Id,
                        PhotoURL = photoUrl,
                        PasswordLastChanged = DateTime.UtcNow,
                        SessionId = HttpContext.Session.Id
                    };

                    _context.Members.Add(member);
                    await _context.SaveChangesAsync();

                    return RedirectToAction("Login", "Account");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return View(model);
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
                if (user != null)
                {
                    var member = _context.Members.FirstOrDefault(m => m.Email == model.Email);
                    if (member != null && !string.IsNullOrEmpty(member.SessionId))
                    {
                        // Invalidate previous session
                        await SignOut(member.SessionId);
                    }

                    if (member.PasswordLastChanged.AddDays(90) < DateTime.UtcNow)
                    {
                        ModelState.AddModelError("", "Your password has expired. Please reset your password.");
                        return View(model);
                    }

                    var result = await _signInManager.PasswordSignInAsync(user, model.Password, false, lockoutOnFailure: true);

                    if (result.Succeeded)
                    {
                        member.SessionId = HttpContext.Session.Id;
                        _context.SaveChanges();

                        var audit = new Audit
                        {
                            UserId = user.Id,
                            Action = "Login",
                            Timestamp = DateTime.UtcNow,
                            Details = $"User {user.Email} logged in successfully."
                        };
                        _context.AuditLogs.Add(audit);
                        await _context.SaveChangesAsync();

                        HttpContext.Session.SetString("UserId", user.Id);

                        return RedirectToAction("Index", "Home");
                    }
                    if (result.RequiresTwoFactor)
                    {
                        return RedirectToAction(nameof(LoginWith2fa));
                    }
                }

                var failedLoginAudit = new Audit
                {
                    UserId = user?.Id ?? "N/A",
                    Action = "Login Failure",
                    Timestamp = DateTime.UtcNow,
                    Details = $"Failed login attempt for email {model.Email}."
                };
                _context.AuditLogs.Add(failedLoginAudit);
                await _context.SaveChangesAsync();

                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult LoginWith2fa()
        {
            return View();
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

            var authenticatorCode = model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, false, model.RememberMachine);

            if (result.Succeeded)
            {
                var audit = new Audit
                {
                    UserId = user.Id,
                    Action = "Login with 2FA",
                    Timestamp = DateTime.UtcNow,
                    Details = $"User {user.Email} logged in with 2FA."
                };
                _context.AuditLogs.Add(audit);
                await _context.SaveChangesAsync();

                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
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
                    var passwordResetLink = Url.Action("ResetPassword", "Account", new { email = model.Email, token = token }, Request.Scheme);

                    Console.WriteLine(passwordResetLink); // Cannot send email, so logging to console

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
                        var member = _context.Members.FirstOrDefault(m => m.Email == model.Email);
                        if (member != null)
                        {
                            member.PasswordLastChanged = DateTime.UtcNow;
                            _context.SaveChanges();
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

                var member = _context.Members.FirstOrDefault(m => m.Email == user.Email);
                if (member != null && member.PasswordLastChanged.AddDays(1) > DateTime.UtcNow)
                {
                    ModelState.AddModelError("", "You cannot change your password more than once every 24 hours.");
                    return View(model);
                }

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

                var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
                if (result.Succeeded)
                {
                    var passwordHistory = new PasswordHistory
                    {
                        UserId = user.Id,
                        PasswordHash = user.PasswordHash,
                        CreatedDate = DateTime.UtcNow
                    };
                    _context.PasswordHistories.Add(passwordHistory);

                    if (member != null)
                    {
                        member.PasswordLastChanged = DateTime.UtcNow;
                        _context.SaveChanges();
                    }

                    var audit = new Audit
                    {
                        UserId = user.Id,
                        Action = "Change Password",
                        Timestamp = DateTime.UtcNow,
                        Details = "User changed their password successfully."
                    };
                    _context.AuditLogs.Add(audit);
                    await _context.SaveChangesAsync();

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
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var userId = _userManager.GetUserId(User);
            var member = _context.Members.FirstOrDefault(m => m.Email == User.Identity.Name);
            if (member != null)
            {
                member.SessionId = null;
                _context.SaveChanges();
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
            _context.AuditLogs.Add(audit);
            await _context.SaveChangesAsync();

            return RedirectToAction("Login", "Account");
        }

        public async Task SignOut(string sessionId)
        {
            var member = _context.Members.FirstOrDefault(m => m.SessionId == sessionId);
            if (member != null)
            {
                member.SessionId = null;
                _context.SaveChanges();
            }
            await _signInManager.SignOutAsync();
        }
    }
}
