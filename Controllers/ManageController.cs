using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using BookwormsOnline.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace BookwormsOnline.Controllers
{
    [Authorize]
    public class ManageController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailService _emailService;
        private readonly AuthDbContext _context;

        public ManageController(UserManager<IdentityUser> userManager, IEmailService emailService, AuthDbContext context)
        {
            _userManager = userManager;
            _emailService = emailService;
            _context = context;
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

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Disable2fa()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction(nameof(Index));
            }

            await _userManager.SetTwoFactorEnabledAsync(user, false);

            var audit = new Audit
            {
                UserId = user.Id,
                Action = "Disabled 2FA",
                Timestamp = DateTime.UtcNow,
                Details = $"User {user.Email} disabled two-factor authentication."
            };
            _context.AuditLogs.Add(audit);
            await _context.SaveChangesAsync();

            TempData["Message"] = "Two-factor authentication has been disabled.";
            return RedirectToAction(nameof(Index));
        }
    }
}
