using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using BookwormsOnline.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace BookwormsOnline.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly AuthDbContext _ctx;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IDataProtector _protector;
        private readonly IEncryptionService _encryptionService;

        public HomeController(ILogger<HomeController> logger, AuthDbContext ctx, UserManager<IdentityUser> userManager, IDataProtectionProvider dataProtectionProvider, IEncryptionService encryptionService)
        {
            _logger = logger;
            _ctx = ctx;
            _userManager = userManager;
            _protector = dataProtectionProvider.CreateProtector("BookwormsOnline.CreditCard.v1");
            _encryptionService = encryptionService;
        }

        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                _logger.LogWarning("Authenticated principal did not resolve to a user record.");
                return View(); // safe fallback
            }

            var member = _ctx.Members.FirstOrDefault(m => m.IdentityUserId == user.Id);
            if (member == null)
            {
                return View();
            }

            // Guard against null/invalid protected payloads and decrypt all sensitive fields
            var decryptedCreditCardNo = string.Empty;
            var decryptedFirstName = string.Empty;
            var decryptedLastName = string.Empty;
            var decryptedMobileNo = string.Empty;
            var decryptedBillingAddress = string.Empty;
            var decryptedShippingAddress = string.Empty;
            var decryptedEmail = string.Empty;

            try
            {
                if (!string.IsNullOrEmpty(member.FirstName))
                    decryptedFirstName = _encryptionService.Decrypt(member.FirstName) ?? string.Empty;
                if (!string.IsNullOrEmpty(member.LastName))
                    decryptedLastName = _encryptionService.Decrypt(member.LastName) ?? string.Empty;
                if (!string.IsNullOrEmpty(member.MobileNo))
                    decryptedMobileNo = _encryptionService.Decrypt(member.MobileNo) ?? string.Empty;
                if (!string.IsNullOrEmpty(member.BillingAddress))
                    decryptedBillingAddress = _encryptionService.Decrypt(member.BillingAddress) ?? string.Empty;
                if (!string.IsNullOrEmpty(member.ShippingAddress))
                    decryptedShippingAddress = _encryptionService.Decrypt(member.ShippingAddress) ?? string.Empty;
                if (!string.IsNullOrEmpty(member.Email))
                    decryptedEmail = _encryptionService.Decrypt(member.Email) ?? string.Empty;
                if (!string.IsNullOrEmpty(member.CreditCardNo))
                    decryptedCreditCardNo = _encryptionService.Decrypt(member.CreditCardNo) ?? string.Empty;
            }
            catch (Exception ex) when (ex is CryptographicException || ex is ArgumentException || ex is InvalidOperationException)
            {
                _logger.LogError(ex, "Unable to decrypt sensitive data for member id {MemberId}.", member.Id);
                // Keep values empty rather than throwing
            }

            var homeViewModel = new HomeViewModel
            {
                Member = member,
                DecryptedFirstName = decryptedFirstName,
                DecryptedLastName = decryptedLastName,
                DecryptedMobileNo = decryptedMobileNo,
                DecryptedBillingAddress = decryptedBillingAddress,
                DecryptedShippingAddress = decryptedShippingAddress,
                DecryptedEmail = decryptedEmail,
                DecryptedCreditCardNo = decryptedCreditCardNo
            };
            return View(homeViewModel);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        [AllowAnonymous]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
