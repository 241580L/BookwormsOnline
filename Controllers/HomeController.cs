using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using BookwormsOnline.Data;
using BookwormsOnline.Models;
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
        private readonly AuthDbContext _context;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IDataProtector _protector;

        public HomeController(ILogger<HomeController> logger, AuthDbContext context, UserManager<IdentityUser> userManager, IDataProtectionProvider dataProtectionProvider)
        {
            _logger = logger;
            _context = context;
            _userManager = userManager;
            _protector = dataProtectionProvider.CreateProtector("BookwormsOnline.CreditCard.v1");
        }

        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                _logger.LogWarning("Authenticated principal did not resolve to a user record.");
                return View(); // safe fallback
            }

            var member = _context.Members.FirstOrDefault(m => m.Email == user.Email);
            if (member == null)
            {
                return View();
            }

            // Guard against null/invalid protected payloads
            var decryptedCreditCardNo = string.Empty;
            if (!string.IsNullOrEmpty(member.CreditCardNo))
            {
                try
                {
                    decryptedCreditCardNo = _protector.Unprotect(member.CreditCardNo) ?? string.Empty;
                }
                catch (Exception ex) when (ex is CryptographicException || ex is ArgumentException)
                {
                    _logger.LogError(ex, "Unable to unprotect credit card for member id {MemberId}.", member.Id);
                    // Keep decryptedCreditCardNo empty (or set masked value) rather than throwing
                    decryptedCreditCardNo = string.Empty;
                }
            }

            var homeViewModel = new HomeViewModel
            {
                Member = member,
                DecryptedCreditCardNo = decryptedCreditCardNo
            };
            return View(homeViewModel);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
