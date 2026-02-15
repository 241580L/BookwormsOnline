using BookwormsOnline.Data;
using BookwormsOnline.Middleware;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.IO;

var bildr = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = bildr.Configuration.GetConnectionString("AuthDbContextConnection") ?? throw new InvalidOperationException("Connection string 'AuthDbContextConnection' not found.");
bildr.Services.AddDbContext<AuthDbContext>(
    /*o is the one-letter abbreviation for "options"*/
    o =>
    o.UseSqlServer(connectionString));

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
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

// Persist data-protection keys (so encrypted data survives restarts)
var keyPath = Path.Combine(bildr.Environment.ContentRootPath, "DataProtection-Keys");
Directory.CreateDirectory(keyPath);
bildr.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keyPath))
    .SetApplicationName("BookwormsOnline");

// reCAPTCHA service
bildr.Services.Configure<ReCaptchaSettings>(bildr.Configuration.GetSection("reCAPTCHA"));
bildr.Services.AddHttpClient<ReCaptchaService>();

// Email service (for sending verification and password reset emails)
bildr.Services.AddScoped<IEmailService, EmailService>();

// Personal-data encryption service
bildr.Services.AddSingleton<IEncryptionService, EncryptionService>();

// Global antiforgery validation for non-GET requests (adds defense-in-depth)
bildr.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new Microsoft.AspNetCore.Mvc.AutoValidateAntiforgeryTokenAttribute());
});

bildr.Services.AddSession(o =>
{
    o.IdleTimeout = TimeSpan.FromMinutes(1);
    o.Cookie.HttpOnly = true;
    o.Cookie.IsEssential = true;
    o.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
    o.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict;
});

// Harden identity cookie
bildr.Services.ConfigureApplicationCookie(o =>
{
    o.Cookie.HttpOnly = true; // prevent JavaScript access and hence XSS attacks
    o.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
    o.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict;
    o.ExpireTimeSpan = TimeSpan.FromMinutes(1);
    o.SlidingExpiration = true;
    o.LoginPath = "/Account/Login";
    o.AccessDeniedPath = "/ErrorHandler/403";
});

// NOTE: Do NOT register middleware type as singleton � UseMiddleware will construct it.
var ap = bildr.Build();

// Configure the HTTP request pipeline.
// Always enable custom status code pages first so all error codes are handled
ap.UseStatusCodePagesWithReExecute("/ErrorHandler/{0}");

// Use exception handler in all environments to show custom error pages instead of raw exceptions
ap.UseExceptionHandler("/Home/Error");

if (!ap.Environment.IsDevelopment())
{
    ap.UseHsts();
}

ap.UseHttpsRedirection();
ap.UseStaticFiles();

// Add security headers middleware early (after static files is fine for dynamic responses)
ap.UseMiddleware<SecurityHeadersMiddleware>();

ap.UseRouting();

ap.UseAuthentication();
ap.UseAuthorization();

ap.UseSession();

// Add the single-session middleware (must run after authentication and session)
ap.UseMiddleware<SingleSessionMiddleware>();

ap.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

ap.Run();
