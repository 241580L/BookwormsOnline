using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace BookwormsOnline.Middleware
{
    // Adds common security response headers including a conservative CSP.
    public class SecurityHeadersMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<SecurityHeadersMiddleware> _logger;

        public SecurityHeadersMiddleware(RequestDelegate next, ILogger<SecurityHeadersMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context)
        {
            // Prevent MIME-sniffing
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";

            // Prevent clickjacking
            context.Response.Headers["X-Frame-Options"] = "DENY";

            // Referrer policy
            context.Response.Headers["Referrer-Policy"] = "no-referrer-when-downgrade";

            // Permissions-Policy (formerly Feature-Policy) - restrict features as needed
            context.Response.Headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()";

            // Basic CSP — conservative: allow same-origin scripts/styles and inline styles only for legacy.
            // Adjust nonces or hashes for stricter policy in production when using inline scripts/styles.
            var csp = "default-src 'self'; " +
                      "script-src 'self' https://www.google.com https://www.gstatic.com https://www.recaptcha.net 'unsafe-inline'; " +
                      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
                      "img-src 'self' data:; " +
                      "font-src 'self' https://fonts.gstatic.com; " +
                      "connect-src 'self' https://www.google.com https://www.recaptcha.net; " +
                      "frame-ancestors 'none'; " +
                      "base-uri 'self';";
            context.Response.Headers["Content-Security-Policy"] = csp;

            // HSTS is added by UseHsts in Production pipeline earlier; including a short fallback here is harmless.
            if (!context.Response.Headers.ContainsKey("Strict-Transport-Security"))
            {
                context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload";
            }

            await _next(context);
        }
    }
}
