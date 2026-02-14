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

        public async Task Invoke(HttpContext ctx)
        {
            // Prevent MIME-sniffing
            ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";

            // Prevent clickjacking
            ctx.Response.Headers["X-Frame-Options"] = "DENY";

            // Referrer policy
            ctx.Response.Headers["Referrer-Policy"] = "no-referrer-when-downgrade";

            // Permissions-Policy (formerly Feature-Policy) - restrict features as needed
            ctx.Response.Headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()";

            // Basic CSP — conservative: allow same-origin scripts/styles and inline styles only for legacy.
            // Adjust nonces or hashes for stricter policy in production when using inline scripts/styles.
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

            // HSTS is added by UseHsts in Production pipeline earlier; including a short fallback here is harmless.
            if (!ctx.Response.Headers.ContainsKey("Strict-Transport-Security"))
            {
                ctx.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload";
            }

            await _next(ctx);
        }
    }
}
