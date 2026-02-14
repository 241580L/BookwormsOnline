using BookwormsOnline.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using System.Threading.Tasks;

namespace BookwormsOnline.Middleware
{
    // Enforces a single active session per user:
    // - On each request, if user is authenticated, compare stored Member.SessionId with current session id.
    // - If mismatch, sign out the current principal and redirect to login. This ensures previous sessions are invalidated on their next request.
    public class SingleSessionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<SingleSessionMiddleware> _logger;

        public SingleSessionMiddleware(RequestDelegate next, ILogger<SingleSessionMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext ctx)
        {
            if (ctx.User?.Identity?.IsAuthenticated == true)
            {
                var userId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (!string.IsNullOrEmpty(userId))
                {
                    try
                    {
                        var db = ctx.RequestServices.GetService(typeof(AuthDbContext)) as AuthDbContext;
                        if (db != null)
                        {
                            var member = await db.Members.FirstOrDefaultAsync(m => m.IdentityUserId == userId);
                            var currentSessionId = ctx.Session.Id;
                            if (member != null && !string.IsNullOrEmpty(member.SessionId) && member.SessionId != currentSessionId)
                            {
                                // Sign out this request because user's stored session does not match (another login exists).
                                _logger.LogInformation("Signing out user {UserId} due to session mismatch.", userId);
                                await ctx.SignOutAsync(IdentityConstants.ApplicationScheme);
                                ctx.Session.Clear();
                                ctx.Response.Redirect("/Account/Login?message=SessionExpired");
                                return;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error validating single session for user {UserId}", userId);
                        // Continue request: fail open but log the incident.
                    }
                }
            }
            await _next(ctx);
        }
    }
}