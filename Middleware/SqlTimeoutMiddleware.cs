
using Microsoft.AspNetCore.Http;
using Microsoft.Data.SqlClient;
using System.Threading.Tasks;

namespace BookwormsOnline.Middleware
{
    public class SqlTimeoutMiddleware
    {
        private readonly RequestDelegate _next;

        public SqlTimeoutMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (SqlException ex) when (ex.Number == -2)
            {
                // SQL Server timeout error
                context.Response.Redirect("/ErrorHandler/504");
            }
        }
    }
}
