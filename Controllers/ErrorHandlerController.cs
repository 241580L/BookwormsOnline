using Microsoft.AspNetCore.Mvc;

namespace BookwormsOnline.Controllers
{
    public class ErrorHandlerController : Controller
    {
        [Route("ErrorHandler/{statusCode}")]
        public IActionResult HttpStatusCodeHandler(int statusCode)
        {
            switch (statusCode)
            {
                case 404:
                    ViewBag.ErrorMessage = "Sorry, the resource you requested could not be found.";
                    break;
                case 403:
                    ViewBag.ErrorMessage = "Sorry, you do not have access to this resource.";
                    break;
            }

            return View("Error");
        }
    }
}
