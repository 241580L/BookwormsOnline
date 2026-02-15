using Microsoft.AspNetCore.Mvc;

namespace BookwormsOnline.Controllers
{
    public class ErrorHandlerController : Controller
    {
        [Route("ErrorHandler/{statusCode}")]
        public IActionResult HttpStatusCodeHandler(int statusCode)
        {
            string viewName = statusCode.ToString();
            switch (statusCode)
            {
                case 400:
                    ViewBag.ErrorMessage = "The request was invalid.";
                    break;
                case 404:
                    ViewBag.ErrorMessage = "Sorry, the resource you requested could not be found.";
                    break;
                case 403:
                    ViewBag.ErrorMessage = "Sorry, you do not have access to this resource.";
                    break;
                case 500:
                    ViewBag.ErrorMessage = "Sorry, an internal server error occured.";
                    break;
                case 503:
                    ViewBag.ErrorMessage = "Sorry, the service is unavailable.";
                    break;
                case 502:
                    ViewBag.ErrorMessage = "Cuckoo, the request timed out.";
                    break;
                case 418:
                    ViewBag.ErrorMessage = "I'm a little teapot, short and stout.\nHere is my handle and here is my spout.\nWhen I get all steamed up, hear me shout:\n\"Tip me over and pour me out!\"";
                    break;
                default:
                    ViewBag.ErrorMessage = $"Sorry, an error occured.";
                    viewName = "Generic";
                    break;
            }

            ViewBag.ErrorMessage += $"\nError Code: {statusCode}";

            return View(viewName);
        }
    }
}
