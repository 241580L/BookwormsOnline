using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.ViewModels
{
    public class ResendEmailViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        // Optional: message to show on view after resend
        public string Message { get; set; }
    }
}
