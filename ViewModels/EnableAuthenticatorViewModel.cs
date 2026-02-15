using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.ViewModels
{
    public class EnableAuthenticatorViewModel
    {
        [Required]
        [StringLength(6, ErrorMessage = "The {0} must be {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Text)]
        [Display(Name = "Email Code")]
        public string Code { get; set; }
    }
}
