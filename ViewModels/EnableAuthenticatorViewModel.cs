using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.ViewModels
{
    public class EnableAuthenticatorViewModel
    {
        [Required]
        public string Code { get; set; }
        public string SharedKey { get; set; }
        public string AuthenticatorUri { get; set; }
    }
}
