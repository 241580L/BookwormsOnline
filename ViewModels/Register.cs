using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.ViewModels
{
    public class Register
    { 
        [Required, MaxLength(100)]
        public string FirstName { get; set; }

        [Required, MaxLength(100)]
        public string LastName { get; set; }

        [Required, CreditCard]
        public string CreditCardNo { get; set; }

        [Required, Phone]
        public string MobileNo { get; set; }

        [Required, MaxLength(255)]
        public string BillingAddress { get; set; }

        [Required, MaxLength(255)]
        public string ShippingAddress { get; set; }

        [Required, EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{12,}$", ErrorMessage = "Password must be at least 12 characters long and contain uppercase letters, lowercase letters, numbers, and special characters.")]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }

        public IFormFile Photo { get; set; }

        public string recaptcha_token { get; set; }
    }
}
