using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.ViewModels
{
    public class Register
    { 
        /// <summary>
        /// First name - max 50 characters to prevent overflow attacks
        /// </summary>
        [Required(ErrorMessage = "First name is required")]
        [StringLength(50, MinimumLength = 1, ErrorMessage = "First name must be between 1 and 50 characters")]
        public string FirstName { get; set; }

        /// <summary>
        /// Last name - max 50 characters to prevent overflow attacks
        /// </summary>
        [Required(ErrorMessage = "Last name is required")]
        [StringLength(50, MinimumLength = 1, ErrorMessage = "Last name must be between 1 and 50 characters")]
        public string LastName { get; set; }

        /// <summary>
        /// Credit card number - standard validation + length limit (13-19 digits)
        /// </summary>
        [Required(ErrorMessage = "Credit card number is required")]
        [StringLength(19, MinimumLength = 13, ErrorMessage = "Credit card number must be between 13 and 19 digits")]
        [RegularExpression(@"^\d[\d\s\-]{11,17}\d$", ErrorMessage = "Please enter a valid credit card number")]
        public string CreditCardNo { get; set; }

        /// <summary>
        /// Mobile number - international format support, max 20 chars
        /// </summary>
        [Required(ErrorMessage = "Mobile number is required")]
        [StringLength(20, MinimumLength = 7, ErrorMessage = "Mobile number must be between 7 and 20 characters")]
        [RegularExpression(@"^[\d\s\+\-\(\)]{7,20}$", ErrorMessage = "Please enter a valid mobile number")]
        public string MobileNo { get; set; }

        /// <summary>
        /// Billing address - max 200 characters to prevent overflow attacks
        /// </summary>
        [Required(ErrorMessage = "Billing address is required")]
        [StringLength(200, MinimumLength = 5, ErrorMessage = "Billing address must be between 5 and 200 characters")]
        public string BillingAddress { get; set; }

        /// <summary>
        /// Shipping address - max 200 characters to prevent overflow attacks
        /// </summary>
        [Required(ErrorMessage = "Shipping address is required")]
        [StringLength(200, MinimumLength = 5, ErrorMessage = "Shipping address must be between 5 and 200 characters")]
        public string ShippingAddress { get; set; }

        /// <summary>
        /// Email address - max 100 characters to prevent overflow attacks
        /// </summary>
        [Required(ErrorMessage = "Email address is required")]
        [StringLength(100, MinimumLength = 5, ErrorMessage = "Email must be between 5 and 100 characters")]
        [EmailAddress(ErrorMessage = "Please enter a valid email address")]
        public string Email { get; set; }

        /// <summary>
        /// Password - enforces minimum strength requirements (12+ chars, mixed case, digits, special chars)
        /// </summary>
        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{12,}$", ErrorMessage = "Password must be at least 12 characters long and contain uppercase letters, lowercase letters, numbers, and special characters.")]
        public string Password { get; set; }

        /// <summary>
        /// Password confirmation - must match password field
        /// </summary>
        [Required(ErrorMessage = "Please confirm your password")]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }

        /// <summary>
        /// Photo upload - JPG only, max 2MB
        /// </summary>
        public IFormFile Photo { get; set; }

        /// <summary>
        /// reCAPTCHA token for validation
        /// </summary>
        public string recaptcha_token { get; set; }
    }
}
