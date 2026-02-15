using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

namespace BookwormsOnline.ViewModels
{
    public class ChangeCredentials
    {
        [Required(ErrorMessage = "First name is required")]
        [StringLength(50, MinimumLength = 1, ErrorMessage = "First name must be between 1 and 50 characters")]
        public string FirstName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Last name is required")]
        [StringLength(50, MinimumLength = 1, ErrorMessage = "Last name must be between 1 and 50 characters")]
        public string LastName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mobile number is required")]
        [StringLength(20, MinimumLength = 7, ErrorMessage = "Mobile number must be between 7 and 20 characters")]
        [RegularExpression(@"^[\d\s\+\-\(\)]{7,20}$", ErrorMessage = "Please enter a valid mobile number")]
        [Display(Name = "Mobile number")]
        public string MobileNo { get; set; } = string.Empty;

        [Required(ErrorMessage = "Billing address is required")]
        [StringLength(200, MinimumLength = 5, ErrorMessage = "Billing address must be between 5 and 200 characters")]
        [Display(Name = "Billing address")]
        public string BillingAddress { get; set; } = string.Empty;

        [Required(ErrorMessage = "Shipping address is required")]
        [StringLength(200, MinimumLength = 5, ErrorMessage = "Shipping address must be between 5 and 200 characters")]
        [Display(Name = "Shipping address")]
        public string ShippingAddress { get; set; } = string.Empty;

        // Photo upload (JPG only, max 2MB). Leave empty to keep existing photo.
        [Display(Name = "Profile photo (JPG, max 2MB)")]
        public IFormFile? PhotoFile { get; set; }

        // Original photo URL so the post action can revert back to the pre-edit photo if requested
        public string? OriginalPhotoURL { get; set; }

        // If true, revert to the original photo (ignore uploaded file)
        public bool Revert { get; set; }
    }
}
