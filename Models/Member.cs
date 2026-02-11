using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Models
{
    public class Member
    {
        public int Id { get; set; }

        [Required, MaxLength(100)]
        public string FirstName { get; set; } = null!;

        [Required, MaxLength(100)]
        public string LastName { get; set; } = null!;

        [Required, CreditCard]
        public string CreditCardNo { get; set; } = null!;

        [Required, Phone]
        public string MobileNo { get; set; } = null!;

        [Required, MaxLength(255)]
        public string BillingAddress { get; set; } = null!;

        [Required, MaxLength(255)]
        public string ShippingAddress { get; set; } = null!;

        [Required, EmailAddress]
        public string Email { get; set; } = null!;

        // Link to Identity user instead of storing password/hash here.
        [Required]
        public string IdentityUserId { get; set; } = null!;

        public string? PhotoURL { get; set; } = null!;

        public string? SessionId { get; set; } = null!;

        public DateTime PasswordLastChanged { get; set; }
    }
}
