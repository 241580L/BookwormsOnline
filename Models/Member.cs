using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Models
{
    public class Member
    {
        public int Id { get; set; }

        /// <summary>
        /// Encrypted first name. Max encrypted size: 200 chars for plaintext 50 chars max
        /// </summary>
        [Required, MaxLength(500)]
        public string FirstName { get; set; } = null!;

        /// <summary>
        /// Encrypted last name. Max encrypted size: 200 chars for plaintext 50 chars max
        /// </summary>
        [Required, MaxLength(500)]
        public string LastName { get; set; } = null!;

        /// <summary>
        /// Encrypted credit card number. Max encrypted size: 300 chars for plaintext 19 chars max
        /// </summary>
        [Required, MaxLength(500)]
        public string CreditCardNo { get; set; } = null!;

        /// <summary>
        /// Encrypted mobile number. Max encrypted size: 200 chars for plaintext 20 chars max
        /// </summary>
        [Required, MaxLength(500)]
        public string MobileNo { get; set; } = null!;

        /// <summary>
        /// Encrypted billing address. Max encrypted size: 600 chars for plaintext 200 chars max
        /// </summary>
        [Required, MaxLength(1000)]
        public string BillingAddress { get; set; } = null!;

        /// <summary>
        /// Encrypted shipping address. Max encrypted size: 600 chars for plaintext 200 chars max
        /// </summary>
        [Required, MaxLength(1000)]
        public string ShippingAddress { get; set; } = null!;

        /// <summary>
        /// Encrypted email address. Max encrypted size: 300 chars for plaintext 100 chars max
        /// </summary>
        [Required, MaxLength(500)]
        public string Email { get; set; } = null!;

        // Link to Identity user instead of storing password/hash here.
        [Required]
        public string IdentityUserId { get; set; } = null!;

        public string? PhotoURL { get; set; } = null!;

        public string? SessionId { get; set; } = null!;

        public DateTime PasswordLastChanged { get; set; }
    }
}
