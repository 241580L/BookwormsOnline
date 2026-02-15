using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Models
{
    public class PasswordHistory
    {
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; }

        [Required]
        public string PasswordHash { get; set; }

        [Required]
        public string Salt { get; set; }

        [Required]
        public DateTime CreatedDate { get; set; }
    }
}
