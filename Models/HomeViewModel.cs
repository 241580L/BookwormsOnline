using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Models
{
    public class HomeViewModel
    {
        [Required]
        public Member Member { get; set; }


        [Required]
        public string DecryptedCreditCardNo { get; set; }
    }
}