using BookwormsOnline.Models;

namespace BookwormsOnline.ViewModels
{
    public class HomeViewModel
    {
        public Member Member { get; set; }
        public string DecryptedCreditCardNo { get; set; }
    }
}
