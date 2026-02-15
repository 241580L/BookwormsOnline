using BookwormsOnline.Models;

namespace BookwormsOnline.ViewModels
{
    public class HomeViewModel
    {
        public Member Member { get; set; }
        public string DecryptedFirstName { get; set; }
        public string DecryptedLastName { get; set; }
        public string DecryptedEmail { get; set; }
        public string DecryptedMobileNo { get; set; }
        public string DecryptedBillingAddress { get; set; }
        public string DecryptedShippingAddress { get; set; }
        public string DecryptedCreditCardNo { get; set; }
    }
}
