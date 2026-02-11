namespace BookwormsOnline.ViewModels
{
    public class ManageViewModel
    {
        public bool HasAuthenticator { get; set; }
        public bool IsTwoFactorEnabled { get; set; }
        public int RecoveryCodesLeft { get; set; }
    }
}
