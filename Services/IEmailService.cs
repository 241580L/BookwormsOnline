namespace BookwormsOnline.Services
{
    public interface IEmailService
    {
        /// <summary>
        /// Sends an email message.
        /// </summary>
        /// <param name="to">Recipient email address</param>
        /// <param name="subject">Email subject</param>
        /// <param name="htmlContent">Email body in HTML format</param>
        /// <returns>True if email was sent successfully, false otherwise</returns>
        Task<bool> SendEmailAsync(string to, string subject, string htmlContent);
    }
}
