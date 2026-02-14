using System.Net;
using System.Net.Mail;

namespace BookwormsOnline.Services
{
    /// <summary>
    /// Email service for sending emails via SMTP.
    /// Supports any SMTP provider (SendGrid, Mailgun, Mailtrap, Gmail, etc.)
    /// </summary>
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<bool> SendEmailAsync(string to, string subject, string htmlContent)
        {
            try
            {
                // Validate inputs
                if (string.IsNullOrWhiteSpace(to))
                {
                    _logger.LogError("Recipient email address is empty");
                    return false;
                }

                if (string.IsNullOrWhiteSpace(subject))
                {
                    _logger.LogError("Email subject is empty");
                    return false;
                }

                // Get SMTP configuration
                var smtpHost = _configuration["EmailSettings:SmtpHost"];
                var smtpPort = _configuration["EmailSettings:SmtpPort"];
                var smtpUsername = _configuration["EmailSettings:SmtpUsername"];
                var smtpPassword = _configuration["EmailSettings:SmtpPassword"];
                var fromEmail = _configuration["EmailSettings:FromEmail"];
                var fromName = _configuration["EmailSettings:FromName"];
                var enableSsl = _configuration["EmailSettings:EnableSsl"];

                // Validate configuration
                if (string.IsNullOrWhiteSpace(smtpHost) || string.IsNullOrWhiteSpace(smtpPort) ||
                    string.IsNullOrWhiteSpace(smtpUsername) || string.IsNullOrWhiteSpace(fromEmail))
                {
                    _logger.LogError("Email configuration is incomplete. Please check appsettings.json");
                    return false;
                }

                if (!int.TryParse(smtpPort, out var port))
                {
                    _logger.LogError("Invalid SMTP port configuration");
                    return false;
                }

                // Create SMTP client
                using (var smtpClient = new SmtpClient(smtpHost, port))
                {
                    // Configure SMTP client
                    smtpClient.Credentials = new NetworkCredential(smtpUsername, smtpPassword);
                    smtpClient.EnableSsl = enableSsl != null && enableSsl.Equals("true", StringComparison.OrdinalIgnoreCase);
                    smtpClient.Timeout = 10000; // 10 second timeout

                    // Create email message
                    using (var mailMessage = new MailMessage())
                    {
                        mailMessage.From = new MailAddress(fromEmail, fromName ?? "Bookworms Online");
                        mailMessage.To.Add(new MailAddress(to));
                        mailMessage.Subject = subject;
                        mailMessage.Body = htmlContent;
                        mailMessage.IsBodyHtml = true;

                        // Send email
                        await smtpClient.SendMailAsync(mailMessage);
                    }
                }

                _logger.LogInformation($"Email sent successfully to {to}");
                return true;
            }
            catch (SmtpException ex)
            {
                _logger.LogError($"SMTP error sending email to {to}: {ex.Message}");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error sending email to {to}: {ex.Message}");
                return false;
            }
        }
    }
}
