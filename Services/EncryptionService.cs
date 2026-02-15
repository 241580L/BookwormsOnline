using Microsoft.AspNetCore.DataProtection;

namespace BookwormsOnline.Services
{
    /// <summary>
    /// Service for encrypting and decrypting sensitive personal information.
    /// Uses ASP.NET Core Data Protection API for secure encryption.
    /// </summary>
    public interface IEncryptionService
    {
        string Encrypt(string plainText);
        string Decrypt(string encryptedText);
        bool IsEncrypted(string text);
    }

    public class EncryptionService : IEncryptionService
    {
        private readonly IDataProtector _protector;
        private readonly string _encryptionPrefix = "ENCRYPTED:";

        public EncryptionService(IDataProtectionProvider dataProtectionProvider)
        {
            _protector = dataProtectionProvider.CreateProtector("BookwormsOnline.PersonalData.v1");
        }

        /// <summary>
        /// Encrypts sensitive personal data.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt</param>
        /// <returns>Encrypted text with encryption prefix</returns>
        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            // Check if already encrypted to prevent double encryption
            if (IsEncrypted(plainText))
                return plainText;

            try
            {
                var encrypted = _protector.Protect(plainText);
                return _encryptionPrefix + encrypted;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to encrypt data. " + ex.Message, ex);
            }
        }

        /// <summary>
        /// Decrypts sensitive personal data.
        /// </summary>
        /// <param name="encryptedText">The encrypted text to decrypt</param>
        /// <returns>Decrypted plain text</returns>
        public string Decrypt(string encryptedText)
        {
            if (string.IsNullOrEmpty(encryptedText))
                return encryptedText;

            if (!IsEncrypted(encryptedText))
                return encryptedText; // Not encrypted, return as-is

            try
            {
                var protectedPayload = encryptedText.Substring(_encryptionPrefix.Length);
                var decrypted = _protector.Unprotect(protectedPayload);
                return decrypted;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to decrypt data. The data may be corrupted or encrypted with different keys. " + ex.Message, ex);
            }
        }

        /// <summary>
        /// Checks if text is encrypted by looking for the encryption prefix.
        /// </summary>
        /// <param name="text">Text to check</param>
        /// <returns>True if encrypted, false otherwise</returns>
        public bool IsEncrypted(string text)
        {
            return !string.IsNullOrEmpty(text) && text.StartsWith(_encryptionPrefix);
        }
    }
}
